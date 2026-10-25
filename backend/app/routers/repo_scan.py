"""Repository secret-scan endpoints (§8.E).

Authorization: ORG_ADMIN only. The archive is uploaded in-memory, scanned
against the documented pattern list, and findings are stored as ONE aggregated
``SECRET_PATTERN_MATCHED`` event bound to the exact CODE_REPOSITORY asset of
the admin's organization (repeat scans replace the module's events — §10.6).

Nothing touches the network; nothing is extracted to the filesystem; matched
VALUES are never stored, logged or echoed (fingerprints only). The audit log
records counts, never contents.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import require_role
from app.engine import normalizer
from app.engine.entities import assert_asset_in_org
from app.models import Membership, OrgAsset
from app.rate_limit import enforce_key, repo_scan_limiter
from app.schemas import OrgRole
from app.signals.secret_scan import SOURCE_LABEL, build_scan_events, scan_archive

router = APIRouter(prefix="/api/repo-scan", tags=["repo-scan"])

ADMIN_ROLES = (OrgRole.ORG_ADMIN.value,)
_REPO_EVENT_TYPES = ["SECRET_PATTERN_MATCHED"]
_CHUNK = 256 * 1024


def _read_bounded(upload: UploadFile, cap: int) -> bytes:
    """Read the upload into memory strictly under ``cap`` bytes."""
    if cap <= 0:
        raise HTTPException(status_code=503, detail="Repository scanning is disabled")
    buffer: list[bytes] = []
    received = 0
    while True:
        chunk = upload.read(_CHUNK)
        if not chunk:
            break
        received += len(chunk)
        if received > cap:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=(
                    f"Archive exceeds the {cap // (1024 * 1024)} MB upload cap; "
                    "nothing was scanned."
                ),
            )
        buffer.append(chunk)
    return b"".join(buffer)


@router.post("")
async def scan_repository(
    request: Request,
    asset_id: Annotated[str, Form()],
    file: UploadFile,
    membership: Annotated[Membership, Depends(require_role(*ADMIN_ROLES))],
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    if not settings.repo_scan_enabled:
        raise HTTPException(status_code=503, detail="Repository scanning is disabled (CRIX_REPO_SCAN_ENABLED)")
    asset = assert_asset_in_org(db, membership.org_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Repository asset not found.")
    if (asset.asset_type or "").upper() != "CODE_REPOSITORY":
        raise HTTPException(
            status_code=404,
            detail="Secret scanning applies to CODE_REPOSITORY assets; this asset is not one.",
        )
    enforce_key(
        repo_scan_limiter,
        f"org:{membership.org_id}",
        limit=settings.repo_scan_rate_limit_per_minute,
    )
    data = _read_bounded(file.file, settings.repo_scan_max_archive_bytes)
    # Close the spooled temp file promptly (our tempfile hygiene: the only
    # place bytes rest is memory under the cap).
    try:
        file.file.close()
    except OSError:
        pass

    scan = scan_archive(data, settings)
    del data  # bytes do not outlive the request
    if scan.error:
        # Fail loud and honest: no scan ran, so nothing was checked.
        raise HTTPException(status_code=422, detail=scan.error)

    events = build_scan_events(user_id=membership.user_id, asset_id=asset.asset_id, scan=scan)
    rows = normalizer.replace_module_events(
        db, membership.user_id, asset.asset_id, _REPO_EVENT_TYPES, events
    )
    audit.record(
        db, action="repo_scan.run", user_id=membership.user_id,
        ip_address=None,  # uploader identity is the admin, not the repo
        detail={
            "org_id": membership.org_id,
            "asset_id": asset.asset_id,
            "source": SOURCE_LABEL,
            "files_scanned": scan.files_scanned,
            "findings": len(scan.findings),
            "skipped_entries": len(scan.skipped_entries),
            "event_rows": len(rows),
        },
    )
    return {
        "asset_id": asset.asset_id,
        "files_scanned": scan.files_scanned,
        "bytes_scanned": scan.bytes_scanned,
        "skipped_entries": scan.skipped_entries,
        "truncated_scan": scan.truncated,
        "findings": scan.findings,
        "events": [normalizer.schema_to_response(normalizer.to_schema(row)) for row in rows],
        "note": (
            "Scan scope: the uploaded working-tree snapshot ONLY — git history was "
            "not scanned. 'No findings' means no match in the documented pattern "
            "list for this snapshot; it is not a statement about the repository's "
            "history or any file that was skipped."
        ),
    }
