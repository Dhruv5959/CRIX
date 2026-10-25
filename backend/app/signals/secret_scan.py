"""Repository-archive secret scanner (§8.E) — deterministic, offline, bounded.

Input contract: ONE ``.zip`` archive of a repository working snapshot. Claims
are exactly what was scanned:

* the archive's files (a working-tree snapshot);
* NOT git history — commits/removals are invisible here, and the response says
  so instead of implying "this repo is clean".

Ingestion safety (all enforced BEFORE any bytes are read):

* zip-only: anything that is not a valid ZipFile is rejected (no tar/7z):
  CRIX explicitly does not pretending other formats were checked;
* entries are validated WITHOUT extraction to disk: names are checked for
  path traversal (``..``, absolute/drive/UNC/backslash forms), filesystem
  linkage entries (symlinks, marked in the POSIX mode bits) are refused, and
  a per-entry read is hard-capped — nothing is ever written to the filesystem;
* decompression-bomb guard: per-entry uncompressed size from the (federated)
  header is capped, plus a header/body cross-check with a compressed-ratio
  ceiling, plus a global uncompressed-bytes ceiling and an entry-count ceiling;
* over-cap entries are skipped — but every skip is RECORDED in the response
  ("skipped_entries"), never silently dropped.

Detection: a small, documented pattern list (private keys, cloud/web service
key formats, generic credential-style assignments, secret-bearing URLs). No
ML, no unpacking, no execution. Each finding stores:

* the file path and line number,
* a category label,
* a stable ``sha256:6`` fingerprint over (path, line, matched value),
* a REDACTED preview where only non-secret structure survives (the LHS key
  name of an assignment; the scheme+host of a URL). The matched VALUE never
  enters evidence, the API response, or any log — not even truncated.

No numeric score is invented here: findings are SecurityEventSchema outputs
and the deterministic engine stays the only scorer (§8).
"""
from __future__ import annotations

import hashlib
import io
import posixpath
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

from app import events
from app.config import Settings
from app.schemas import EventStatus, SecurityEventSchema, SourceMode

SOURCE_LABEL = "repo_secret_scan"

# Zip members with this POSIX file-type are links; CRIX never extracts them.
_S_IFLNK = 0o120000
# Ceiling on the uncompressed/compressed ratio per entry: far above any real
# source file, low enough that a classic "42 MB of zeros from 4 KB" bomb dies.
_MAX_RATIO = 200

FINDING = "FINDING"
CHECKED_SAFE = "CHECKED_SAFE"

# --------------------------------------------------------------------------- #
# Detection patterns (documented §8 categories)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Pattern:
    category: str
    severity: float
    regex: re.Pattern[str]
    # For assignment-style findings: evidence shows the LHS key name
    # (``name_group``), the fingerprint covers the matched VALUE
    # (``value_group``) — never the reverse.
    name_group: int = 0
    value_group: int = 0


_PATTERNS: tuple[Pattern, ...] = (
    # Only the BEGIN marker is pattern-matched (line-scoped): the classic
    # committed-private-key signature, without needing a multi-line match.
    Pattern(
        "private_key_block", 0.9,
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----"),
    ),
    Pattern("aws_access_key_id", 0.85, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Pattern("google_api_key", 0.85, re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Pattern("slack_token", 0.75, re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    Pattern("github_token", 0.75, re.compile(r"\b(?:gh[pousr]_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,})\b")),
    Pattern("gitlab_token", 0.75, re.compile(r"\bglpat-?[0-9A-Za-z_\-]{18,}\b")),
    Pattern("generic_secret_token", 0.6, re.compile(
        r"\bsk-(?:proj-)?[0-9A-Za-z_\-]{16,}\b|\bmongodb(?:\+srv)?://[^/\s:]+:[^/\s@]{4,}@"
    )),
    Pattern("jwt", 0.5, re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
    )),
    Pattern(
        # Quoted literal assigned to a secret-ish LHS (code OR config files).
        "credential_assignment", 0.6,
        re.compile(
            r"(?i)\b([a-z0-9_.\-]*(?:password|passwd|pwd|secret|api_?key|auth_?token|access_?token|"
            r"client_?secret|private_?key)[a-z0-9_.\-]*)\s*[:=]\s*[\"']([^\"'\s]{6,200})[\"']",
        ),
        name_group=1,
        value_group=2,
    ),
    Pattern(
        # user:pass@ in a connection URL (the password is the embedded secret).
        "secret_in_url", 0.7,
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@<>\"]{1,64}:([^/\s:@<>\"]{4,})@"),
        value_group=1,
    ),
)

# Values that appear in template files / examples are not live secrets.
_PLACEHOLDER_RE = re.compile(
    r"^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<[^\n>]+>|%[A-Z_]+%"
    r"|changeme|CHANGEME|ChangeME|x{6,}|X{6,}|0{6,}|z{6,}|Z{6,}"
    r"|your[-_][^\s]*|example[-_.][^\s]*|dummy|placeholder|sample[^\s]*|"
    r"insert[-_][^\s]*)$",
    re.IGNORECASE,
)

_TEXT_SUFFIXES = frozenset((
    ".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".go", ".rs", ".php", ".java",
    ".kt", ".swift", ".c", ".h", ".cpp", ".cs", ".sh", ".bash", ".zsh", ".ps1",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".properties", ".txt", ".md", ".rst", ".sql", ".html", ".css", ".scss",
    ".dockerfile", ".npmrc", ".netrc", ".tf", ".envrc", ".git-credentials",
))


def _is_scannable(name: str) -> bool:
    lowered = name.lower()
    base = posixpath.basename(lowered)
    if any(lowered.endswith(suf) for suf in _TEXT_SUFFIXES) or base in (
        "dockerfile", "makefile", ".gitconfig", ".npmrc", ".netrc", ".env",
    ):
        return True
    # Files without an extension are treated as candidate sources (Makefile,
    # Jenkinsfile, scripts committed without a suffix) — still text-checked.
    return "." not in base or lowered.endswith(".env")


def _entry_name_error(name: str) -> str | None:
    """Refuse entries that do not name a plain relative file path."""
    if not name:
        return "empty entry name"
    if "\\" in name or "\x00" in name:
        return "entry name contains backslash/NUL separators"
    if name.startswith("/") or name.startswith("~"):
        return "entry name is absolute"
    if re.match(r"^[A-Za-z]:", name):
        return "entry name carries a drive letter"
    parts = posixpath.normpath(name).split("/")
    if ".." in parts:
        return "entry name contains path traversal ('..')"
    return None


@dataclass
class ScanResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    skipped_entries: list[dict[str, Any]] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    truncated: bool = False  # scanner stopped early (finding cap / byte cap)
    error: str = ""


def _record_skip(result: ScanResult, name: str, reason: str) -> None:
    result.skipped_entries.append({"path": name[:200], "reason": reason[:160]})


def scan_archive(data: bytes, settings: Settings) -> ScanResult:
    """Scan ONE zip archive. Never extracts to disk; never contacts anything."""
    result = ScanResult()
    if not data:
        result.error = "The uploaded archive is empty."
        return result
    if len(data) > settings.repo_scan_max_archive_bytes:
        result.error = (
            f"Archive exceeds the {settings.repo_scan_max_archive_bytes // (1024 * 1024)} MB upload cap."
        )
        return result
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        result.error = (
            "Not a readable ZIP archive. CRIX scans .zip working snapshots; "
            "it did not check any other format, so no clean result is claimed."
        )
        return result

    infos = [info for info in archive.infolist() if not info.is_dir()]
    if len(infos) > settings.repo_scan_max_file_count:
        result.error = (
            f"Archive contains more than the configured maximum of "
            f"{settings.repo_scan_max_file_count} file entries; no scan was run."
        )
        return result

    max_file = settings.repo_scan_max_file_bytes
    total_cap = settings.repo_scan_max_total_bytes
    findings_cap = settings.repo_scan_max_findings
    time_budget = settings.repo_scan_max_scan_seconds

    import time as _time

    deadline = _time.monotonic() + time_budget
    total_bytes = 0
    for info in infos:
        if result.truncated:
            _record_skip(result, info.filename, "scan cap reached; entry not examined")
            continue
        if _time.monotonic() > deadline:
            result.truncated = True
            _record_skip(result, info.filename, "scan time budget exhausted; entry not examined")
            continue

        name_error = _entry_name_error(info.filename)
        if name_error:
            _record_skip(result, info.filename, name_error)
            continue

        mode = (info.external_attr >> 16) & 0o170000
        if mode == _S_IFLNK:
            _record_skip(result, info.filename, "filesystem link entry — never dereferenced")
            continue

        if info.file_size > max_file:
            _record_skip(result, info.filename, f"entry larger than the {max_file // (1024 * 1024)} MB per-file cap")
            continue
        if total_bytes + info.file_size > total_cap:
            result.truncated = True
            _record_skip(result, info.filename, "aggregate byte cap reached; entry not examined")
            continue
        if info.compress_size and info.file_size / info.compress_size > _MAX_RATIO:
            _record_skip(result, info.filename, "decompressed/compressed ratio exceeds the bomb guard")
            continue

        try:
            with archive.open(info) as member:
                blob = member.read(max_file + 1)
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
            _record_skip(result, info.filename, f"entry not readable ({type(exc).__name__})")
            continue
        if len(blob) > max_file:
            _record_skip(result, info.filename, "entry exceeded the per-file read cap")
            continue
        if b"\x00" in blob:
            _record_skip(result, info.filename, "binary file (patterns apply to text only)")
            continue

        if not _is_scannable(info.filename):
            _record_skip(result, info.filename, "outside the text-pattern scan scope (not a source/config text file)")
            continue

        text = blob.decode("utf-8", errors="replace")
        truncated = _scan_text(info.filename, text, result, findings_cap)
        result.truncated = result.truncated or truncated
        total_bytes += info.file_size
        result.bytes_scanned += info.file_size
        result.files_scanned += 1
    return result


def _scan_text(path: str, text: str, result: ScanResult, findings_cap: int) -> bool:
    """Run every pattern over the text line-wise. Returns True if truncated."""
    for line_no, line in enumerate(text.splitlines(), start=1):
        if len(result.findings) >= findings_cap:
            _record_skip(result, path, "finding cap reached; remaining lines not examined")
            return True
        for pattern in _PATTERNS:
            match = pattern.regex.search(line)
            if match is None:
                continue
            value = match.group(pattern.value_group) if pattern.value_group else match.group(0)
            if pattern.category in ("credential_assignment", "secret_in_url"):
                # These two families only fire for real-looking literals; a
                # template placeholder (e.g. ${VAR}, "your-api-key-here") is
                # not a live secret and must not be reported.
                if _PLACEHOLDER_RE.match(value or ""):
                    continue
            fingerprint = hashlib.sha256(f"{path}:{line_no}:{value}".encode("utf-8")).hexdigest()[:6]
            finding: dict[str, Any] = {
                "path": path[:300],
                "line": line_no,
                "category": pattern.category,
                "severity_hint": pattern.severity,
                "fingerprint": f"sha256:{fingerprint}",
                "value_stored": False,
            }
            if pattern.category == "credential_assignment":
                finding["key_hint"] = (match.group(pattern.name_group) or "")[:80]
            elif pattern.category == "secret_in_url":
                finding["key_hint"] = "embedded userinfo password in a connection URL (value withheld)"
            else:
                finding["key_hint"] = "matched a documented literal token format"
            result.findings.append(finding)
            break  # one finding per line — repeated matches in one line add noise
    return False


# --------------------------------------------------------------------------- #
# Event building (aggregation + honesty)
# --------------------------------------------------------------------------- #

def build_scan_events(
    *,
    user_id: str,
    asset_id: str,
    scan: ScanResult,
) -> list[SecurityEventSchema]:
    """Findings → ONE aggregated SECRET_PATTERN_MATCHED finding for the asset.

    Aggregation (like the domain-posture module) keeps dedupe exact for repeat
    scans of the same repo: the module's events for the asset are replaced, so
    two uploads never double-count the same leak. A scan with no matches
    stores NOTHING — 'nothing found in the default pattern list over the
    uploaded snapshot' is not a 'safe' label (history was not scanned).
    """
    if not scan.findings:
        return []
    severity = max(float(f["severity_hint"]) for f in scan.findings)
    categories = sorted({f["category"] for f in scan.findings})
    by_category: dict[str, int] = {}
    for f in scan.findings:
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
    # The schema caps evidence at EVIDENCE_MAX_CHARS (4096): event evidence
    # carries a bounded SLICE of the findings — the FULL list (still
    # value-redacted) is returned by the scan response, and the slice is
    # labeled so a reader can never mistake it for "all of them".
    evidence_findings = list(scan.findings[:12])
    evidence_skipped = list(scan.skipped_entries[:12])
    return [
        SecurityEventSchema(
            event_id=events.new_event_id(),
            user_id=user_id,
            account_id=asset_id,
            event_type=events.SECRET_PATTERN_MATCHED,
            exposure_type=None,
            severity=round(min(max(severity, 0.0), 1.0), 4),
            confidence=0.8,
            source=SOURCE_LABEL,
            # The archive is admin-provided content; the detections are
            # deterministic CRIX rules over that content. USER_PROVIDED
            # provenance describes the data honestly (not REAL external data).
            source_mode=SourceMode.USER_PROVIDED,
            status=EventStatus.FINDING,
            evidence={
                "target_asset_id": asset_id,
                "finding_count": len(scan.findings),
                "findings_in_evidence_capped": len(evidence_findings) < len(scan.findings),
                "findings": evidence_findings,
                "categories": categories,
                "category_counts": by_category,
                "values_stored": False,
                "value_redaction_note": (
                    "Each finding's fingerprint is a sha256 digest of the matched "
                    "value with its location; the value itself is never stored."
                ),
                "scope_note": (
                    "Findings reflect ONLY the uploaded working-tree snapshot; "
                    "git history was not scanned."
                ),
                "files_scanned": scan.files_scanned,
                "bytes_scanned": scan.bytes_scanned,
                "skipped_count": len(scan.skipped_entries),
                "skipped_in_evidence_capped": len(evidence_skipped) < len(scan.skipped_entries),
                "skipped_entries": evidence_skipped,
                "truncated_scan": scan.truncated,
            },
            metadata={"target_asset_id": asset_id, "categories": categories},
            provenance=(
                "Deterministic pattern scan over an admin-uploaded archive. "
                "Matched values are never stored or logged — only fingerprints."
            ),
        )
    ]
