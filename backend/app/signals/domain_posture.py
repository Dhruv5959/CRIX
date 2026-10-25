"""Company domain / email-security posture checks (§7.D) — REAL external source.

Checks, and only where explicitly supported:

* SPF          — TXT on the apex domain starting ``v=spf1`` (RFC 7208).
* DMARC        — TXT on ``_dmarc.<domain>`` starting ``v=DMARC1``.
* DKIM         — TXT on ``<selector>._domainkey.<domain>``, **only when the
                 admin supplies a selector** (CRIX never invents one). Without
                 a selector the check is ``NOT_CHECKED`` — never a failure.
* HTTPS + TLS  — certificate validity/expiry and HSTS headers, obtained by a
                 strict probe (see below).
* Ownership    — a DNS TXT challenge before any checks are allowed, so the
                 backend never scans a host just because anyone typed it.

Why DoH (DNS-over-HTTPS): the backend MUST validate every IP it could touch
before touching it (SSRF rules §7). Reading DNS through the documented JSON
endpoints (``https://dns.google/resolve``, no key) gives CRIX the resolved
addresses as *data* instead of results of an internal resolver, so the
allow/block decision is explicit, deterministic and testable.

The HTTPS/TLS probe never connects to a name — it connects to an **already
validated IP** and presents the domain via TLS SNI. That closes the
DNS-rebinding window (TOCTOU between resolve and connect): the connection
cannot end up anywhere the validation did not see. Redirects are NEVER
followed (a 3xx is reported as an observation).

Honesty contract: a timeout, DoH failure or DNS miss is *not* SAFE:
per-check status stays ``UNAVAILABLE`` and defects are only claimed when
observed. No numeric score is invented here — findings are SecurityEventSchema
outputs and the deterministic engine stays the only scorer (§7/§10).
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
import socket
import ssl
import datetime as dt
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from app import events
from app.config import Settings
from app.schemas import EventStatus, SecurityEventSchema, SourceMode

PROVIDER_LABEL = "Domain posture (DoH + live TLS probe)"
SOURCE_LABEL = "domain_posture"
USER_AGENT = "CRIX-Capstone/0.1 (security-signal-correlator)"

_OWNERSHIP_PREFIX = "crix-verify="
_OWNERSHIP_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.IGNORECASE)

FINDING = "FINDING"
CHECKED_SAFE = "CHECKED_SAFE"
UNAVAILABLE = "UNAVAILABLE"
NOT_CHECKED = "NOT_CHECKED"


# --------------------------------------------------------------------------- #
# Domain validation and ownership challenges
# --------------------------------------------------------------------------- #

def is_well_formed_domain(domain: str) -> bool:
    candidate = (domain or "").strip().lower().rstrip(".")
    if not 4 <= len(candidate) <= 253:
        return False
    return bool(_OWNERSHIP_RE.match(candidate))


def new_ownership_token() -> str:
    """Fresh single-purpose TXT value. The RAW value leaves the API exactly
    once; the database keeps only its SHA-256 hash (same pattern as the
    invitation/reset tokens)."""
    return _OWNERSHIP_PREFIX + secrets.token_hex(24)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# DoH resolution with IP allow-listing (SSRF defenses)
# --------------------------------------------------------------------------- #

@dataclass
class ResolvedIPs:
    answers: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    error: str = ""


def ip_verdict(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """None when the address may be contacted; a reason string when blocked.

    Blocks loopback, RFC1918/private, link-local (incl. cloud metadata
    endpoints like 169.254.169.254), multicast, reserved, unspecified, shared
    address space (100.64/10), and IPv4-mapped IPv6 (re-checked as v4).
    """
    if ip.version == 6:
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            return ip_verdict(mapped)
    blocked_reason = (
        ip.is_loopback or ip.is_private or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )
    if blocked_reason:
        return "address is loopback/private/link-local/multicast/reserved (SSRF denied)"
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return "address is shared address space (SSRF denied)"
    if ip.version == 6 and ip in ipaddress.ip_network("64:ff9b::/96"):
        return "address is NAT64 range (SSRF denied)"
    return None


def resolve_domain(domain: str, settings: Settings) -> ResolvedIPs:
    """DoH A + AAAA lookups; every returned address is verdict-checked."""
    result = ResolvedIPs()
    for rrtype in ("A", "AAAA"):
        entries, err = doh_query(domain, rrtype, settings)
        if err:
            result.error = err
            return result
        for raw in entries:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                continue
            reason = ip_verdict(address)
            if reason:
                result.blocked.append(f"{raw}: {reason}")
            else:
                result.answers.append(address)
    return result


def doh_query(domain: str, rrtype: str, settings: Settings) -> tuple[list[str], str | None]:
    """One DoH JSON query. Returns ``(data fields, error)`` — never raises."""
    if not settings.domain_checks_enabled:
        return [], "Domain checks are disabled (CRIX_DOMAIN_CHECKS_ENABLED)."
    try:
        response = httpx.get(
            settings.domain_doh_url,
            params={"name": domain, "type": rrtype},
            headers={"accept": "application/dns-json", "user-agent": USER_AGENT},
            timeout=float(settings.domain_doh_timeout_seconds),
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        return [], f"DNS-over-HTTPS request failed ({type(exc).__name__})."
    if response.status_code != 200:
        return [], f"DNS-over-HTTPS returned HTTP {response.status_code}."
    try:
        body = response.json()
    except ValueError:
        return [], "DNS-over-HTTPS returned a non-JSON body."
    if not isinstance(body, dict) or "Status" not in body:
        return [], "DNS-over-HTTPS returned an unrecognised response."
    if body.get("Status") != 0:
        # NXDOMAIN/SERVFAIL: the name is not (currently) resolvable — an
        # observation with no answers; NOT a clean bill of health.
        status_code = body.get("Status")
        if status_code in (2, 3):  # SERVFAIL / NXDOMAIN
            return [], f"DNS status {status_code} (record could not be resolved)."
        return [], f"DNS-over-HTTPS status {status_code}."
    answers: list[str] = []
    for answer in body.get("Answer") or []:
        if isinstance(answer, dict) and isinstance(answer.get("data"), str):
            answers.append(answer["data"])
    return answers, None


def txt_values(domain: str, settings: Settings) -> tuple[list[str], str | None]:
    values, err = doh_query(domain, "TXT", settings)
    cleaned: list[str] = []
    for value in values:
        text = str(value)
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        text = text.replace('" "', "")  # DoH splits multi-string TXT with '" "'
        if text:
            cleaned.append(text)
    return cleaned, err


# --------------------------------------------------------------------------- #
# Email-authentication checks
# --------------------------------------------------------------------------- #

def _records_starting_with(values: list[str], prefix: str) -> list[str]:
    return [v for v in values if v.strip().lower().startswith(prefix)]


def check_spf(domain: str, settings: Settings) -> dict[str, Any]:
    values, err = txt_values(domain, settings)
    if err:
        return {"check": "spf", "status": UNAVAILABLE, "reason": err}
    matches = _records_starting_with(values, "v=spf1")
    if not matches:
        return {
            "check": "spf",
            "status": FINDING,
            "observed": "no SPF record published",
            "remediation": "Publish v=spf1 with your sending systems' includes.",
        }
    if len(matches) > 1:
        return {
            "check": "spf",
            "status": FINDING,
            "observed": f"{len(matches)} SPF records published (RFC 7208: undefined)",
            "remediation": "Merge into one SPF TXT record.",
        }
    record = matches[0]
    qualifier = re.search(r"(?:[\s^])([+\-~?])all(?:\s|\.|$)", record + " ")
    if qualifier and qualifier.group(1) == "+":
        return {
            "check": "spf",
            "status": FINDING,
            "observed": "weak policy: +all",
            "remediation": "Use a strict all (fail/softfail), never +all.",
        }
    return {
        "check": "spf",
        "status": CHECKED_SAFE,
        "observed": f"SPF published ({'strict -all' if qualifier and qualifier.group(1) == '-' else 'non-failing all qualifier present'})",
    }


def check_dmarc(domain: str, settings: Settings) -> dict[str, Any]:
    values, err = txt_values(f"_dmarc.{domain}", settings)
    if err:
        return {"check": "dmarc", "status": UNAVAILABLE, "reason": err}
    matches = _records_starting_with(values, "v=dmarc1")
    if not matches:
        return {
            "check": "dmarc",
            "status": FINDING,
            "observed": "no DMARC record published",
            "remediation": "Publish v=DMARC1 with a reporting address (rua=…).",
        }
    tag_p = re.search(r"[;\s]p=([a-z]+)", matches[0].lower() + ";")
    policy = (tag_p.group(1) if tag_p else "none")
    if policy not in ("reject", "quarantine"):
        return {
            "check": "dmarc",
            "status": FINDING,
            "observed": f"DMARC present but policy p={policy} (monitoring only)",
            "remediation": "Once reports confirm legitimate sources, move to p=quarantine/reject.",
        }
    return {"check": "dmarc", "status": CHECKED_SAFE, "observed": f"DMARC published with p={policy}."}


def check_dkim(domain: str, selector: str | None, settings: Settings) -> dict[str, Any]:
    """DKIM is checked ONLY for an admin-supplied selector (never invented)."""
    if not selector:
        return {
            "check": "dkim",
            "status": NOT_CHECKED,
            "observed": "no selector supplied — DKIM was NOT checked (CRIX does not guess selectors)",
        }
    selector = selector.strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{1,63}", selector):
        return {"check": "dkim", "status": UNAVAILABLE, "reason": "Invalid DKIM selector (must be label-like)."}
    values, err = txt_values(f"{selector}._domainkey.{domain}", settings)
    if err:
        return {"check": "dkim", "status": UNAVAILABLE, "reason": err, "selector": selector}
    if not values:
        return {
            "check": "dkim",
            "status": FINDING,
            "observed": f"no DKIM record published for selector '{selector}'",
            "selector": selector,
            "remediation": "Publish the DKIM TXT for this selector or re-check the right one.",
        }
    return {
        "check": "dkim",
        "status": CHECKED_SAFE,
        "observed": f"DKIM record found for selector '{selector}'.",
        "selector": selector,
    }


# --------------------------------------------------------------------------- #
# HTTPS / TLS / HSTS probe (connect to VALIDATED IP, SNI = domain)
# --------------------------------------------------------------------------- #

def _probe_https(
    domain: str,
    settings: Settings,
    *,
    connect: Any = None,
    ctx_factory: Any = None,
) -> dict[str, Any]:
    """Validate-resolve, connect to the IP, TLS-verify the name, HEAD /.

    Kept dependency-free (stdlib socket/ssl). Redirects are never followed; a
    3xx is reported with its Location host as an observation. Response body is
    never read (HEAD only) and header bytes are capped.
    """
    resolved = resolve_domain(domain, settings)
    if resolved.error and not resolved.answers:
        return {"check": "https", "status": UNAVAILABLE, "reason": resolved.error}
    if resolved.blocked and not resolved.answers:
        return {
            "check": "https",
            "status": UNAVAILABLE,
            "reason": "every resolved address was in a blocked (SSRF) range",
            "blocked_count": len(resolved.blocked),
        }
    if not resolved.answers:
        return {"check": "https", "status": UNAVAILABLE, "reason": "no A/AAAA answers"}

    target_ip = str(sorted(resolved.answers, key=str)[0])
    connect = connect or socket.create_connection
    ctx_factory = ctx_factory or ssl.create_default_context
    timeout = float(settings.domain_doh_timeout_seconds)
    try:
        raw_sock = connect((target_ip, 443), timeout=timeout)
        context = ctx_factory()
        try:
            tls_sock = context.wrap_socket(raw_sock, server_hostname=domain)
        except ssl.SSLCertVerificationError as exc:
            return {
                "check": "tls",
                "status": FINDING,
                "observed": "certificate failed browser-grade verification",
                "detail": type(exc).__name__,
                "remediation": "Fix the certificate chain/host match and re-check.",
            }
        except ssl.SSLError as exc:
            return {"check": "https", "status": UNAVAILABLE, "reason": f"TLS handshake failed ({type(exc).__name__})."}
        with tls_sock:
            cert = tls_sock.getpeercert(silent=True) or {}
            not_after = str(cert.get("notAfter", ""))
            expiry = _parse_cert_time(not_after)
            days_left = int((expiry.date() - _utcnow().date()).days) if expiry else None
            tls_result = {
                "check": "tls",
                "status": CHECKED_SAFE,
                "host_verified_with_sni": domain,
                "cert_expires_at": not_after or None,
                "cert_days_left": days_left,
                "address_contacted": target_ip,
                "issuer_org": str(cert.get("issuer", ""))[:200],
            }
            if days_left is not None and days_left < 0:
                tls_result["status"] = FINDING
                tls_result["observed"] = "certificate expired"
                tls_result["remediation"] = "Renew the certificate now."
            elif days_left is not None and days_left <= 15:
                tls_result["status"] = FINDING
                tls_result["observed"] = f"certificate expires in {days_left} days"
                tls_result["remediation"] = "Renew the certificate."
            # Cap: at most 8 KiB of HEAD response (headers only).
            tls_sock.sendall(
                b"HEAD / HTTP/1.1\r\n" + f"Host: {domain}\r\n".encode("ascii")
                + b"Connection: close\r\nUser-Agent: " + USER_AGENT.encode("ascii") + b"\r\n\r\n"
            )
            reader = _line_reader(tls_sock)
            status_line = reader.readline().decode("iso-8859-1", "replace").strip()
            headers: dict[str, str] = {}
            read = 0
            while True:
                line = reader.readline().decode("iso-8859-1", "replace").strip()
                read += len(line) + 2
                if not line or read > 8192:
                    break
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()
            if not status_line.startswith("HTTP/"):
                return {
                    "check": "https",
                    "status": UNAVAILABLE,
                    "reason": "no valid HTTP response (service may not speak HTTP on 443)",
                    "tls": tls_result,
                    "hsts": None,
                }
            http_code = int(status_line.split()[1]) if status_line.split()[1:2] else 0
            hsts = {
                "check": "hsts",
                "status": CHECKED_SAFE if headers.get("strict-transport-security") else FINDING,
                "observed": "HSTS header present" if headers.get("strict-transport-security") else "no Strict-Transport-Security header",
                "value": headers.get("strict-transport-security", "")[:200],
                "remediation": None if headers.get("strict-transport-security") else "Add Strict-Transport-Security with max-age ≥ 15552000.",
            }
            result: dict[str, Any] = {
                "check": "https",
                "status": CHECKED_SAFE,
                "http_status": http_code,
                "address_contacted": target_ip,
                "redirect": None,
            }
            if http_code in (301, 302, 303, 307, 308):
                location = headers.get("location", "")
                loc_host = urlsplit(location if "//" in location else f"https://{domain}{location}").hostname or ""
                result["redirect"] = location[:200]
                result["status"] = CHECKED_SAFE  # 3xx IS the service being reachable
                result["redirect_host"] = loc_host[:100]
            return result | tls_result | ({"hsts": hsts})
    except (socket.timeout, TimeoutError):
        return {"check": "https", "status": UNAVAILABLE, "reason": "connection/timings timed out (never treated as safe)"}
    except (ConnectionError, ssl.SSLError, OSError) as exc:
        return {"check": "https", "status": UNAVAILABLE, "reason": f"connection failed ({type(exc).__name__})."}


def _line_reader(sock) -> Any:
    return sock.makefile("rb")


def _parse_cert_time(value: str) -> dt.datetime | None:
    try:
        return dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except (ValueError, TypeError):
        return None


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------- #
# Ownership challenge: generation, expiry, TXT verification
# --------------------------------------------------------------------------- #

def verify_ownership_txt(domain: str, expect_hash: str, settings: Settings) -> tuple[bool | None, str]:
    """One crix-verify TXT value must hash to ``expect_hash``.

    The comparison is between SHA-256 digests; the issued token value is never
    stored. Returns ``(True | False | None, reason)`` — None = check
    impossible (lookup failed), which is never a pass.
    """
    values, err = txt_values(domain, settings)
    if err:
        return None, f"TXT lookup failed: {err}"
    for value in values:
        if value.strip().lower().startswith(_OWNERSHIP_PREFIX):
            candidate = value.strip()
            if token_hash(candidate) == expect_hash:
                return True, "TXT ownership challenge matched."
            return False, "TXT record present but challenge value did not match."
    return False, "No crix-verify TXT record found for this domain."


# --------------------------------------------------------------------------- #
# Event building: findings only; the response table carries pass/pending rows
# --------------------------------------------------------------------------- #

_SEVERITY_BY_CHECK = {
    "spf": {"no record published": 0.8, "records published (rfc": 0.6, "weak policy: +all": 0.7},
    "dmarc": {"no dmarc record published": 0.7, "policy p=none": 0.5},
    "dkim": {"no dkim record published": 0.35},
    "tls": {"certificate expired": 0.9, "certificate expires in": 0.65, "certificate failed": 0.8},
    "hsts": {"no strict-transport-security header": 0.45},
    "https": {},
}


def build_domain_events(
    *,
    user_id: str,
    asset_id: str,
    results: list[dict[str, Any]],
) -> list[SecurityEventSchema]:
    """Findings → SecurityEventSchema. Unavailable/not-checked checks are
    included in evidence but never become DEFECT findings (§7 results rules).

    Email-auth defects aggregate into ONE EMAIL_AUTH_WEAKNESS finding with a
    per-check breakdown; TLS/HSTS/HTTPS defects aggregate into ONE
    TLS_POSTURE_WEAK finding. account_id = the domain asset id, so the
    normalizer binds both to the registered DOMAIN asset exactly (same-org).
    """
    email_checks = {"spf", "dmarc", "dkim"}
    email_defects = [r for r in results if r["check"] in email_checks and r["status"] == FINDING]
    tls_defects = [r for r in results if r["check"] in {"tls", "hsts"} and r["status"] == FINDING]
    out: list[SecurityEventSchema] = []
    if email_defects:
        severity = max(_severity_for(r) for r in email_defects)
        out.append(SecurityEventSchema(
            event_id=events.new_event_id(),
            user_id=user_id,
            account_id=asset_id,
            event_type=events.EMAIL_AUTH_WEAKNESS,
            exposure_type=None,
            severity=round(severity, 4),
            confidence=0.8,
            source=SOURCE_LABEL,
            source_mode=SourceMode.REAL,
            status=EventStatus.FINDING,
            evidence={
                "target_asset_id": asset_id,
                "defects": [_redact_check_result(r) for r in email_defects],
                "checks_observed": [r["check"] for r in results if r["check"] in email_checks],
            },
            metadata={"target_asset_id": asset_id, "checks": [r["check"] for r in email_defects]},
            provenance=(
                "Observations are live DNS records read over DoH. A DNS failure "
                "means the check could not complete — it is UNAVAILABLE, not a defect."
            ),
        ))
    if tls_defects:
        severity = max(_severity_for(r) for r in tls_defects)
        out.append(SecurityEventSchema(
            event_id=events.new_event_id(),
            user_id=user_id,
            account_id=asset_id,
            event_type=events.TLS_POSTURE_WEAK,
            exposure_type=None,
            severity=round(severity, 4),
            confidence=0.8,
            source=SOURCE_LABEL,
            source_mode=SourceMode.REAL,
            status=EventStatus.FINDING,
            evidence={
                "target_asset_id": asset_id,
                "defects": [_redact_check_result(r) for r in tls_defects],
            },
            metadata={"target_asset_id": asset_id, "checks": [r["check"] for r in tls_defects]},
            provenance=(
                "Live TLS/header probe to a validated IP with the domain as SNI; "
                "redirects are never followed. These checks are not a penetration test."
            ),
        ))
    return out


def _severity_for(result: dict[str, Any]) -> float:
    observed = str(result.get("observed", "")).lower()
    table = _SEVERITY_BY_CHECK.get(result["check"], {})
    for needle, severity in table.items():
        if needle in observed:
            return severity
    return 0.5


def _redact_check_result(result: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in result.items():
        if isinstance(value, str):
            safe[key] = value[:300]
        elif isinstance(value, dict):
            safe[key] = {
                k: (v[:300] if isinstance(v, str) else v) for k, v in value.items()
            }
        else:
            safe[key] = value
    return safe
