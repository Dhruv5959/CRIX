"""End-to-end HTTP smoke test against a running backend.

Exercises the real API surface: register → login → add account → record signals
→ run pipeline → graph → planner → explanation → evaluation → logout, checking
status codes and that authoritative values come from the server.

Usage:
    .venv\\Scripts\\python.exe backend\\scripts\\smoke.py
    (requires the backend running on http://127.0.0.1:8000)
"""
from __future__ import annotations

import sys
import time
import uuid

import httpx

BASE = "http://127.0.0.1:8000"
failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def main() -> None:
    email = f"smoke-{uuid.uuid4().hex[:8]}@example.com"
    password = "smoke-test-password-123"
    client = httpx.Client(base_url=BASE, timeout=30.0)

    # Wait for the server.
    for _ in range(30):
        try:
            if client.get("/api/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    else:
        print("Backend not reachable at", BASE)
        sys.exit(1)

    print("Health")
    health = client.get("/api/health").json()
    check("health ok", health["status"] == "ok")
    check("hibp capability reported", "hibp_configured" in health)
    check(
        "email breach provider reported",
        bool(health.get("breach_email_provider"))
        and bool(health.get("breach_email_provider_label")),
        detail=str(health.get("breach_email_provider")),
    )

    print("Auth")
    check("register", client.post("/api/auth/register", json={"email": email, "password": password}).status_code == 201)
    login = client.post("/api/auth/login", json={"email": email, "password": password})
    check("login", login.status_code == 200)
    data = login.json()
    headers = {"Authorization": f"Bearer {data['access_token']}", "X-CSRF-Token": data["csrf_token"]}
    check("me", client.get("/api/auth/me", headers=headers).json()["email"] == email)

    print("Accounts & signals")
    check("create account", client.post("/api/accounts", headers=headers, json={
        "account_id": "g-main", "label": "Gmail", "service_name": "Google", "email": email
    }).status_code == 201)

    breach = client.post("/api/signals/breach", headers=headers, json={
        "account_id": "g-main", "email": email,
        "simulated_exposure_type": "SESSION_ONLY", "simulated_mfa_bypass_capable": True,
    })
    check("breach check", breach.status_code == 200)
    breach_events = breach.json()["events"]
    live = [e for e in breach_events if e["event_type"] == "BREACH_EXPOSURE"]
    check(
        "breach lookup reports its provider + checked_at",
        bool(live)
        and all(e["metadata"].get("provider") and e["metadata"].get("checked_at") for e in live),
    )
    check(
        "breach verdict is an honest value (never a guess)",
        {e["status"] for e in live} <= {"FINDING", "CHECKED_SAFE", "UNAVAILABLE"},
        detail=str([e["status"] for e in live]),
    )

    hygiene = client.post("/api/signals/password-hygiene", headers=headers, json={
        "account_id": "g-main", "provider": "Google", "mfa_enabled": False,
        "passkey_enabled": False, "sms_otp_recovery": True, "push_bombing_reported": True,
        "reused_credentials": [{"label": "x", "reused": True}],
    })
    check("hygiene check", hygiene.status_code == 200)

    perms = client.post("/api/signals/permissions/audit", headers=headers, json={
        "account_id": "g-main",
        "entries": [{"app_name": "Sketchy", "platform": "android", "permissions": ["contacts", "sms"]}],
    })
    check("permission audit", perms.status_code == 200)

    print("Analysis pipeline")
    run = client.post("/api/analysis/run", headers=headers).json()
    check("risk score in range", 0 <= run["risk"]["score"] <= 100)
    check("correlations returned", isinstance(run["correlations"], list))
    eff = run["attribution"]["efficiency_error"]
    check("shapley efficiency holds", eff < 1e-6, f"err={eff}")
    # Exact never worse than greedy in the server's own comparison.
    check("exact <= greedy", run["planner"]["exact"]["risk_after"] <= run["planner"]["greedy"]["risk_after"] + 1e-6)

    print("What-if")
    wi = client.post("/api/analysis/what-if", headers=headers, json={
        "toggles": [{"action_key": "strengthen_mfa", "enabled": True},
                    {"action_key": "revoke_session", "enabled": True}]
    })
    check("what-if runs", wi.status_code == 200)
    wi_data = wi.json()
    check("what-if reduces risk", wi_data["after"]["score"] <= wi_data["before"]["score"] + 1e-6)
    check("what-if has real attribution", "contributions" in wi_data["after"]["attribution"])
    check("what-if rejects bad action", client.post("/api/analysis/what-if", headers=headers, json={
        "toggles": [{"action_key": "made_up", "enabled": True}]
    }).status_code == 422)

    print("Graph / planner / explanation / knowledge")
    check("graph", client.get("/api/graph", headers=headers).status_code == 200)
    check("planner", client.get("/api/planner/plan", headers=headers).status_code == 200)
    expl = client.get("/api/analysis/explanation", headers=headers).json()
    check("explanation grounded", expl["grounded"] is True, str(expl.get("unsupported_claims")))
    check("explanation has citations", len(expl["citations"]) > 0)
    check("knowledge graph", client.get("/api/knowledge-graph", headers=headers).status_code == 200)
    check("correlation rules", client.get("/api/correlation-rules", headers=headers).status_code == 200)
    check("evaluation", client.get("/api/evaluation", headers=headers).status_code == 200)

    print("Live connections & propagation")
    if client.get("/api/oauth/providers").status_code == 404:
        # OAuth is FROZEN (§1.4) — the shipped default. Assert the freeze holds,
        # then run the propagation demo from ordinary accounts (no OAuth).
        check("oauth frozen: providers endpoint absent", True)
        check("oauth frozen: connections endpoint absent",
              client.get("/api/oauth/connections", headers=headers).status_code == 404)
        check("oauth frozen: authorize route absent",
              client.get("/api/oauth/google/authorize", headers=headers).status_code == 404)
        check("create second account", client.post("/api/accounts", headers=headers, json={
            "account_id": "repo-main", "label": "Work GitHub", "service_name": "GitHub"
        }).status_code == 201)
        src, dst = "g-main", "repo-main"
    else:
        provs = client.get("/api/oauth/providers").json()["providers"]
        check("oauth providers listed", set(provs) == {"google", "linkedin"})
        check("instagram removed from providers", "instagram" not in provs)
        check("providers report NOT_CONFIGURED without creds",
              all(p["status"] == "NOT_CONFIGURED" for p in provs.values()))
        check("no client secrets in provider payload",
              all("client_secret" not in str(p) for p in provs.values()))

        caps = client.get("/api/oauth/capabilities").json()["capabilities"]
        check("capability matrix non-empty", len(caps) > 0)
        unavailable = [c for c in caps if not c["available"]]
        check("unavailable caps exist", len(unavailable) > 0)
        check("unavailable never marked SAFE",
              all(c["status"] == "UNAVAILABLE_THROUGH_PROVIDER" for c in unavailable),
              str({c["status"] for c in unavailable}))

        # Unconfigured authorize must fail loudly, not pretend.
        check("unconfigured authorize -> 503",
              client.get("/api/oauth/google/authorize", headers=headers).status_code == 503)

        # FIXTURE connectors (clearly labeled) power the propagation demo offline.
        fx_g = client.post("/api/oauth/fixtures/google", headers=headers)
        check("fixture connect", fx_g.status_code == 200 and fx_g.json()["source_mode"] == "FIXTURE")
        fx_l = client.post("/api/oauth/fixtures/linkedin", headers=headers)
        check("fixture connect 2", fx_l.status_code == 200)
        src, dst = fx_g.json()["account_id"], fx_l.json()["account_id"]

        conns = client.get("/api/oauth/connections", headers=headers).json()["connections"]
        check("connections listed", any(c["account_id"] == src for c in conns))
        check("connections never expose tokens",
              "access_token_enc" not in client.get("/api/oauth/connections", headers=headers).text)

        # Connecting must NOT flip an unavailable capability to available.
        caps_after = client.get("/api/oauth/capabilities").json()["capabilities"]
        still_unavailable = {(c["provider"], c["capability"]) for c in caps_after if not c["available"]}
        check("connection does not imply capability",
              {(c["provider"], c["capability"]) for c in unavailable} == still_unavailable)

    rel = client.post("/api/relationships", headers=headers, json={
        "from_account_id": src, "to_account_id": dst,
        "relationship_type": "recovery_email", "confidence": 1.0,
    })
    check("user-confirmed relationship", rel.status_code == 201)
    check("relationship labeled USER_CONFIRMED",
          rel.json()["source"] == "USER_CONFIRMED" and rel.json()["source_mode"] == "USER_PROVIDED")
    check("unknown relationship type rejected",
          client.post("/api/relationships", headers=headers, json={
              "from_account_id": src, "to_account_id": dst,
              "relationship_type": "made_up"}).status_code == 422)

    accounts = client.get("/api/propagation/accounts", headers=headers).json()["accounts"]
    check("propagation accounts listed", any(a["account_id"] == src for a in accounts))

    sim = client.post("/api/propagation/simulate", headers=headers,
                      json={"upstream_account_id": src})
    check("simulate runs", sim.status_code == 200, sim.text[:200])
    sim_data = sim.json()
    check("scenario marked SIMULATED", sim_data["scenario"]["source_mode"] == "SIMULATED")
    check("scenario says no real account touched",
          "No real account was" in sim_data["scenario"]["notice"])
    check("propagation affected >= 1", sim_data["propagation"]["affected_count"] >= 1)
    check("exposure scores in range",
          all(0 <= d["exposure"] <= 100 for d in sim_data["propagation"]["downstream"]))
    check("disclaimer is not a probability",
          "Not a probability" in sim_data["disclaimer"])
    check("storyline starts upstream", sim_data["storyline"][0]["band"] == "COMPROMISED")
    check("scenario risk recomputed", 0 <= sim_data["scenario_risk"]["score"] <= 100)
    check("scenario attribution exact",
          sim_data["scenario_attribution"]["efficiency_error"] < 1e-6)
    check("scenario remediation recomputed",
          sim_data["scenario_plan"]["comparison"]["exact"]["risk_after"]
          <= sim_data["scenario_plan"]["comparison"]["initial_risk"] + 1e-6)
    check("scenario plan never calls greedy optimal",
          "baseline" in sim_data["scenario_plan"]["note"].lower()
          and "greedy is a baseline" in sim_data["scenario_plan"]["note"].lower())

    print("IDOR")
    other = f"smoke-other-{uuid.uuid4().hex[:8]}@example.com"
    client_b = httpx.Client(base_url=BASE, timeout=30.0)
    client_b.post("/api/auth/register", json={"email": other, "password": password})
    other_login = client_b.post("/api/auth/login", json={"email": other, "password": password}).json()
    other_headers = {"Authorization": f"Bearer {other_login['access_token']}"}
    check("cannot read other's account", client_b.get("/api/accounts/g-main", headers=other_headers).status_code == 404)

    print("Logout")
    check("logout", client.post("/api/auth/logout", headers=headers).status_code == 204)
    check("refresh after logout fails", client.post("/api/auth/refresh", headers={"X-CSRF-Token": data["csrf_token"]}).status_code == 401)

    print()
    if failures:
        print(f"SMOKE FAILED: {len(failures)} check(s): {failures}")
        sys.exit(1)
    print("SMOKE PASSED — all checks green.")


if __name__ == "__main__":
    main()