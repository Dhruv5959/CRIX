# CRIX — Presentation Guide

> A rehearsal script for presenting the capstone. Contains a slide outline, a
> click-by-click live demo, the exact numbers to cite, examiner Q&A with honest
> answers, and a backup plan. Last updated: 2026-10-25.

---

## 0. The one-sentence pitch

> **CRIX doesn't just tell you what security problems you have — it tells you how
> they connect, which one matters most, why, and what to fix first.**

Say that once, slowly, then move on. Everything else is evidence for it.

---

## 1. Before you walk in (pre-flight checklist)

Run these ~5 minutes before presenting:

```powershell
# From C:\sem 7\major project

# 1. Backend up?
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
#   (run from the backend\ folder; or start it in one terminal)

# 2. Frontend up?  (second terminal)
cd frontend
npm run dev

# 3. Verify demo data + metrics exist
cd ..\backend
..\.venv\Scripts\python.exe scripts\seed_demo.py
#   (also seeds the FIXTURE connectors + USER_CONFIRMED relationships the
#    Propagation demo needs — labeled FIXTURE / YOU CONFIRMED, never REAL)
..\.venv\Scripts\python.exe scripts\run_evaluation.py

# 4. Optional but recommended: confirm everything is green
..\.venv\Scripts\python.exe scripts\smoke.py
```

Then open **http://localhost:5173** and log in once to confirm it loads:
- Email: `demo@example.com`
- Password: `demo-password-123`

Quick route check before presenting: **Live Connections** (`/connections`) and
**Propagation** (`/propagation`) both load, and all three providers read
`NOT_CONFIGURED` — that is *expected* and is itself a talking point (live
OAuth is deliberately frozen in this build per the spec's §12 freeze).

**The two breach/password providers are keyless** (XposedOrNot for email
lookups, HIBP Pwned Passwords for the password corpus), so no API keys are
needed — but the *live* Signal lookups need internet. On a dead connection
they show **UNAVAILABLE** honestly instead of a verdict, which is correct
behavior and a talking point, not a failure. A login with the provider down
is never blocked — it just records the honest outcome.

**Fallback if Wi-Fi/laptop fails:** keep the `datasets/` folder and
`docs/` open, plus the README. You can screen-share the Markdown and still tell
the whole story without the running app.

---

## 2. Slide outline (~13–14 slides)

1. **Title** — CRIX: Contextual Risk Intelligence. The one-sentence pitch.
2. **The problem** — dashboards drown you in isolated findings. "You have 47
   alerts" tells you nothing about *what to fix first*.
3. **The idea (thesis)** — connect signals → prioritize → explain → recommend.
   Draw the pipeline as one arrow diagram (see README).
4. **Architecture** — React → FastAPI → Signal Modules → Normalizer →
    Correlation → Risk → Shapley → Graph → Planner → GraphRAG → Dashboard.
5. **Honesty policy** — real vs simulated vs unavailable; no fabricated metrics;
    deterministic engine decides, GraphRAG explains. *(This slide earns marks.)*
6. **SMB features, consent-first** — the registered work email works out of the
    box; automatic breach monitoring only after an affirmative, timestamped
    consent; a >24h cache so the provider is not hammered at every login; the
    login password is checked server-side with k-anonymity (5-char SHA-1 prefix
    only) and the outcome is recorded honestly — never blocking a login. A
    placeholder-style address (never a real mailbox) gets an explicit
    "not evidence" note.
7. **Live connections, honestly scoped** — official OAuth + PKCE + encrypted
    tokens; but a connection proves a *relationship*, not security posture —
    capability matrix marks what the API won't expose as
    `UNAVAILABLE_THROUGH_PROVIDER`, and relationships are user-confirmed.
    (In this build live OAuth is frozen per spec §12 — the code path is real
    and gated off.)
8. **Compromise propagation** — a defensive what-if with a documented exposure
    formula; relative prioritization, explicitly not a probability.
9. **Live demo** — see §3 below.
10. **How the risk engine works** — `risk = asset criticality × (base +
    interaction) − mitigation`; non-additive compounding is the thesis, and the
    company's own asset importance is a documented, bounded input.
11. **Transparent attribution** — exact Shapley; contributions sum to the total.
12. **Prioritization** — greedy **baseline** vs exact branch-and-bound; measured
    gap; a deliberately constructed greedy trap.
13. **Evaluation** — real measured metrics (phishing F1, Shapley efficiency, etc.).
14. **Security of CRIX itself** — its own login/auth hardening + the §14 checklist.
15. **Limitations & future work** — say them before the examiner does.

---

## 3. Live demo script (15–18 minutes)

Do it in this exact order. Each step names the page and the *one thing to say*.

### Step 1 — Login page → Overview
- **Click:** log in as `demo@example.com` / `demo-password-123`.
- **Say:** "This is a real account seeded with a realistic scenario — 23 security
  events across the connected accounts. CRIX collapses that into one contextual
  risk score: **69.5, HIGH**, with a sensitivity range of **63–78**.
  Notice it's a *relative prioritization*, not a probability."
- **Note:** that login also ran a live Pwned-Passwords check of the demo user's
  password (server-side, k-anonymity). It recorded an honest outcome — and it
  did **not** block authentication. You'll show that banner in Step 1b.

### Step 1b — Feature A/B: consent-gated monitoring + honest password outcome
- **Do:** go to **Signals → Breach / Exposure** (the "Your work email" account
  is pre-selected). Show the **Automatic breach monitoring** panel.
- **Say:** "Every user gets their registered work email as a signal account
  automatically — the four signal features work at first login, no setup. This
  switch is *consent*: we never auto-check anyone's address without an
  affirmative opt-in, and we store the consent with a timestamp. When it's on,
  CRIX re-checks at sign-in **only if the last check is older than 24 hours** —
  watch it: the 'Last automatic check' line is the honest cache; a fresh login
  costs the provider zero calls."
- **Do:** toggle it on — the first lookup runs immediately and events appear
  for the registered-email account. If you demo on a placeholder-style address
  (`.invalid`/`example.com`/`test`), the result card carries a written note:
  *this address was never a real monitored mailbox, so the verdict is not
  evidence*. Toggle off to revoke — live.
- **Do:** open the **Password Hygiene** tab and point at the banner at the top.
- **Say:** "Feature B. Every sign-in, CRIX checks the just-verified password
  against the Pwned Passwords corpus — server-side, sending only a 5-character
  SHA-1 prefix (k-anonymity; the hash and the plaintext never leave). The
  outcome is named here with the provider and time: this demo login's password
  is genuinely in the breach corpus — twice — yet login was **not** blocked;
  we warn and store, never fabricate. If a corpus check is unavailable, the
  banner says UNKNOWN — never 'safe'. Try registering with something like
  `sunshine123`: the server refuses it with the real corpus count."

### Step 2 — Connected Signals (`/signals`)
- **Say:** "Every finding carries provenance. **REAL** means a live provider
  answered — for email breaches that's XposedOrNot (and HIBP when its key is
  configured; both free, no credentials stored). **SIMULATED** means the user
  constructed the scenario — for example the session-cookie exposure, which we
  label 'simulated exposure scenario'. And **UNAVAILABLE** means we couldn't
  run the check — which is never shown as 'safe'. That distinction is a core
  rule of this project."

### Step 3 — Live Connections (`/connections`)
- **Do:** show the three provider cards (Google, LinkedIn, Instagram
  Professional), all reading **NOT_CONFIGURED**, then the capability matrix.
- **Say:** "This is where I have to be careful about what a connection *proves*.
  These are official OAuth 2.0 with PKCE — authorization code, single-use state,
  minimum scopes; Google's `gmail.metadata`, not message bodies. CRIX never
  asks for a provider password and never sends a token to the browser — refresh
  tokens are Fernet-encrypted at rest.
  But notice: connecting would **not** tell us the MFA state or breach status,
  because Google doesn't expose those to third parties. So the matrix marks them
  **UNAVAILABLE_THROUGH_PROVIDER** — never 'safe'. And connecting must not flip
  a row to available; there's a test for that."
- **Do (if no credentials):** click *Demo fixture* — it comes back labeled
  **FIXTURE — NOT REAL**, which is the honest way to demo without registering
  three apps.

### Step 4 — Correlations (`/correlations`)
- **Say:** "This is the heart of the thesis. Two correlation rules fired here.
  `mfa_ineffective_session_exposure` — severity 0.85 — because a stolen session
  cookie is MFA-bypass-capable: MFA protects the *login*, not an already-issued
  session. And `sim_swap_recovery_exposure`. These are the *combinations* that
  matter, not the individual alerts."

### Step 5 — Risk & Attribution (`/risk`)
- **Say:** "Here's *why* the score is 69.5. Base risk 48.5, plus **interaction
  risk 13.2** — that's the compounding: breach + reuse is worse than the sum of
  its parts — scaled by **asset criticality ×1.1** because the findings hit a
  level-4 company asset (+6.2), plus **1.6 from the organization's dependency
  graph** — the level-5 repository this account can reach is worth accounting
  for — minus mitigation credit 0. The waterfall shows
  each feature's exact **Shapley** contribution, and they sum exactly to the
  total (efficiency error ~2×10⁻⁹). This explains the *real* deterministic
  function; it is not a model trained on CRIX's own labels."

### Step 6 — Dependency Graph (`/graph`)
- **Say:** "Accounts aren't independent. This is a curated, hand-verified
  dependency graph — recovery and OAuth routes. We rank by NetworkX PageRank:
  compromising a high-centrality account (like a recovery email) cascades to the
  ones that trust it. Every edge is marked curated/static with a source."

### Step 7 — Compromise Propagation (`/propagation`)
- **Do:** pick **Primary Gmail**, click *Simulate Account Compromise*.
- **Say:** "This is a defensive **what-if**. Nothing was accessed, altered, or
  disabled — no account is attacked. CRIX recomputes exposure through the graph
  *you confirmed*, then re-runs the real risk engine, exact Shapley, and the
  planner.
  The score comes from a documented formula — dependency strength × account
  criticality × credential/auth weakness × path exposure, minus mitigation —
  and every component is shown per account, so you can see *why*. It moves when
  the inputs move; there's no hardcoded number.
  Read the wording carefully: 'Instagram has elevated downstream compromise
  exposure **if** Gmail is compromised.' Not 'will be hacked'. It's a relative
  prioritization, and the API ships a disclaimer saying it isn't a probability."
- **Say (relationships):** "And notice CRIX didn't invent the Gmail→Instagram
  edge. OAuth login doesn't prove a recovery path — the Connections page asks
  *'How are these accounts related?'* and stores only what you confirm, labeled
  `USER_CONFIRMED`."

### Step 8 — Remediation & What-If (`/remediation`)
- **Say:** "CRIX compares exactly **two** methods: a greedy baseline and an exact
  branch-and-bound solver — and it never calls greedy optimal. On our scenario
  suite the measured mean optimality gap is **6.9%**, and we include a
  deliberately constructed **greedy trap** where greedy provably does worse."
- **Do:** toggle an action (e.g. *Revoke session* / *Enable passkey*) in What-If.
- **Say:** "Toggling re-runs the **real** pipeline — risk, Shapley, and graph
  recompute server-side. Historical facts persist; only the mitigation state
  changes. Watch the score drop and the attribution update."

### Step 9 — GraphRAG Explanation (`/explanation`)
- **Say:** "Finally, an explanation layer. GraphRAG **explains** — it never decides
  risk. Every statement cites either a curated knowledge-graph edge or the
  engine's own output. It only receives sanitized context: event types and
  numbers, never passwords, secrets, or message text. A validator flags any
  unsupported claim — and it found zero."

### Step 10 — Evaluation (`/evaluation`)
- **Say:** "Every number here was produced by code that actually ran. The phishing
  classifier: F1 **0.830**. The AI-text detector: F1 **0.809**. Shapley:
  efficiency error **3×10⁻⁹**, mean **~69 ms**. Correlation coverage: **8/8**
  rules exercised. If a metric hadn't been measured, this page would say
  'not yet measured' — nothing is hardcoded."

### Step 11 (optional, strong) — Knowledge Graph (`/knowledge`)
- **Say:** "The curated knowledge graph behind the explanations — techniques like
  Session Hijacking, Push Bombing, AiTM Phishing, SIM Swapping, with their
  enables / defeats / prevented_by edges. Nothing here is auto-discovered."

---

## 4. Numbers to cite (all real, reproducible)

| Claim | Value | Where it comes from |
|---|---|---|
| Demo contextual risk score | **69.5 / HIGH** | `seed_demo.py` on the real engine |
| Score range (sensitivity) | **63–78** | risk sensitivity interval |
| Demo asset-criticality term | **+6.2** (level 4 → ×1.1) | documented multiplier, `risk.py` |
| Demo dependency-exposure term | **+1.6** (level-5 repo, 1 hop → d=0.2) | documented graph term, `risk.py` §1.3 |
| Demo events | **23** | seeded scenario |
| Demo correlations fired | **2** (0.85, 0.55) | correlation engine |
| Phishing classifier F1 | **0.830** (P 1.00, R 0.71) | `run_evaluation.py` |
| AI-text detector F1 | **0.809** | `run_evaluation.py` |
| Planner mean optimality gap | **0.0686** | `run_evaluation.py` |
| Greedy traps observed | **2** | `run_evaluation.py` |
| Shapley max efficiency error | **2.0×10⁻⁹** | `run_evaluation.py` |
| Shapley mean compute time | **~100 ms** (13 features) | `run_evaluation.py` |
| Correlation rules exercised | **8 / 8** | `run_evaluation.py` |
| Backend tests passing | **451** (verified 2026-10-25) | `pytest` |
| Frontend tests passing | **33** | `vitest` |
| End-to-end smoke checks | **46 green, 0 fail** (verified 2026-10-25) | `scripts/smoke.py` |
| Feature B live block (registration) | `sunshine123` → HTTP 422, *"appears **83,270** times in known breach data"* | live run 2026-10-25, HIBP corpus |
| Feature B live login outcome | demo password → `PWNED, count=2`; auth NOT blocked | `/api/auth/me` after demo login, 2026-10-25 |
| Feature A cache | consent-gated auto-refresh **>24h**; re-login inside window = **zero provider calls** | verified live 2026-10-25 |
| Breach email providers | **XposedOrNot** (default, keyless) + HIBP if key configured | `/api/health` provider field |
| Propagation formula factors | **5** (dependency × criticality × weakness × path − mitigation) | `engine/propagation.py` `PROPAGATION_PARAMS` |
| `source_mode` values | **5** (`REAL` / `USER_PROVIDED` / `SIMULATED` / `FIXTURE` / `UNAVAILABLE`) | `schemas.SourceMode` |

**Rule for yourself:** only say the numbers above. Do not improvise a
percentage. If you don't know, say *"I'd have to check the evaluation output."*

---

## 5. Examiner Q&A — anticipate these

**Q: Is this real data?**
A: Mixed, and labeled per-signal. Email-breach checks hit real providers —
XposedOrNot by default, HIBP when its key is configured; both keyless-class
integrations, and the provider that actually answered is named on every
result. The phishing corpus is SYNTHETIC and explicitly labeled — I can't
legally redistribute a real phishing corpus, and I won't fabricate "real"
metrics. The metrics measure generalization on a synthetic disjoint-template
split, not real-world accuracy.

**Q: Why is the phishing F1 only 0.83?**
A: Because it's an honest held-out evaluation on *unseen templates*, not the
training set. Recall is the weaker side (0.71) — the model misses some phrasings,
which is exactly what a real baseline does. I chose not to tune to inflate it.

**Q: Why live OAuth to Google/GitHub/Instagram? Is that safe?**
A: Because the account-connection layer is real: official OAuth 2.0 with PKCE
(S256), a single-use state bound to the initiating user, and a minimum scope —
Google's `gmail.metadata` rather than full mail. CRIX never asks for a provider
password, never stores provider credentials, and never returns an OAuth token to
the browser; refresh tokens are Fernet-encrypted at rest. But I'm careful about
what a connection *proves*: it proves an authorized relationship, not security
posture. Google doesn't expose Security Checkup or 2SV state to third parties,
so CRIX marks those `UNAVAILABLE_THROUGH_PROVIDER` — never "safe." And OAuth
never proves that one account is a recovery route for another, so CRIX asks you
to confirm each relationship; it will not invent an edge.

**Q: What is Compromise Propagation Analysis actually doing?**
A: A defensive what-if. You select an account and mark it `SIMULATED
COMPROMISE`; CRIX recomputes exposure through your confirmed dependency graph,
then re-runs the real risk engine, exact Shapley attribution, and the planner.
The Downstream Exposure Score is a documented formula — dependency strength ×
account criticality × credential/auth weakness × path exposure, minus
mitigation — with the components shown per account. It's a relative
prioritization, not a probability, and it says "Instagram has elevated
downstream compromise exposure if Gmail is compromised," never "Instagram will
be hacked."

**Q: How do you know the risk weights are right?**
A: They're documented expert-set parameters for *relative prioritization*, not a
probability, and they live in one `RISK_PARAMS` dict. A sensitivity test gives the
range (56–69 here). The contribution isn't the weights' precision — it's the
inspectable, non-additive structure and the attribution.

**Q: Why is Shapley exact and not `shap`?**
A: With 13 features, exact enumeration over 2ⁿ subsets is fast (~100 ms) and
guarantees the efficiency property exactly. The authoritative path uses no
sampling; a seeded approximation exists only as a labelled teaching aid, never
as the authority.

**Q: Is greedy optimal?**
A: No — it's a **baseline**. The exact solver is the reference. I measure the gap
(6.9%) and include a constructed trap where greedy loses. I never call greedy
optimal.

**Q: Could GraphRAG hallucinate a relationship?**
A: No. It's deterministic and template-based over a curated knowledge graph, it
only receives sanitized context, and every statement cites an edge or engine
output. A validator flags unsupported claims and it reported zero.

**Q: What about plaintext passwords?**
A: At no point do they leave the browser *or* CRIX. Two paths, same rule:
(a) the Signals page has a client-side k-anonymity check — the browser SHA-1s
the password and sends only the first 5 hex characters; (b) since CRIX
legitimately *holds* your password at registration and sign-in, the server
hashes it transiently and likewise sends only the 5-char prefix to Pwned
Passwords. The stored outcome is provider/status/count/time metadata — the
plaintext and its hash are stored nowhere, and a test asserts no password
material can appear in any response. An automated suite also fails the build
if any network call could leak it.

**Q: How does the automatic breach monitoring respect the user? (Feature A)**
A: Consent-first. Nothing happens automatically until the user turns the
switch on; the opt-in is stored with a timestamp and can be revoked. When
consenting, the first lookup runs immediately; afterwards the lookups happen
only at sign-in and only when the last check is over 24 hours old — otherwise
the login shows the stored result and makes zero provider calls. A down
provider is recorded as UNKNOWN with the stamp still updated, so sign-in is
never blocked and the cache never lies.

**Q: What happens with a fake or placeholder email?**
A: Honesty, by design. If an address uses a placeholder-style domain
(`example.com`, `.invalid`, `.test`, …), CRIX still runs the lookup (that's
the factual part) but marks every resulting event with an explicit warning:
the mailbox was never a real monitored account, so the verdict is shown for
transparency — it is neither "safe" nor evidence of a breach. No fake
conclusions from invented inputs.

**Q: What is actually finished?**
A: A tagged history covers Phases 1–7 plus the SMB org-model migration and the
recent security hardening; the Feature A/B consent flows are tested and
committed. Later milestone phases are documented as future work — I will not
claim completion beyond what the commits and the test suites show. The
evaluation page only shows what was actually measured. (Also honest: the rate
limiter is in-process, so this is a single-worker deployment; PostgreSQL runs
in production, the whole suite runs on SQLite here.)

**Q: What's the weakest part?**
A: Being honest up front is a strength. Tiered: (1) synthetic ML corpus — a real
corpus is future work; (2) curated graphs are static and go stale; (3) the risk
weights are expert-set, not empirically calibrated; (4) live OAuth is frozen in
this build per the spec's §12 freeze — the connector code path is real and
tested, but no provider is configured until the freeze is lifted, and
clearly-labeled `FIXTURE` connectors let the propagation demo run without
credentials. All are documented in `docs/IMPLEMENTATION_STATUS.md`.

---

## 6. Terminology discipline (say it their way)

Use: **"contextual risk score," "relative risk prioritization," "transparent
attribution."**

Also, for the Signal features: **"consent-gated," "k-anonymity," "recorded
outcome," "not meaningful for a placeholder mailbox."**

Never say: "predicts hacking," "prevents account takeover," "probability of being
hacked," "checked everything," or "provider said safe." If asked to predict an
attack, redirect: *"CRIX prioritizes relative risk; it deliberately does not
claim to predict events."*

---

## 7. Time budget

| Section | Minutes |
|---|---|
| Pitch + problem + thesis | 2 |
| Architecture + honesty policy | 2 |
| Live demo | 16–19 |
| Evaluation + security | 2 |
| Limitations & future work | 1 |
| Q&A | remainder |

If short on time, cut Step 11 (Knowledge Graph) and the What-If toggle; keep
Overview → Step 1b (consent + honest outcomes) → Correlations → Risk →
Remediation → Explanation. Step 1b is the strongest "SMB features done right"
evidence — do not cut that one. If you have extra time, keep Connections +
Propagation — they're the strongest "honesty under pressure" story in the deck.

---

## 8. Backup plan

- **App won't load:** present from `README.md` + `docs/ARCHITECTURE.md` +
  `docs/SECURITY.md` + `docs/IMPLEMENTATION_STATUS.md` and the `datasets/` folder.
  The story and every number still hold.
- **No internet:** every live lookup shows **UNAVAILABLE** — that's *correct
  and expected*, and itself a talking point (couldn't-check ≠ safe). A login
  with providers down still succeeds and records the honest outcome; nothing
  blocks, nothing is fabricated.
- **Evaluation page empty:** run `run_evaluation.py` before presenting, or explain
  that empty means "not yet measured" by design.