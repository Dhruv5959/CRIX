import { useEffect, useState } from "react";
import { Plus, ShieldCheck, Trash2, Radar } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { checkPasswordPwned, passwordsMatch } from "@/lib/password";
import { formatCheckedAt, summarizeBreachLookup } from "@/lib/breach";
import type {
  Account,
  BreachMonitorStatus,
  PasswordExposureOutcome,
  PhishingResult,
  SecurityEvent,
} from "@/lib/types";
import { BreachResult } from "@/components/BreachResult";
import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { ProvenanceBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const TABS = ["Breach / Exposure", "Password Hygiene", "Phishing", "Permissions"] as const;
type Tab = (typeof TABS)[number];

// The account the backend guarantees for every user: their registered work
// email. It makes all four signal features usable at login (no manual setup),
// while extra accounts can still be connected below it.
const SELF_ACCOUNT_ID = "registered-email";

function AccountManager({
  accounts,
  selected,
  onSelect,
  onChanged,
}: {
  accounts: Account[];
  selected: string | null;
  onSelect: (id: string) => void;
  onChanged: () => void;
}) {
  const [label, setLabel] = useState("");
  const [service, setService] = useState("Google");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);

  async function create() {
    if (!label) return;
    setBusy(true);
    try {
      await api.createAccount({
        account_id: `${service.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${Date.now()}`,
        label,
        service_name: service,
        email: email || undefined,
        platform: "web",
      } as never);
      setLabel("");
      setEmail("");
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connected Accounts</CardTitle>
        <ProvenanceBadge provenance="USER_REPORTED" />
      </CardHeader>
      <CardBody className="space-y-4">
        {accounts.length > 0 && (
          <div className="space-y-2">
            {accounts.map((a) => (
              <div
                key={a.id}
                className={cn(
                  "flex items-center justify-between rounded-lg border px-3 py-2",
                  selected === a.account_id
                    ? "border-accent/50 bg-accent/5"
                    : "border-white/10 bg-white/[0.04]",
                )}
              >
                <button className="flex-1 text-left" onClick={() => onSelect(a.account_id)}>
                  <div className="text-sm text-ink">{a.label}</div>
                  <div className="text-[11px] text-ink-faint">
                    {a.service_name || "service"} · {a.email || "no email"}
                  </div>
                </button>
                {/* The registered-email account is recreated on the next login,
                    so deleting it would be a illusion of control. */}
                {a.account_id !== SELF_ACCOUNT_ID && (
                  <button
                    className="text-ink-faint hover:text-rose-300"
                    onClick={() => api.deleteAccount(a.account_id).then(onChanged)}
                    aria-label="delete"
                  >
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <Label>Label</Label>
            <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="My Gmail" />
          </div>
          <div>
            <Label>Service</Label>
            <Select value={service} onChange={(e) => setService(e.target.value)}>
              {["Google", "GitHub", "Microsoft", "Apple", "Dropbox", "PayPal", "Coinbase", "Steam", "Reddit"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </Select>
          </div>
          <div>
            <Label>Email (optional)</Label>
            <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
          </div>
        </div>
        <Button variant="primary" size="sm" onClick={create} disabled={busy || !label}>
          <Plus size={14} /> Connect account
        </Button>
      </CardBody>
    </Card>
  );
}

export default function SignalsPage() {
  const [tab, setTab] = useState<Tab>("Breach / Exposure");
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [log, setLog] = useState<string[]>([]);

  const load = () =>
    api.listAccounts().then((list) => {
      // The registered work email sorts first and is selected by default, so
      // the four feature tabs work immediately after login.
      const ordered = [...list].sort(
        (a, b) =>
          Number(a.account_id !== SELF_ACCOUNT_ID) - Number(b.account_id !== SELF_ACCOUNT_ID),
      );
      setAccounts(ordered);
      setSelected((prev) => prev ?? ordered[0]?.account_id ?? null);
    });

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const push = (message: string) => setLog((prev) => [`${new Date().toLocaleTimeString()} — ${message}`, ...prev].slice(0, 8));

  return (
    <div className="space-y-6 animate-fade-in">
      <header>
        <h1 className="text-2xl font-semibold text-ink">Connected Signals</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Feed CRIX the signals it correlates. Live provider connections live on the{" "}
          <a href="#/connections" className="text-accent hover:underline">
            Live Connections
          </a>{" "}
          page; every signal here is either a live lookup against a real breach
          provider, or entered/simulated by you — and labeled as such.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[340px_1fr]">
        <AccountManager accounts={accounts} selected={selected} onSelect={setSelected} onChanged={load} />

        <div className="space-y-4">
          <div className="flex flex-wrap gap-1 glass-sub rounded-lg p-1">
            {TABS.map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={cn(
                  "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                  tab === t ? "bg-white/15 text-ink" : "text-ink-faint hover:text-ink",
                )}
              >
                {t}
              </button>
            ))}
          </div>

          {!selected && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-amber-200">
              Connect an account first to record signals.
            </div>
          )}

          {selected && tab === "Breach / Exposure" && (
            <BreachForm accountId={selected} accounts={accounts} onDone={push} />
          )}
          {selected && tab === "Password Hygiene" && (
            <HygieneForm accountId={selected} accounts={accounts} onDone={push} />
          )}
          {selected && tab === "Phishing" && <PhishingForm accountId={selected} onDone={push} />}
          {selected && tab === "Permissions" && <PermissionsForm accountId={selected} onDone={push} />}

          {log.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Activity</CardTitle>
              </CardHeader>
              <CardBody>
                <ul className="space-y-1 font-mono text-[11px] text-ink-faint">
                  {log.map((entry, i) => (
                    <li key={i}>{entry}</li>
                  ))}
                </ul>
              </CardBody>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

// Feature A: consent + state for automatic breach monitoring of the account
// every user gets at registration — their registered work email. Consent gates
// the automatic sign-in lookup (run only when the last check is >24h old);
// this panel shows state, never a verdict on a password.
function BreachMonitorPanel({ onDone }: { onDone: (m: string) => void }) {
  const { refreshUser } = useAuth();
  const [status, setStatus] = useState<BreachMonitorStatus | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .monitorStatus()
      .then((s) => alive && setStatus(s))
      .catch(() => alive && setStatus(null));
    return () => {
      alive = false;
    };
  }, []);

  async function toggle(enabled: boolean) {
    setBusy(true);
    try {
      const next = await api.setBreachMonitorConsent(enabled);
      setStatus(next);
      await refreshUser();
      onDone(
        enabled
          ? next.last_breach_check_at !== null
            ? "monitoring on — first recorded check stored for the registered email"
            : "monitoring on — first check could not be consulted (recorded as UNKNOWN)"
          : "monitoring off — automatic sign-in lookups stop",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="glass-sub rounded-lg p-3">
      <Switch
        checked={status?.enabled ?? false}
        onChange={toggle}
        label="Automatic breach monitoring"
        disabled={busy || !status}
        description={
          "At sign-in, re-check your registered work email in breach data — only when the " +
          "last check is older than 24h. Consent is stored with a timestamp; revoke anytime. " +
          "Manual checks below never require this switch."
        }
      />
      <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-ink-faint">
        <span>
          Consent:{" "}
          <span className="text-ink-muted">
            {status?.enabled ? "granted" : "not granted"}
          </span>
        </span>
        <span>
          Last automatic check:{" "}
          <span className="font-mono text-ink-muted">
            {formatCheckedAt(status?.last_breach_check_at ?? null)}
          </span>
        </span>
        <span>
          Refresh cadence: <span className="text-ink-muted">24h (offline logs show as UNKNOWN)</span>
        </span>
      </div>
      {status?.placeholder_domain && (
        <p className="mt-2 text-[11px] leading-relaxed text-sky-200">
          The registered address uses a placeholder-style domain, so any provider verdict on
          it is shown for transparency — not evidence about a real monitored mailbox.
        </p>
      )}
    </div>
  );
}

// Feature B: the outcome of the server-side Pwned-Passwords check of the
// password entered at the LAST sign-in. Recorded, not re-tested: CRIX stores
// no password material. Honest vocabulary — an unreachable provider is
// UNAVAILABLE, never "safe".
function PasswordExposureBanner() {
  const { user } = useAuth();
  const outcome: PasswordExposureOutcome | null = user?.last_password_exposure ?? null;
  const who: Record<string, string> = {
    "hibp-pwned-passwords": "HIBP Pwned Passwords",
  };
  const provider = outcome ? (who[outcome.provider] ?? outcome.provider) : "";
  const when = outcome ? formatCheckedAt(outcome.checked_at) : "";

  if (!outcome) {
    return (
      <p className="text-[11px] leading-relaxed text-ink-faint">
        Login password check: the outcome of your next sign-in appears here. The check runs
        server-side with k-anonymity (only a 5-character SHA-1 prefix is sent); CRIX stores
        the outcome — never the password or its hash.
      </p>
    );
  }
  if (outcome.status === "PWNED") {
    return (
      <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-[11px] leading-relaxed text-rose-200">
        <span className="font-semibold">Your last sign-in password appears in known breach data</span>
        {" "}
        ({outcome.count === null ? "multiple matches" : `${outcome.count.toLocaleString()} match${outcome.count === 1 ? "" : "es"}`}{" "}
        via {provider}, {when}). Change it — and anywhere else it was reused — to something
        unique, and enable MFA. This was recorded at sign-in; the password itself is never stored.
      </div>
    );
  }
  if (outcome.status === "UNAVAILABLE") {
    return (
      <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-[11px] leading-relaxed text-amber-200">
        The breach-corpus check at your last sign-in could not be completed ({provider}, {when}).
        Recorded as UNKNOWN — no conclusion was drawn, and no “safe” claim was made.
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-[11px] leading-relaxed text-emerald-200">
      Your last sign-in password was not found in the breach corpus ({provider}, {when}).
      A stored absence is not proof of safety — keep it unique to this account.
    </div>
  );
}

function BreachForm({
  accountId,
  accounts,
  onDone,
}: {
  accountId: string;
  accounts: Account[];
  onDone: (m: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [exposure, setExposure] = useState<"NONE" | "SESSION_ONLY" | "PASSWORD_AND_SESSION">("NONE");
  const [mfaBypass, setMfaBypass] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SecurityEvent[] | null>(null);
  // Most recent stored check for this account, shown right after login so the
  // registered work email has an answer on screen without re-running a call.
  const [stored, setStored] = useState<SecurityEvent[] | null>(null);
  const [prefilledFor, setPrefilledFor] = useState<string | null>(null);

  const account = accounts.find((a) => a.account_id === accountId);

  // Prefill the check target with the selected account's email (your work
  // email is prefilled by default). Prefills exactly once per selected
  // account, so a value you typed is never silently overwritten.
  useEffect(() => {
    const a = accounts.find((x) => x.account_id === accountId);
    if (a?.email && prefilledFor !== accountId) {
      setEmail(a.email);
      setPrefilledFor(accountId);
    }
  }, [accountId, accounts, prefilledFor]);

  useEffect(() => {
    let alive = true;
    api
      .events()
      .then((res) => {
        if (!alive) return;
        const mine = res.events
          .filter(
            (e) => e.account_id === accountId && (e.event_type === "BREACH_EXPOSURE" || e.event_type === "IDENTITY_EXPOSED"),
          )
          .sort((a, b) => (a.detected_at < b.detected_at ? 1 : -1));
        setStored(mine.length ? mine : null);
      })
      .catch(() => alive && setStored(null));
    return () => {
      alive = false;
    };
  }, [accountId]);

  async function run() {
    setBusy(true);
    try {
      const res = await api.breachCheck({
        account_id: accountId,
        email,
        simulated_exposure_type: exposure === "NONE" ? null : exposure,
        simulated_mfa_bypass_capable: mfaBypass,
      });
      setResult(res.events);
      setStored(null);
      const summary = summarizeBreachLookup(res.events);
      const simulated = res.events.some((e) => e.event_type === "SESSION_EXPOSURE");
      onDone(
        `breach lookup via ${summary.providerLabel} → ${summary.status}` +
          (simulated ? " + simulated session scenario" : ""),
      );
    } finally {
      setBusy(false);
    }
  }

  const shownEvents = result ?? stored;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Breach / Exposure</CardTitle>
        <div className="flex gap-1">
          <ProvenanceBadge provenance="REAL" />
          <ProvenanceBadge provenance="SIMULATED" />
        </div>
      </CardHeader>
      <CardBody className="space-y-4">
        {accountId === SELF_ACCOUNT_ID && <BreachMonitorPanel onDone={onDone} />}
        <div>
          <Label>Email to check for breaches</Label>
          <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
          <p className="mt-1 text-[11px] text-ink-faint">
            {account?.email
              ? `Prefilled with the selected account's email (${account.email}). Change it to check another address you control.`
              : "A real lookup, sent through the CRIX backend — you are never redirected to the provider."}{" "}
            The provider that answers is named with the result; if it cannot be
            consulted, the answer is UNKNOWN, never "safe".
          </p>
        </div>
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-amber-300">
            Simulated exposure scenario
          </div>
          <Select value={exposure} onChange={(e) => setExposure(e.target.value as never)}>
            <option value="NONE">None</option>
            <option value="SESSION_ONLY">Session cookie only</option>
            <option value="PASSWORD_AND_SESSION">Password + session cookie</option>
          </Select>
          <div className="mt-3">
            <Switch
              checked={mfaBypass}
              onChange={setMfaBypass}
              label="MFA bypass-capable session"
              description="Stolen session that does not require re-authentication"
              disabled={exposure === "NONE"}
            />
          </div>
          <p className="mt-2 text-[11px] text-amber-200">
            No real infostealer database is consulted; this is a scenario you construct.
          </p>
        </div>
        <Button variant="primary" onClick={run} disabled={busy || !email}>
          <Radar size={14} /> {busy ? "Checking…" : "Run breach check"}
        </Button>
        {shownEvents ? (
          <div className="space-y-1">
            {!result && stored && (
              <p className="text-[11px] text-ink-faint">
                Most recent stored check for this account (no new provider call).
              </p>
            )}
            <BreachResult summary={summarizeBreachLookup(shownEvents)} />
          </div>
        ) : (
          <BreachResult summary={summarizeBreachLookup([])} />
        )}
      </CardBody>
    </Card>
  );
}

function HygieneForm({ accountId, accounts, onDone }: { accountId: string; accounts: Account[]; onDone: (m: string) => void }) {
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [mfaMethod, setMfaMethod] = useState("totp");
  const [passkey, setPasskey] = useState(false);
  const [sms, setSms] = useState(false);
  const [push, setPush] = useState(false);
  const [password, setPassword] = useState("");
  const [otherPassword, setOtherPassword] = useState("");
  const [pwned, setPwned] = useState<{ pwned: boolean; count: number } | null>(null);
  const [reused, setReused] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  const account = accounts.find((a) => a.account_id === accountId);

  async function checkPwned() {
    const [result, reuse] = await Promise.all([
      checkPasswordPwned(password, (prefix) => api.passwordRange(prefix)),
      otherPassword ? passwordsMatch(password, otherPassword) : Promise.resolve(false),
    ]);
    setPwned({ pwned: result.pwned, count: result.count });
    setReused(otherPassword ? reuse : null);
  }

  async function submit() {
    setBusy(true);
    try {
      await api.passwordHygiene({
        account_id: accountId,
        provider: account?.service_name || undefined,
        mfa_enabled: mfaEnabled,
        mfa_method: mfaEnabled ? mfaMethod : null,
        passkey_enabled: passkey,
        sms_otp_recovery: sms,
        push_bombing_reported: push,
        reused_credentials: reused ? [{ label: "cross-account", reused: true }] : [],
      });
      onDone("password hygiene recorded");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Password / Auth Hygiene</CardTitle>
        <ProvenanceBadge provenance="USER_REPORTED" />
      </CardHeader>
      <CardBody className="space-y-5">
        <PasswordExposureBanner />
        <div className="glass-sub rounded-lg p-3">
          <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-accent">
            <ShieldCheck size={13} /> Client-side password check
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <Label>Password to test</Label>
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <div>
              <Label>Another password (reuse test)</Label>
              <Input type="password" value={otherPassword} onChange={(e) => setOtherPassword(e.target.value)} />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-3">
            <Button size="sm" onClick={checkPwned} disabled={!password}>
              Check (k-anonymity)
            </Button>
            {pwned && (
              <span className={cn("text-xs", pwned.pwned ? "text-rose-300" : "text-emerald-300")}>
                {pwned.pwned ? `PWNED — seen ${pwned.count.toLocaleString()}×` : "not found in breach data"}
              </span>
            )}
            {reused !== null && (
              <span className={cn("text-xs", reused ? "text-rose-300" : "text-emerald-300")}>
                {reused ? "passwords match (reuse)" : "passwords differ"}
              </span>
            )}
          </div>
          <p className="mt-2 text-[11px] text-ink-faint">
            The password is SHA-1 hashed in your browser; only the first 5 hash characters are sent.
            Plaintext never leaves this page.
          </p>
        </div>

        <div className="space-y-3">
          <Switch checked={mfaEnabled} onChange={setMfaEnabled} label="MFA enabled on this account" />
          {mfaEnabled && (
            <div>
              <Label>MFA method</Label>
              <Select value={mfaMethod} onChange={(e) => setMfaMethod(e.target.value)}>
                <option value="passkey">Passkey</option>
                <option value="totp">Authenticator app (TOTP)</option>
                <option value="sms">SMS</option>
                <option value="push">Push approval</option>
              </Select>
            </div>
          )}
          <Switch checked={passkey} onChange={setPasskey} label="Passkey enabled" description="Phishing-resistant, origin-bound" />
          <Switch checked={sms} onChange={setSms} label="SMS used for recovery" description="Flagged as SIM-swap exposed" />
          <Switch checked={push} onChange={setPush} label="Received repeated unexpected MFA prompts" description="Push-bombing self-report" />
        </div>

        <Button variant="primary" onClick={submit} disabled={busy}>
          Save hygiene signals
        </Button>
      </CardBody>
    </Card>
  );
}

function PhishingForm({ accountId, onDone }: { accountId: string; onDone: (m: string) => void }) {
  const [text, setText] = useState("");
  const [result, setResult] = useState<PhishingResult | null>(null);
  const [busy, setBusy] = useState(false);

  async function analyze() {
    setBusy(true);
    try {
      setResult(await api.analyzePhishing(text));
    } finally {
      setBusy(false);
    }
  }
  async function record() {
    setBusy(true);
    try {
      await api.recordPhishing(accountId, text);
      onDone("phishing message recorded to account");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Phishing / Scam Analysis</CardTitle>
        <ProvenanceBadge provenance="MODEL" />
      </CardHeader>
      <CardBody className="space-y-4">
        <div>
          <Label>Paste a message to analyze</Label>
          <Textarea rows={5} value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste the email or message text…" />
          <p className="mt-1 text-[11px] text-ink-faint">
            Analyzed by a real trained classifier. Message text is not stored — only derived signals.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="primary" size="sm" onClick={analyze} disabled={busy || !text}>
            Analyze
          </Button>
          <Button size="sm" onClick={record} disabled={busy || !text || !result}>
            Record to account
          </Button>
        </div>
        {result && (
          <div className="space-y-3 glass-sub rounded-lg p-4">
            <div className="flex items-center justify-between">
              <span className={cn("text-sm font-semibold", result.label === "PHISHING" ? "text-rose-300" : "text-emerald-300")}>
                {result.label}
              </span>
              <span className="font-mono text-xs text-ink-muted">confidence {result.confidence.toFixed(2)}</span>
            </div>
            {result.ai_generated_label && (
              <div className="text-xs text-ink-muted">
                Style: <span className="text-ink">{result.ai_generated_label}</span>{" "}
                ({result.ai_generated_confidence?.toFixed(2)})
              </div>
            )}
            {result.signals.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {result.signals.map((s) => (
                  <span key={s.type} className="glass-chip rounded border px-2 py-0.5 text-[10px] text-ink-muted">
                    {s.type}: {s.detail.join(", ")}
                  </span>
                ))}
              </div>
            )}
            <p className="text-[11px] leading-relaxed text-ink-faint">{result.note}</p>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

function PermissionsForm({ accountId, onDone }: { accountId: string; onDone: (m: string) => void }) {
  const [appName, setAppName] = useState("");
  const [platform, setPlatform] = useState("android");
  const [perms, setPerms] = useState("contacts, location");
  const [lastUsed, setLastUsed] = useState("");
  const [report, setReport] = useState<Array<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    try {
      const res = await api.permissionAudit({
        account_id: accountId,
        entries: [
          {
            app_name: appName,
            platform,
            permissions: perms.split(",").map((p) => p.trim()).filter(Boolean),
            last_used_at: lastUsed || null,
          },
        ],
      });
      setReport(res.classification_report as Array<Record<string, unknown>>);
      onDone("permissions audited");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Permission Auditor</CardTitle>
        <ProvenanceBadge provenance="USER_REPORTED" />
      </CardHeader>
      <CardBody className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label>App name</Label>
            <Input value={appName} onChange={(e) => setAppName(e.target.value)} placeholder="Sketchy App" />
          </div>
          <div>
            <Label>Platform</Label>
            <Select value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="android">Android</option>
              <option value="ios">iOS</option>
              <option value="web">Web OAuth</option>
              <option value="desktop">Desktop</option>
            </Select>
          </div>
          <div className="col-span-2">
            <Label>Permissions (comma-separated)</Label>
            <Input value={perms} onChange={(e) => setPerms(e.target.value)} placeholder="contacts, sms, location" />
          </div>
          <div className="col-span-2">
            <Label>Last used (optional)</Label>
            <Input type="date" value={lastUsed} onChange={(e) => setLastUsed(e.target.value)} />
          </div>
        </div>
        <Button variant="primary" size="sm" onClick={submit} disabled={busy || !appName}>
          Audit permissions
        </Button>
        {report && (
          <div className="space-y-2">
            {(report[0] as { permissions: Array<Record<string, string>> })?.permissions?.map((p, i) => (
              <div key={i} className="flex items-start justify-between gap-3 glass-sub rounded-lg px-3 py-2">
                <div>
                  <div className="font-mono text-xs text-ink">{p.permission}</div>
                  <div className="mt-0.5 text-[11px] text-ink-faint">{p.rationale}</div>
                </div>
                <span
                  className={cn(
                    "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                    p.sensitivity === "high"
                      ? "border-rose-500/40 text-rose-300"
                      : p.sensitivity === "medium"
                        ? "border-amber-500/40 text-amber-300"
                        : "border-emerald-500/40 text-emerald-300",
                  )}
                >
                  {p.sensitivity}
                </span>
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}