import { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { ShieldHalf } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { api, ApiError } from "@/lib/api";
import { detectBreachedPassword } from "@/lib/password";
import {
  copyToClipboard,
  parseBreachWarningCount,
  passwordUsePlan,
} from "@/lib/passwordGenerator";
import { PasswordBreachWarning, PasswordGenerator } from "@/components/PasswordGenerator";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";

export default function LoginPage() {
  const { user, login, register } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<"login" | "register" | "forgot">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  // Feature A: optional affirmative opt-in at registration. Never on by
  // default — the server stores the choice with a timestamp.
  const [consent, setConsent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Live k-anonymity verdict for the password being typed: the breach count
  // when it is found, null in every other case (clean, empty, or unchecked —
  // a provider failure never renders as an all-clear).
  const [breachCount, setBreachCount] = useState<number | null>(null);
  const [generatorOpen, setGeneratorOpen] = useState(false);

  // Debounced client-side check of whatever is typed, reusing CRIX's existing
  // checker + /api/password-check/range/{prefix}: SHA-1 locally, only the first
  // five hash characters leave the browser. Never runs on the reset-request tab.
  useEffect(() => {
    if (mode === "forgot" || !password) {
      setBreachCount(null);
      return;
    }
    let alive = true;
    const timer = window.setTimeout(() => {
      detectBreachedPassword(password, (prefix) => api.passwordRange(prefix)).then((found) => {
        if (alive) setBreachCount(found ? found.count : null);
      });
    }, 1000);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [password, mode]);

  if (user) return <Navigate to="/" replace />;

  /** Switching tabs drops mode-specific state: the warning and the open
   * generator both describe the previous tab's password. */
  function switchMode(next: "login" | "register" | "forgot") {
    setMode(next);
    setBreachCount(null);
    setGeneratorOpen(false);
  }

  /** "Use this password": per-surface behavior from passwordUsePlan. Register
   * fills the field and leaves the normal flow intact; login fills nothing and
   * routes to the reset flow with the value copied, because a replacement
   * password cannot authenticate until it is saved to the account. Never
   * submits a form or changes an account. */
  async function applyGenerated(generated: string) {
    if (mode === "forgot") return;
    const plan = passwordUsePlan(mode);
    if (plan.copy) await copyToClipboard(generated);
    if (plan.fillPassword) setPassword(generated);
    if (plan.guideToReset) {
      setMode("forgot");
      setError(null);
      setNotice(
        "A strong password was generated and copied to your clipboard. Request a reset " +
          "link below, then paste it as your new password — it only takes effect once it " +
          "has been saved to your account.",
      );
    }
    setBreachCount(null);
    setGeneratorOpen(false);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      if (mode === "login") {
        await login(email, password, totp || undefined);
        navigate("/");
      } else if (mode === "register") {
        await register(email, password, consent);
        navigate("/");
      } else {
        // Password reset. The backend has no SMTP in dev, so it writes the
        // message to a local outbox — tell the user where to find it.
        await api.passwordResetRequest(email);
        setNotice(
          "If that address has an account, a reset link was sent. " +
            "With no SMTP configured in development, open the newest .eml in " +
            "backend/artifacts/outbox/ and follow the link inside.",
        );
      }
    } catch (err) {
      // The server refuses to register a password found in breach data. Show
      // that as the same breach warning + generate affordance as the live
      // check instead of a generic error.
      const serverBreachCount =
        mode === "register" && err instanceof ApiError && err.status === 422
          ? parseBreachWarningCount(err.message)
          : null;
      if (serverBreachCount !== null) {
        setError(null);
        setBreachCount(serverBreachCount);
        return;
      }
      setError(err instanceof Error ? err.message : "Something went wrong");
      // 409 from register means the address is taken — point them at sign-in
      // (or reset) instead of leaving a dead end.
      if (mode === "register" && err instanceof ApiError && err.status === 409) {
        setError(
          "An account with this email already exists. Sign in instead — or use “Forgot password?” if you don't remember it.",
        );
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative grid min-h-screen place-items-center px-4">
      {/* Local light source behind the card so the frost has depth even on a
          short viewport. Decorative only — never read by assistive tech. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 h-[26rem] w-[26rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/20 blur-3xl"
      />
      <div className="relative w-full max-w-sm animate-fade-in">
        <div className="mb-8 flex flex-col items-center gap-3">
          <span className="grid h-12 w-12 place-items-center rounded-2xl border border-accent/25 bg-accent/15 text-accent shadow-accent backdrop-blur-md">
            <ShieldHalf size={22} />
          </span>
          <div className="text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-ink">CRIX</h1>
            <p className="mt-1 text-sm text-ink-muted">
              Security problems, connected and prioritized.
            </p>
          </div>
        </div>

        <div className="relative">
          {/* Glass edge highlight: a soft accent sheen along the top edge. */}
          <span
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-8 -top-px h-px bg-gradient-to-r from-transparent via-accent/60 to-transparent"
          />
          <form onSubmit={submit} className="glass panel-pad space-y-4">
            <div className="flex rounded-xl border border-white/10 bg-white/[0.04] p-0.5 text-xs backdrop-blur-md">
              {(["login", "register"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => switchMode(m)}
                  className={`flex-1 cursor-pointer rounded-lg px-3 py-1.5 font-medium capitalize transition-colors ${
                    mode === m
                      ? "bg-white/15 text-ink shadow-inset"
                      : "text-ink-faint hover:bg-white/[0.06] hover:text-ink"
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>

          <div>
            <Label>Email</Label>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="email" />
          </div>
          {mode !== "forgot" && (
            <div>
              <Label>Password</Label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                minLength={mode === "register" ? 10 : undefined}
              />
              {mode === "register" && (
                <p className="mt-1 text-[11px] text-ink-faint">At least 10 characters. Hashed with bcrypt (cost 12).</p>
              )}
            </div>
          )}
          {mode !== "forgot" && breachCount !== null && (
            <PasswordBreachWarning
              count={breachCount}
              surface={mode}
              onGenerate={() => setGeneratorOpen(true)}
            />
          )}
          {mode !== "forgot" && generatorOpen && (
            <PasswordGenerator surface={mode} onUse={(generated) => void applyGenerated(generated)} />
          )}
          {mode === "register" && (
            <Switch
              checked={consent}
              onChange={setConsent}
              label="Enable automatic breach monitoring"
              description={
                "At sign-in, re-check this address in breach data — only when the last " +
                "check is older than 24h. Consent is recorded with a timestamp; revoke anytime."
              }
            />
          )}
          {mode === "login" && (
            <div>
              <Label>2FA code (optional)</Label>
              <Input value={totp} onChange={(e) => setTotp(e.target.value)} placeholder="123456" inputMode="numeric" />
            </div>
          )}
          {mode === "login" && (
            <button
              type="button"
              onClick={() => {
                switchMode("forgot");
                setError(null);
                setNotice(null);
              }}
              className="-mt-1 block cursor-pointer text-right text-[11px] text-accent hover:underline"
            >
              Forgot password?
            </button>
          )}

          {error && (
            <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200 backdrop-blur-md">
              {error}
            </div>
          )}
          {notice && (
            <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-xs text-sky-200 backdrop-blur-md">
              {notice}
            </div>
          )}

          <Button type="submit" variant="primary" className="w-full" disabled={busy}>
            {busy
              ? "Working…"
              : mode === "login"
                ? "Sign in"
                : mode === "register"
                  ? "Create account"
                  : "Send reset link"}
          </Button>
          {mode === "forgot" && (
            <button
              type="button"
              onClick={() => {
                switchMode("login");
                setError(null);
                setNotice(null);
              }}
              className="block w-full cursor-pointer text-center text-xs text-accent hover:underline"
            >
              Back to sign in
            </button>
          )}
        </form>
        </div>

        <p className="mt-6 text-center text-[11px] leading-relaxed text-ink-faint">
          CRIX's own login uses bcrypt, rotating refresh tokens, and rate limiting.
          Live third-party connectors are disabled in this build; tokens are never
          sent to this browser.
        </p>
      </div>
    </div>
  );
}