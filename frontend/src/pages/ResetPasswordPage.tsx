import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { KeyRound, MailCheck } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

// Consumes the single-use token from the reset link the backend emails.
// In dev there is no SMTP, so the .eml lands in backend/artifacts/outbox/ —
// that path is surfaced on the "request" screen so the flow is usable locally.
export default function ResetPasswordPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await api.passwordResetConfirm(token, password);
      setDone(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reset the password.");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <Shell>
        <div className="flex items-start gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
          <MailCheck size={15} className="mt-0.5 shrink-0" />
          <span>Password updated. Existing sessions were revoked — sign in again.</span>
        </div>
        <Button variant="primary" className="w-full" onClick={() => navigate("/login")}>
          Go to sign in
        </Button>
      </Shell>
    );
  }

  if (!token) {
    return (
      <Shell>
        <p className="text-xs text-rose-300">
          This link is missing its token. Request a new password reset email.
        </p>
        <Link to="/login" className="text-center text-xs text-accent hover:underline">
          Back to sign in
        </Link>
      </Shell>
    );
  }

  return (
    <Shell>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <Label>New password</Label>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={10}
            maxLength={128}
            autoComplete="new-password"
          />
          <p className="mt-1 text-[11px] text-ink-faint">
            At least 10 characters. Hashed with bcrypt (cost 12).
          </p>
        </div>
        <div>
          <Label>Confirm new password</Label>
          <Input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            minLength={10}
            maxLength={128}
            autoComplete="new-password"
          />
        </div>

        {error && (
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
            {error}
          </div>
        )}

        <Button type="submit" variant="primary" className="w-full" disabled={busy}>
          {busy ? "Working…" : "Set new password"}
        </Button>
      </form>

      <Link to="/login" className="block text-center text-xs text-accent hover:underline">
        Back to sign in
      </Link>
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative grid min-h-screen place-items-center px-4">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 h-[26rem] w-[26rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/20 blur-3xl"
      />
      <div className="relative w-full max-w-sm animate-fade-in">
        <div className="mb-8 flex flex-col items-center gap-3">
          <span className="grid h-12 w-12 place-items-center rounded-2xl border border-accent/25 bg-accent/15 text-accent shadow-accent backdrop-blur-md">
            <KeyRound size={22} />
          </span>
          <div className="text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-ink">Reset your password</h1>
            <p className="mt-1 text-sm text-ink-muted">
              The token is single-use and expires 30 minutes after the request.
            </p>
          </div>
        </div>
        <div className="relative">
          <span
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-8 -top-px h-px bg-gradient-to-r from-transparent via-accent/60 to-transparent"
          />
          <div className="glass panel-pad space-y-4">{children}</div>
        </div>
      </div>
    </div>
  );
}
