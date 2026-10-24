import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { UserPlus } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

// Consumes the single-use token from the invitation link an ORG_ADMIN shares.
// The account is created here only when the email has no CRIX account yet;
// otherwise the backend requires the recipient to be logged in as that
// account (defense against pre-registration invite takeover), and this page
// relays the backend's message instead of guessing.
export default function InviteAcceptPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const result = await api.acceptInvitation(token, password);
      setDone(`${result.email} joined as ${result.role}.`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not accept the invitation.");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <Shell>
        <p className="text-xs text-emerald-300">{done}</p>
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
          This link is missing its token. Ask your administrator for a new invitation.
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
          <Label>Choose a password</Label>
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
            At least 10 characters. Only needed if no account exists yet for the invited email.
          </p>
        </div>
        <div>
          <Label>Confirm password</Label>
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
            {error.toLowerCase().includes("log in") && (
              <>
                {" "}
                <Link
                  to="/login"
                  className="font-medium text-accent underline underline-offset-2"
                >
                  Sign in
                </Link>{" "}
                and reopen this invitation link.
              </>
            )}
          </div>
        )}

        <Button type="submit" variant="primary" className="w-full" disabled={busy}>
          {busy ? "Working…" : "Accept invitation"}
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
            <UserPlus size={22} />
          </span>
          <div className="text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-ink">Join the organization</h1>
            <p className="mt-1 text-sm text-ink-muted">
              The invitation token is single-use and expires after 7 days.
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
