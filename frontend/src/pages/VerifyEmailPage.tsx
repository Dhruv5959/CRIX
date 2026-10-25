import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { MailCheck } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";

// Consumes the single-use token from the verification email link. Like the
// reset link, the raw token exists only in that email — this page proves
// mailbox control, then CRIX can let the user gate automatic monitoring.
export default function VerifyEmailPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get("token") ?? "";
  const [state, setState] = useState<"verifying" | "verified" | "error">(
    token ? "verifying" : "error",
  );
  const [message, setMessage] = useState(token ? "" : "This link is missing its token.");
  // Confirm exactly once: StrictMode double-invokes effects in dev.
  const attempted = useRef(false);

  useEffect(() => {
    if (!token || attempted.current) return;
    attempted.current = true;
    api
      .confirmEmailVerification(token)
      .then((result) => {
        setState("verified");
        setMessage(
          `${result.email} is verified. Automatic breach monitoring can now be enabled on the Signals page.`,
        );
      })
      .catch((e) => {
        setState("error");
        setMessage(
          e instanceof ApiError ? e.message : "Verification could not complete.",
        );
      });
  }, [token]);

  return (
    <div className="relative grid min-h-screen place-items-center px-4">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-1/2 h-[26rem] w-[26rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/20 blur-3xl"
      />
      <div className="relative w-full max-w-sm animate-fade-in space-y-4">
        <div className="mb-8 flex flex-col items-center gap-3">
          <span className="grid h-12 w-12 place-items-center rounded-2xl border border-accent/25 bg-accent/15 text-accent shadow-accent backdrop-blur-md">
            <MailCheck size={22} />
          </span>
          <div className="text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-ink">Verify your email</h1>
            <p className="mt-1 text-sm text-ink-muted">
              {state === "verifying"
                ? "Checking the link in your mailbox…"
                : state === "verified"
                  ? "The token is single-use; this link is now spent."
                  : "The token is single-use and expires 24 hours after the request."}
            </p>
          </div>
        </div>

        {state === "verifying" && (
          <p className="text-center text-xs text-ink-faint">One moment…</p>
        )}

        {state === "verified" && (
          <>
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
              {message}
            </div>
            <Button variant="primary" className="w-full" onClick={() => navigate("/signals")}>
              Open Signals page
            </Button>
            <Link to="/" className="block text-center text-xs text-accent hover:underline">
              Go to overview
            </Link>
          </>
        )}

        {state === "error" && (
          <>
            <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
              {message} Request a new verification email from the Signals page.
            </div>
            <Link to="/login" className="block text-center text-xs text-accent hover:underline">
              Back to sign in
            </Link>
          </>
        )}
      </div>
    </div>
  );
}
