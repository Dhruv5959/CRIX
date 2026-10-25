// "Generate a safe password" for the auth screens.
//
// The container owns only UI state (working / verified / error); every
// security decision lives in @/lib/passwordGenerator: candidates come from the
// Web Crypto CSPRNG and are recommended only after a live zero-count range
// check. Buttons are type="button" because the panel renders inside the
// login/register/reset forms — nothing here may submit a form or change an
// account's password on its own.

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  copyToClipboard,
  generateVerifiedPassword,
  verificationErrorMessage,
  GENERATED_PASSWORD_LENGTH,
  type PasswordSurface,
  type VerificationOutcome,
} from "@/lib/passwordGenerator";

type FailureOutcome = Exclude<VerificationOutcome, { status: "VERIFIED" }>;

function isFailure(outcome: VerificationOutcome): outcome is FailureOutcome {
  return outcome.status !== "VERIFIED";
}

/**
 * The compromised-password warning on the auth screen, with the generate
 * affordance directly below it. Non-blocking on every surface: it never
 * disables the form.
 */
export function PasswordBreachWarning({
  count,
  surface,
  onGenerate,
}: {
  count: number;
  surface: "login" | "register";
  onGenerate: () => void;
}) {
  return (
    <div className="space-y-2" data-testid="password-breach-warning">
      <div
        role="alert"
        className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs leading-relaxed text-rose-200 backdrop-blur-md"
      >
        <span className="font-semibold">
          This password appears {count.toLocaleString()} times in known breach data.
        </span>{" "}
        {surface === "login"
          ? "You can still sign in — but do not keep it: a password entered here is checked, not changed. Reset it so the replacement is saved to your account."
          : "Choose a different one, or generate a password that is verified against breach data."}
      </div>
      <Button
        type="button"
        size="sm"
        onClick={onGenerate}
        data-testid="generate-safe-password"
        className="w-full"
      >
        Generate a safe password
      </Button>
    </div>
  );
}

export interface PasswordGeneratorViewProps {
  phase: "working" | "verified" | "error";
  outcome: VerificationOutcome | null;
  revealing: boolean;
  copied: boolean;
  surface: PasswordSurface;
  onGenerateAnother: () => void;
  onToggleReveal: () => void;
  onCopy: () => void;
  onUse: () => void;
}

/** Pure presentational panel — every state is passed in, so it is unit-testable. */
export function PasswordGeneratorView({
  phase,
  outcome,
  revealing,
  copied,
  surface,
  onGenerateAnother,
  onToggleReveal,
  onCopy,
  onUse,
}: PasswordGeneratorViewProps) {
  return (
    <div className="glass-sub space-y-2 rounded-lg p-3" data-testid="password-generator">
      {phase === "working" && (
        <p
          aria-busy="true"
          data-testid="password-generator-working"
          className="text-[11px] leading-relaxed text-ink-muted"
        >
          Generating a {GENERATED_PASSWORD_LENGTH}-character password and verifying it against
          breach data — only a 5-character SHA-1 hash prefix is sent, never the password or the
          full hash.
        </p>
      )}

      {phase === "error" && outcome && isFailure(outcome) && (
        <div
          role="alert"
          data-testid="password-generator-error"
          className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs leading-relaxed text-rose-200"
        >
          {verificationErrorMessage(outcome)}
        </div>
      )}

      {phase === "verified" && outcome && outcome.status === "VERIFIED" && (
        <>
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] font-semibold uppercase tracking-wide text-accent">
              Generated password
            </span>
            <span
              data-testid="password-generator-verified"
              className="text-[10px] font-semibold uppercase tracking-wide text-emerald-300"
            >
              Verified — 0 matches in breach data
            </span>
          </div>

          <div className="flex items-center gap-2 rounded-lg border border-white/15 bg-white/[0.06] px-3 py-2">
            <output
              data-testid="generated-password"
              className="min-w-0 flex-1 break-all font-mono text-sm text-ink"
            >
              {revealing ? outcome.password : "•".repeat(outcome.password.length)}
            </output>
            <button
              type="button"
              data-testid="toggle-reveal"
              onClick={onToggleReveal}
              aria-pressed={revealing}
              className="shrink-0 cursor-pointer text-[11px] font-semibold text-accent hover:underline"
            >
              {revealing ? "Hide" : "Show"}
            </button>
          </div>

          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" data-testid="generate-another" onClick={onGenerateAnother}>
              Generate another
            </Button>
            <Button type="button" size="sm" data-testid="copy-password" onClick={onCopy}>
              {copied ? "Copied" : "Copy password"}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="primary"
              data-testid="use-password"
              onClick={onUse}
            >
              Use this password
            </Button>
          </div>

          <p className="text-[11px] leading-relaxed text-ink-faint">
            {outcome.password.length} characters from upper- and lowercase letters, digits and
            symbols, drawn from the browser&rsquo;s cryptographic random source and confirmed
            against breach data with a live zero-match check. Absence from the corpus is not proof
            of safety — keep it unique to this account.
            {surface === "login" &&
              " Using it here does not change your password: save it through the reset flow before it can sign you in."}
          </p>
        </>
      )}

      {phase === "error" && (
        <Button type="button" size="sm" data-testid="generate-another" onClick={onGenerateAnother}>
          Try again
        </Button>
      )}
    </div>
  );
}

/**
 * Container: runs the verified-generation loop and hands the result (or a
 * clear error) to the view. `onUse` only ever delivers the value — the parent
 * decides what to fill; no submit happens from here.
 */
export function PasswordGenerator({
  surface,
  onUse,
}: {
  surface: PasswordSurface;
  onUse: (password: string) => void;
}) {
  const [phase, setPhase] = useState<"working" | "verified" | "error">("working");
  const [outcome, setOutcome] = useState<VerificationOutcome | null>(null);
  const [revealing, setRevealing] = useState(false);
  const [copied, setCopied] = useState(false);
  const alive = useRef(true);

  const run = useCallback(async () => {
    setPhase("working");
    setOutcome(null);
    setRevealing(false);
    setCopied(false);
    const result = await generateVerifiedPassword((prefix) => api.passwordRange(prefix));
    if (!alive.current) return;
    setOutcome(result);
    setPhase(result.status === "VERIFIED" ? "verified" : "error");
  }, []);

  useEffect(() => {
    alive.current = true;
    void run();
    return () => {
      alive.current = false;
    };
  }, [run]);

  const handleCopy = useCallback(async () => {
    if (!outcome || outcome.status !== "VERIFIED") return;
    const done = await copyToClipboard(outcome.password);
    if (done && alive.current) setCopied(true);
  }, [outcome]);

  const handleUse = useCallback(() => {
    if (!outcome || outcome.status !== "VERIFIED") return;
    onUse(outcome.password);
  }, [outcome, onUse]);

  return (
    <PasswordGeneratorView
      phase={phase}
      outcome={outcome}
      revealing={revealing}
      copied={copied}
      surface={surface}
      onGenerateAnother={() => void run()}
      onToggleReveal={() => setRevealing((value) => !value)}
      onCopy={() => void handleCopy()}
      onUse={handleUse}
    />
  );
}
