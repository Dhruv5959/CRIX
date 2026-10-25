// Browser-side generation of a strong password that is verified against live
// breach data before it is ever recommended.
//
// CRITICAL (Rule #4): the candidate NEVER leaves this process except as the
// first five characters of its SHA-1 hash — exactly the k-anonymity contract
// the existing checker in ./password uses with `/api/password-check/range/
// {prefix}`. Nothing in this module logs or persists the generated value, and
// a candidate is only returned after the live range check confirms a count of
// zero. Every failure mode (timeout, provider outage, malformed response,
// exhausted retries) is an explicit error that claims nothing is safe.

import { ApiError } from "./api";
import { checkPasswordPwned } from "./password";

/** Four character classes, ASCII only, so the value survives any transport. */
const CHARACTER_CLASSES = [
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "abcdefghijklmnopqrstuvwxyz",
  "0123456789",
  "!@#$%^&*()-_=+[]{};:,.?/",
] as const;

const ALL_CHARACTERS = CHARACTER_CLASSES.join("");

/**
 * Recommended length: comfortably above CRIX's 10-character minimum while
 * staying inside bcrypt's 72-byte truncation limit (20 ASCII bytes).
 */
export const GENERATED_PASSWORD_LENGTH = 20;

/** Limited retries: a reasonable number of candidates before giving up honestly. */
export const MAX_VERIFICATION_ATTEMPTS = 5;

/** Per-request cap so a hung range endpoint becomes an error, not a hang. */
export const VERIFICATION_TIMEOUT_MS = 8000;

/** Uniform integer in [0, max) via rejection sampling over Web Crypto. */
function randomIndex(max: number): number {
  const limit = 0x100000000 - (0x100000000 % max);
  const sample = new Uint32Array(1);
  crypto.getRandomValues(sample);
  while (sample[0] >= limit) {
    crypto.getRandomValues(sample);
  }
  return sample[0] % max;
}

/**
 * Generate a cryptographically random password with the Web Crypto API
 * (`crypto.getRandomValues`) — never `Math.random()`, never a hardcoded value,
 * never a fixed pattern: every position is drawn from the CSPRNG and the
 * result is shuffled so the guaranteed per-class characters are not pinned to
 * known slots.
 */
export function generatePassword(length: number = GENERATED_PASSWORD_LENGTH): string {
  if (!Number.isInteger(length) || length < CHARACTER_CLASSES.length) {
    throw new RangeError(
      `Password length must be an integer of at least ${CHARACTER_CLASSES.length}.`,
    );
  }
  const characters: string[] = [];
  // One guaranteed character per class, then fill from the full pool.
  for (const characterClass of CHARACTER_CLASSES) {
    characters.push(characterClass[randomIndex(characterClass.length)]);
  }
  for (let i = characters.length; i < length; i += 1) {
    characters.push(ALL_CHARACTERS[randomIndex(ALL_CHARACTERS.length)]);
  }
  // Fisher–Yates shuffle with the same CSPRNG.
  for (let i = characters.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    const swap = characters[i];
    characters[i] = characters[j];
    characters[j] = swap;
  }
  return characters.join("");
}

/** The backend's k-anonymity range proxy (5 hex chars in, suffix list out). */
export type RangeFetcher = (prefix: string) => Promise<{ suffixes: string }>;

export type VerificationOutcome =
  | { status: "VERIFIED"; password: string; attempts: number }
  | { status: "BREACH_REJECTED"; attempts: number; reason: string }
  | { status: "UNAVAILABLE"; attempts: number; reason: string }
  | { status: "MALFORMED"; attempts: number; reason: string };

export interface VerificationOptions {
  length?: number;
  maxAttempts?: number;
  timeoutMs?: number;
  /** Candidate source override (tests / advanced callers). Defaults to generatePassword. */
  generate?: () => string;
}

class RangeResponseShapeError extends Error {}
class RangeTimeoutError extends Error {}

async function withTimeout<T>(work: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new RangeTimeoutError()), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Generate candidates until one is confirmed absent from breach data.
 *
 * Per candidate: SHA-1 locally → send only the first five hex characters to
 * the range endpoint → compare the returned suffixes locally. A hit (count > 0)
 * means the candidate is discarded and another is generated, up to
 * `maxAttempts`. Only a live zero-count answer returns `VERIFIED`; every
 * failure returns a status that the UI must render as an error, never as a
 * safety claim.
 */
export async function generateVerifiedPassword(
  rangeFetcher: RangeFetcher,
  options: VerificationOptions = {},
): Promise<VerificationOutcome> {
  const length = options.length ?? GENERATED_PASSWORD_LENGTH;
  const maxAttempts = options.maxAttempts ?? MAX_VERIFICATION_ATTEMPTS;
  const timeoutMs = options.timeoutMs ?? VERIFICATION_TIMEOUT_MS;
  const generate = options.generate ?? (() => generatePassword(length));

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const candidate = generate();
    let pwned: boolean;
    try {
      const checked = await checkPasswordPwned(candidate, async (prefix) => {
        const response = await withTimeout(rangeFetcher(prefix), timeoutMs);
        if (!response || typeof response.suffixes !== "string") {
          throw new RangeResponseShapeError("the range response carried no suffix list");
        }
        return response;
      });
      pwned = checked.pwned || checked.count > 0;
    } catch (error) {
      if (error instanceof RangeResponseShapeError) {
        return { status: "MALFORMED", attempts: attempt, reason: error.message };
      }
      if (error instanceof RangeTimeoutError) {
        return {
          status: "UNAVAILABLE",
          attempts: attempt,
          reason: `the breach-check service did not respond within ${timeoutMs}ms`,
        };
      }
      if (error instanceof ApiError) {
        return { status: "UNAVAILABLE", attempts: attempt, reason: error.message };
      }
      return {
        status: "UNAVAILABLE",
        attempts: attempt,
        reason: error instanceof Error ? error.message : "unknown network failure",
      };
    }
    if (!pwned) {
      return { status: "VERIFIED", password: candidate, attempts: attempt };
    }
    // Found in breach data: discard the candidate and generate another.
  }
  return {
    status: "BREACH_REJECTED",
    attempts: maxAttempts,
    reason: `all ${maxAttempts} generated candidates were found in breach data`,
  };
}

type FailureOutcome = Exclude<VerificationOutcome, { status: "VERIFIED" }>;

/** User-facing error copy. Every path states that no password was recommended. */
export function verificationErrorMessage(outcome: FailureOutcome): string {
  if (outcome.status === "BREACH_REJECTED") {
    return (
      `No password was recommended: all ${outcome.attempts} generated candidates ` +
      "were found in breach data. Generate another to try again."
    );
  }
  if (outcome.status === "MALFORMED") {
    return (
      "No password was recommended: the breach-check service returned an " +
      "unexpected response, so no candidate could be verified."
    );
  }
  const reason = outcome.reason.replace(/[.\s]+$/, "");
  return (
    `Could not verify a candidate against breach data: ${reason}. ` +
    "No password was recommended, and nothing here is claimed to be safe."
  );
}

/**
 * Copy the generated value to the clipboard — the one place besides the form
 * field it may go. Fails quietly (returns false) when the API is unavailable
 * or blocked; never logs the value.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  if (!text) return false;
  try {
    const clipboard = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
    if (!clipboard || typeof clipboard.writeText !== "function") return false;
    await clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

const BREACH_COUNT_RE = /appears\s+([\d,]+)\s+times\s+in\s+known\s+breach\s+data/i;

/**
 * Read the breach count out of the backend's registration refusal
 * ("That password appears 126,414 times in known breach data. …") so the auth
 * screen can show the same warning with the generate affordance. Returns null
 * for any other message — a non-breach 422 must never become a breach warning.
 */
export function parseBreachWarningCount(message: string | null | undefined): number | null {
  if (!message) return null;
  const match = BREACH_COUNT_RE.exec(message);
  if (!match) return null;
  const count = Number.parseInt(match[1].replace(/,/g, ""), 10);
  return Number.isFinite(count) && count > 0 ? count : null;
}

export type PasswordSurface = "register" | "login" | "reset";

export interface UsePasswordPlan {
  /** Put the generated value into the main password field. */
  fillPassword: boolean;
  /** Put it into the confirmation field (the reset screen has one). */
  fillConfirm: boolean;
  /** Copy to the clipboard first — the value must survive navigation. */
  copy: boolean;
  /**
   * Send the user into the password-reset flow instead of touching the value
   * in the login field: a replacement password cannot authenticate until it
   * has been saved to the account, so it must never silently replace it.
   */
  guideToReset: boolean;
}

/**
 * The single source of truth for what "Use this password" does per surface.
 * `login` deliberately fills nothing.
 */
export function passwordUsePlan(surface: PasswordSurface): UsePasswordPlan {
  switch (surface) {
    case "register":
      return { fillPassword: true, fillConfirm: false, copy: false, guideToReset: false };
    case "login":
      return { fillPassword: false, fillConfirm: false, copy: true, guideToReset: true };
    case "reset":
      return { fillPassword: true, fillConfirm: true, copy: false, guideToReset: false };
  }
}
