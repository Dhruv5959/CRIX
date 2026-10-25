// Tests for the "Generate a safe password" feature.
//
// Covered here (spec §5): breached-password detection, generated format and
// strength, live zero-count verification, rejection of candidates found in
// breach data, API timeout / unavailable service / malformed responses, the
// copy + use wiring (including login-never-replaces and reset-accepts), and
// the Rule #4 invariant that no plaintext password or full hash is logged or
// transmitted — only a 5-character SHA-1 prefix ever reaches the network.

import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";
import {
  GENERATED_PASSWORD_LENGTH,
  MAX_VERIFICATION_ATTEMPTS,
  copyToClipboard,
  generatePassword,
  generateVerifiedPassword,
  parseBreachWarningCount,
  passwordUsePlan,
  verificationErrorMessage,
  type RangeFetcher,
  type VerificationOutcome,
} from "./passwordGenerator";
import { detectBreachedPassword, sha1Hex } from "./password";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** Narrow a non-verified outcome for the error-copy helper. */
function failure(outcome: VerificationOutcome): Exclude<VerificationOutcome, { status: "VERIFIED" }> {
  if (outcome.status === "VERIFIED") throw new Error("expected a failure outcome, got VERIFIED");
  return outcome;
}

const SYMBOLS = /[!@#$%^&*()\-_=+\[\]{};:,.?\/]/;
const HEX_PREFIX = /^[0-9A-F]{5}$/;

describe("generated password format and strength", () => {
  it("produces a 20-character password using all four character classes", () => {
    for (let i = 0; i < 25; i += 1) {
      const password = generatePassword();
      expect(password).toHaveLength(GENERATED_PASSWORD_LENGTH);
      expect(password).toHaveLength(20);
      expect(password).toMatch(/[a-z]/);
      expect(password).toMatch(/[A-Z]/);
      expect(password).toMatch(/[0-9]/);
      expect(password).toMatch(SYMBOLS);
      expect(password).toMatch(/^[A-Za-z0-9!@#$%^&*()\-_=+\[\]{};:,.?\/]+$/);
      // bcrypt truncates past 72 bytes — every candidate must fit.
      expect(new TextEncoder().encode(password).length).toBeLessThanOrEqual(72);
      expect(password.length).toBeGreaterThanOrEqual(10);
    }
  });

  it("honours a longer requested length without dropping any class", () => {
    const password = generatePassword(48);
    expect(password).toHaveLength(48);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(SYMBOLS);
  });

  it("refuses lengths too short to cover every class", () => {
    expect(() => generatePassword(3)).toThrow(RangeError);
    expect(() => generatePassword(2.5)).toThrow(RangeError);
  });

  it("uses the Web Crypto CSPRNG and never Math.random()", () => {
    const mathRandom = vi.spyOn(Math, "random").mockImplementation(() => {
      throw new Error("Math.random() must never be used for password generation");
    });
    const password = generatePassword();
    expect(password).toHaveLength(20);
    expect(mathRandom).not.toHaveBeenCalled();
  });

  it("is unpredictable across calls (no fixed or cycling pattern)", () => {
    const samples = new Set(Array.from({ length: 20 }, () => generatePassword()));
    expect(samples.size).toBe(20);
  });
});

describe("breached-password detection", () => {
  it("reports the breach count when the password is found, sending only the prefix", async () => {
    const typed = "TypedReader126414!";
    const fullHash = await sha1Hex(typed);
    const seen: string[] = [];
    const fetcher: RangeFetcher = vi.fn(async (prefix: string) => {
      seen.push(prefix);
      return { suffixes: `${fullHash.slice(5)}:126414\n00000000000000000000000000000000000:3` };
    });

    const found = await detectBreachedPassword(typed, fetcher);

    expect(found).toEqual({ count: 126414 });
    expect(seen).toEqual([fullHash.slice(0, 5)]);
    expect(seen[0]).toMatch(HEX_PREFIX);
    expect(JSON.stringify(seen)).not.toContain(typed);
    expect(JSON.stringify(seen)).not.toContain(fullHash);
  });

  it("returns null when the password is absent from breach data", async () => {
    const fetcher: RangeFetcher = async () => ({
      suffixes: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:9",
    });
    await expect(detectBreachedPassword("unique-never-seen-9Fq2!", fetcher)).resolves.toBeNull();
  });

  it("returns null (no verdict, never a safe claim) when the check fails", async () => {
    const fetcher: RangeFetcher = async () => {
      throw new ApiError(503, "CRIX is temporarily unavailable (HTTP 503).");
    };
    await expect(detectBreachedPassword("whatever-user-typed", fetcher)).resolves.toBeNull();
  });

  it("treats an empty password as no verdict without touching the network", async () => {
    const fetcher = vi.fn(async () => ({ suffixes: "" }));
    await expect(detectBreachedPassword("", fetcher)).resolves.toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("live zero-count verification", () => {
  it("recommends a candidate only after the range check confirms zero matches", async () => {
    const seen: string[] = [];
    const fetcher = vi.fn(async (prefix: string) => {
      seen.push(prefix);
      return {
        suffixes: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\n00000000000000000000000000000000000:7",
      };
    });

    const outcome = await generateVerifiedPassword(fetcher);

    expect(outcome.status).toBe("VERIFIED");
    if (outcome.status !== "VERIFIED") return;
    expect(outcome.attempts).toBe(1);
    expect(outcome.password).toHaveLength(20);
    // Only the 5-char prefix went out; the plaintext and full hash stayed local.
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(HEX_PREFIX);
    const wire = JSON.stringify(fetcher.mock.calls);
    expect(wire).not.toContain(outcome.password);
    expect(wire).not.toContain(await sha1Hex(outcome.password));
  });

  it("sends only the prefix over the real API client, with no request body", async () => {
    const fetcher = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ prefix: "ABCDE", suffixes: "", k_anonymity: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetcher);

    const outcome = await generateVerifiedPassword((prefix) => api.passwordRange(prefix));

    expect(outcome.status).toBe("VERIFIED");
    if (outcome.status !== "VERIFIED") return;
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toMatch(/^\/api\/password-check\/range\/[0-9A-Fa-f]{5}$/);
    expect(init.body).toBeUndefined();
    expect(init.headers.get("Authorization")).toBeNull();
    expect(JSON.stringify(fetcher.mock.calls)).not.toContain(outcome.password);
  });

  it("never logs the generated password", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );

    const outcome = await generateVerifiedPassword(async () => ({ suffixes: "" }));

    expect(outcome.status).toBe("VERIFIED");
    if (outcome.status !== "VERIFIED") return;
    for (const spy of spies) {
      expect(spy.mock.calls.flat().join(" ")).not.toContain(outcome.password);
    }
    expect(spies.every((spy) => spy.mock.calls.length === 0)).toBe(true);
  });
});

describe("rejection of candidates found in breach data", () => {
  it("discards a flagged candidate and recommends the next verified one", async () => {
    const breached = "BreachedCandidate126414!";
    const clean = "QuietHarbor72!qX";
    const breachedSuffix = (await sha1Hex(breached)).slice(5);
    const fetcher = vi.fn(async () => ({ suffixes: `${breachedSuffix}:126414` }));
    const queue = [breached, clean];

    const outcome = await generateVerifiedPassword(fetcher, {
      generate: () => queue.shift()!,
      maxAttempts: 3,
    });

    expect(outcome).toMatchObject({ status: "VERIFIED", password: clean, attempts: 2 });
    expect(fetcher).toHaveBeenCalledTimes(2);
    // The breached candidate was checked (prefix only) and never recommended.
    expect(JSON.stringify(fetcher.mock.calls)).not.toContain(breached);
  });

  it("gives up honestly when every attempt is found, recommending nothing", async () => {
    const breached = "KnownBadPassword126414!";
    const breachedSuffix = (await sha1Hex(breached)).slice(5);
    const fetcher = vi.fn(async () => ({ suffixes: `${breachedSuffix}:126414` }));

    const outcome = await generateVerifiedPassword(fetcher, {
      generate: () => breached,
      maxAttempts: 3,
    });

    expect(outcome.status).toBe("BREACH_REJECTED");
    expect(outcome).not.toHaveProperty("password");
    expect(outcome.attempts).toBe(3);
    // Limited, bounded retries.
    expect(fetcher).toHaveBeenCalledTimes(3);
    const message = verificationErrorMessage(failure(outcome));
    expect(message).toContain("No password was recommended");
    expect(message).not.toMatch(/is safe/);
  });

  it("stops at the default retry limit rather than looping forever", async () => {
    const breached = "AlwaysPwned126414!";
    const breachedSuffix = (await sha1Hex(breached)).slice(5);
    const fetcher = vi.fn(async () => ({ suffixes: `${breachedSuffix}:126414` }));

    const outcome = await generateVerifiedPassword(fetcher, { generate: () => breached });

    expect(outcome.status).toBe("BREACH_REJECTED");
    expect(outcome.attempts).toBe(MAX_VERIFICATION_ATTEMPTS);
    expect(fetcher).toHaveBeenCalledTimes(MAX_VERIFICATION_ATTEMPTS);
  });
});

describe("failure modes never claim safety", () => {
  it("times out a range request that never answers", async () => {
    const fetcher = vi.fn((_prefix: string) => new Promise<{ suffixes: string }>(() => undefined));

    const outcome = await generateVerifiedPassword(fetcher, { timeoutMs: 30, maxAttempts: 2 });

    expect(outcome.status).toBe("UNAVAILABLE");
    expect(fetcher).toHaveBeenCalledTimes(1);
    const message = verificationErrorMessage(failure(outcome));
    expect(message).toContain("Could not verify");
    expect(message).toContain("did not respond");
    expect(message).toContain("No password was recommended");
    expect(message).not.toMatch(/is safe|verified successfully/);
  });

  it("times out through the real API client as well", async () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise<never>(() => undefined)));

    const outcome = await generateVerifiedPassword((prefix) => api.passwordRange(prefix), {
      timeoutMs: 30,
    });

    expect(outcome.status).toBe("UNAVAILABLE");
  });

  it("reports an unavailable service (HTTP 503) with the server's message", async () => {
    const fetcher: RangeFetcher = async () => {
      throw new ApiError(503, "CRIX is temporarily unavailable (HTTP 503). Please try again shortly.");
    };

    const outcome = await generateVerifiedPassword(fetcher);

    expect(outcome.status).toBe("UNAVAILABLE");
    const message = verificationErrorMessage(failure(outcome));
    expect(message).toContain("temporarily unavailable");
    expect(message).toContain("No password was recommended");
    expect(message).toContain("nothing here is claimed to be safe");
  });

  it("treats a proxy HTML 503 from the real endpoint as unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("<html>upstream diagnostic</html>", {
          status: 503,
          headers: { "Content-Type": "text/html" },
        }),
      ),
    );

    const outcome = await generateVerifiedPassword((prefix) => api.passwordRange(prefix));

    expect(outcome.status).toBe("UNAVAILABLE");
    expect(outcome).not.toHaveProperty("password");
    expect(verificationErrorMessage(failure(outcome))).toContain("No password was recommended");
  });

  it("treats a network-level failure as unavailable, not as a pass", async () => {
    const fetcher: RangeFetcher = async () => {
      throw new TypeError("fetch failed");
    };

    const outcome = await generateVerifiedPassword(fetcher);

    expect(outcome.status).toBe("UNAVAILABLE");
    expect(verificationErrorMessage(failure(outcome))).toContain("fetch failed");
  });

  it("rejects a malformed range response instead of recommending anything", async () => {
    const fetcher = async () =>
      ({ suffixes: undefined } as unknown as { suffixes: string });

    const outcome = await generateVerifiedPassword(fetcher);

    expect(outcome.status).toBe("MALFORMED");
    expect(outcome).not.toHaveProperty("password");
    const message = verificationErrorMessage(failure(outcome));
    expect(message).toContain("unexpected response");
    expect(message).toContain("No password was recommended");
  });

  it("classifies a JSON body without suffixes through the real API client", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ unexpected: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    const outcome = await generateVerifiedPassword((prefix) => api.passwordRange(prefix));

    expect(outcome.status).toBe("MALFORMED");
    expect(outcome).not.toHaveProperty("password");
  });
});

describe("copy and use controls", () => {
  it("copies the exact generated value to the clipboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });

    await expect(copyToClipboard("Abc123!xyz")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("Abc123!xyz");
  });

  it("fails quietly when the clipboard is unavailable or blocked", async () => {
    vi.stubGlobal("navigator", {});
    await expect(copyToClipboard("value")).resolves.toBe(false);

    vi.stubGlobal("navigator", {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) },
    });
    await expect(copyToClipboard("value")).resolves.toBe(false);
  });

  it("refuses to copy an empty value", async () => {
    const writeText = vi.fn();
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    await expect(copyToClipboard("")).resolves.toBe(false);
    expect(writeText).not.toHaveBeenCalled();
  });

  it("fills only the registration field on the register tab", () => {
    expect(passwordUsePlan("register")).toEqual({
      fillPassword: true,
      fillConfirm: false,
      copy: false,
      guideToReset: false,
    });
  });

  it("never replaces the login password — it copies and guides to reset", () => {
    const plan = passwordUsePlan("login");
    expect(plan.fillPassword).toBe(false);
    expect(plan.fillConfirm).toBe(false);
    expect(plan.copy).toBe(true);
    expect(plan.guideToReset).toBe(true);
  });

  it("lets the reset screen accept the generated value in both fields", () => {
    expect(passwordUsePlan("reset")).toEqual({
      fillPassword: true,
      fillConfirm: true,
      copy: false,
      guideToReset: false,
    });
  });
});

describe("password-reset behavior", () => {
  it("sends a generated replacement password to the reset-confirm endpoint", async () => {
    const generated = generatePassword();
    const fetcher = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "Password has been reset. Please log in again." }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetcher);

    await api.passwordResetConfirm("reset-token", generated);

    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toBe("/api/auth/password-reset/confirm");
    expect(JSON.parse(init.body)).toEqual({ token: "reset-token", new_password: generated });
    // The replacement goes to CRIX's own backend over HTTPS (that is how a
    // password is saved) — never to the breach-check endpoint.
    expect(url).not.toContain("password-check");
  });

  it("accepts a generated value within the form's length constraints", () => {
    // The reset form enforces minLength 10 / maxLength 128 on both fields.
    expect(GENERATED_PASSWORD_LENGTH).toBeGreaterThanOrEqual(10);
    expect(GENERATED_PASSWORD_LENGTH).toBeLessThanOrEqual(128);
  });
});

describe("breach warning parsing (server refusal → warning + generate button)", () => {
  it("extracts the count from the backend's registration refusal", () => {
    const backendMessage =
      "That password appears 126,414 times in known breach data. Please choose a different password.";
    expect(parseBreachWarningCount(backendMessage)).toBe(126414);
  });

  it("returns null for any non-breach message so nothing else becomes a warning", () => {
    expect(parseBreachWarningCount("Password must be at least 10 characters long.")).toBeNull();
    expect(parseBreachWarningCount("Password is too common.")).toBeNull();
    expect(parseBreachWarningCount(null)).toBeNull();
    expect(parseBreachWarningCount(undefined)).toBeNull();
    expect(parseBreachWarningCount("")).toBeNull();
  });
});
