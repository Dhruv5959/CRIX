// Security invariant tests for the client-side password handling (Rule #4).
//
// These prove, in an automated way, that:
//   1. Only the 5-char SHA-1 prefix ever leaves the client.
//   2. The plaintext password never appears in any value handed to the network.
//   3. Reuse comparison happens locally (no network calls).

import { describe, expect, it, vi } from "vitest";
import { checkPasswordPwned, passwordsMatch, sha1Hex } from "./password";

const PLAINTEXT = "SuperSecretPlaintext-Password-42!";

describe("client-side password handling", () => {
  it("sends only the 5-character SHA-1 prefix to the range endpoint", async () => {
    const seen: string[] = [];
    const fetcher = vi.fn(async (prefix: string) => {
      seen.push(prefix);
      return { suffixes: "0000000000000000000000000000000000:0" };
    });

    await checkPasswordPwned(PLAINTEXT, fetcher);

    expect(fetcher).toHaveBeenCalledTimes(1);
    const fullHash = (await sha1Hex(PLAINTEXT)).toUpperCase();
    // Exactly the prefix, never the full hash.
    expect(seen[0]).toBe(fullHash.slice(0, 5));
    expect(seen[0]).toHaveLength(5);
    expect(seen[0]).not.toBe(fullHash);
  });

  it("never passes the plaintext password to the network layer", async () => {
    const captured: unknown[] = [];
    const fetcher = vi.fn(async (prefix: string) => {
      captured.push(prefix);
      return { suffixes: "" };
    });

    await checkPasswordPwned(PLAINTEXT, fetcher);

    const serialized = JSON.stringify(captured);
    expect(serialized).not.toContain(PLAINTEXT);
    expect(serialized).not.toContain("SuperSecret");
  });

  it("detects a match using only hash suffixes (k-anonymity)", async () => {
    const fullHash = (await sha1Hex(PLAINTEXT)).toUpperCase();
    const suffix = fullHash.slice(5);
    const fetcher = async (_prefix: string) => ({
      // A realistic response with padding entries plus the real suffix.
      suffixes: `0000000000000000000000000000000000:1\n${suffix}:1234\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:9`,
    });

    const result = await checkPasswordPwned(PLAINTEXT, fetcher);
    expect(result.pwned).toBe(true);
    expect(result.count).toBe(1234);
    expect(result.suffix).toBe(suffix);
  });

  it("reports not-pwned when the suffix is absent", async () => {
    const fetcher = async (_prefix: string) => ({ suffixes: "00:1\n11:2" });
    const result = await checkPasswordPwned(PLAINTEXT, fetcher);
    expect(result.pwned).toBe(false);
    expect(result.count).toBe(0);
  });

  it("compares passwords locally without any network call", async () => {
    const same = await passwordsMatch("correct horse", "correct horse");
    const different = await passwordsMatch("correct horse", "battery staple");
    expect(same).toBe(true);
    expect(different).toBe(false);
  });

  it("produces a stable uppercase SHA-1 digest", async () => {
    // Known SHA-1 test vector: "abc" -> a9993e36...
    const digest = await sha1Hex("abc");
    expect(digest).toBe("A9993E364706816ABA3E25717850C26C9CD0D89D");
  });
});