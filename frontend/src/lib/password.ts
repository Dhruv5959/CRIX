// Password hygiene helpers that run ENTIRELY IN THE BROWSER.
//
// CRITICAL (Rule #4): a plaintext password must NEVER leave the client. We
// SHA-1 the password here, then ask the backend proxy only for the 5-character
// hash prefix. The full hash and the plaintext stay in this process.

/** SHA-1 hex digest of the given text, using the Web Crypto API. */
export async function sha1Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-1", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export interface PasswordCheckResult {
  prefix: string;
  suffix: string;
  pwned: boolean;
  count: number;
}

/**
 * Check a password against the HIBP Pwned Passwords range API via the backend
 * k-anonymity proxy. Returns whether it was found and the observed count.
 */
export async function checkPasswordPwned(
  password: string,
  rangeFetcher: (prefix: string) => Promise<{ suffixes: string }>,
): Promise<PasswordCheckResult> {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const { suffixes } = await rangeFetcher(prefix);
  let count = 0;
  let pwned = false;
  for (const line of suffixes.split("\n")) {
    const [suf, cnt] = line.trim().split(":");
    if (!suf) continue;
    if (suf.toUpperCase() === suffix) {
      pwned = true;
      count = parseInt(cnt, 10) || 0;
      break;
    }
  }
  return { prefix, suffix, pwned, count };
}

/**
 * Compare two passwords for reuse WITHOUT sending either anywhere. Only the
 * boolean result is ever transmitted to the server.
 */
export async function passwordsMatch(a: string, b: string): Promise<boolean> {
  return (await sha1Hex(a)) === (await sha1Hex(b));
}