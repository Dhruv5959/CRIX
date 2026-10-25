import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, setTokens } from "./api";

afterEach(() => {
  setTokens(null, null);
  vi.unstubAllGlobals();
});

function reply(body: string | null, status: number, contentType = "text/plain") {
  const fetcher = vi.fn().mockResolvedValue(new Response(body, {
    status,
    headers: { "Content-Type": contentType },
  }));
  vi.stubGlobal("fetch", fetcher);
  return fetcher;
}

describe("API response handling", () => {
  it("reports the screenshot's plain-text 404 as an API routing error", async () => {
    const fetcher = reply("Not Found", 404);

    const error = await api.login("employee@example.invalid", "test-crix-password").catch(
      (failure: unknown) => failure,
    );
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 404, message: expect.stringContaining("API endpoint") });
    expect(fetcher).toHaveBeenCalledWith("/api/auth/login", expect.objectContaining({
      method: "POST",
      credentials: "include",
    }));
  });

  it.each([502, 503, 504])("handles an HTML proxy failure with HTTP %s safely", async (status) => {
    reply("<html>upstream diagnostic that must not appear in the UI</html>", status, "text/html");

    await expect(api.health()).rejects.toMatchObject({
      status,
      message: `CRIX is temporarily unavailable (HTTP ${status}). Please try again shortly.`,
    });
  });

  it.each([
    ["<html>SPA fallback</html>", "text/html"],
    ["{broken-json", "application/json"],
    ["", "application/json"],
  ])("rejects an invalid successful response (%s)", async (body, contentType) => {
    reply(body, 200, contentType);

    await expect(api.login("employee@example.invalid", "test-crix-password")).rejects.toMatchObject({
      status: 200,
      message: "CRIX returned an unexpected response. Please try again or contact your administrator.",
    });
  });

  it("preserves the backend's JSON authentication error", async () => {
    reply(JSON.stringify({ detail: "Invalid email or password." }), 401, "application/json");

    await expect(api.login("employee@example.invalid", "test-crix-password")).rejects.toMatchObject({
      status: 401,
      message: "Invalid email or password.",
    });
  });

  it("uses a safe HTTP error for a JSON response with no string detail", async () => {
    reply(JSON.stringify({ detail: [{ msg: "private validation diagnostic" }] }), 422, "application/json");

    await expect(api.health()).rejects.toMatchObject({
      status: 422,
      message: "Request failed (HTTP 422). Please try again.",
    });
  });

  it("continues to accept a bodyless 204", async () => {
    reply(null, 204);

    await expect(api.deleteAccount("account-id")).resolves.toBeUndefined();
  });  it("keeps cookie credentials, access tokens, and CSRF on successful auth requests", async () => {
    const tokens = { access_token: "test-access-token", csrf_token: "test-csrf-token" };
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(tokens)))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "test-user" })))
      .mockResolvedValueOnce(new Response(JSON.stringify(tokens)));
    vi.stubGlobal("fetch", fetcher);

    await expect(api.login("employee@example.invalid", "test-crix-password")).resolves.toEqual(tokens);
    await api.me();
    await api.refresh();

    const [loginPath, loginOptions] = fetcher.mock.calls[0];
    expect(loginPath).toBe("/api/auth/login");
    expect(loginOptions.credentials).toBe("include");
    expect(loginOptions.headers.get("Authorization")).toBeNull();
    expect(loginOptions.headers.get("Content-Type")).toBe("application/json");
    expect(fetcher.mock.calls[1][1].headers.get("Authorization")).toBe("Bearer test-access-token");
    const [refreshPath, refreshOptions] = fetcher.mock.calls[2];
    expect(refreshPath).toBe("/api/auth/refresh");
    expect(refreshOptions.credentials).toBe("include");
    expect(refreshOptions.headers.get("X-CSRF-Token")).toBe("test-csrf-token");
  });
});

// Regression guards for the two session bugs found in production: a page
// reload lost the in-memory CSRF token (silent refresh 403 → forced logout),
// and the 15-minute access token expired with nothing to renew it (every page
// started failing until a reload — which also logged the user out).
describe("session continuity", () => {
  const json = { "Content-Type": "application/json" };

  function replyQueue(bodies: Array<{ body: string; status: number }>) {
    const fetcher = vi.fn().mockImplementation((_url: string, _init: RequestInit) => {
      const next = bodies.shift();
      if (!next) return Promise.reject(new Error("unexpected extra request"));
      return Promise.resolve(
        new Response(next.body, { status: next.status, headers: json }),
      );
    });
    vi.stubGlobal("fetch", fetcher);
    return fetcher;
  }

  it("rebuilds the CSRF header from the cookie after a page reload", async () => {
    const fetcher = replyQueue([
      { body: JSON.stringify({ access_token: "t", csrf_token: "c" }), status: 200 },
    ]);
    // Post-reload: nothing in memory, only the server's JS-readable cookie.
    vi.stubGlobal("document", { cookie: "theme=dark; crix_csrf=cookie-csrf-value" });

    await api.refresh();

    expect(fetcher).toHaveBeenCalledTimes(1);
    const [path, init] = fetcher.mock.calls[0];
    expect(path).toBe("/api/auth/refresh");
    expect(init.headers.get("X-CSRF-Token")).toBe("cookie-csrf-value");
  });

  it("prefers the in-memory CSRF token over the cookie", async () => {
    setTokens(null, "memory-csrf");
    const fetcher = replyQueue([
      { body: JSON.stringify({ access_token: "t", csrf_token: "c" }), status: 200 },
    ]);
    vi.stubGlobal("document", { cookie: "crix_csrf=cookie-csrf" });

    await api.refresh();

    expect(fetcher.mock.calls[0][1].headers.get("X-CSRF-Token")).toBe("memory-csrf");
  });

  it("refreshes once and replays when the access token has expired", async () => {
    setTokens("expired-access", "csrf-1");
    const fetcher = replyQueue([
      { body: JSON.stringify({ detail: "Token expired." }), status: 401 },
      { body: JSON.stringify({ access_token: "fresh-access", csrf_token: "csrf-2" }), status: 200 },
      { body: JSON.stringify([{ account_id: "acct-1" }]), status: 200 },
    ]);

    await expect(api.listAccounts()).resolves.toEqual([{ account_id: "acct-1" }]);

    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(fetcher.mock.calls[0][0]).toBe("/api/accounts");
    expect(fetcher.mock.calls[1][0]).toBe("/api/auth/refresh");
    expect(fetcher.mock.calls[2][0]).toBe("/api/accounts");
    expect(fetcher.mock.calls[0][1].headers.get("Authorization")).toBe("Bearer expired-access");
    expect(fetcher.mock.calls[2][1].headers.get("Authorization")).toBe("Bearer fresh-access");
  });

  it("never attempts a refresh for unauthenticated failures (login stays a plain 401)", async () => {
    const fetcher = replyQueue([
      { body: JSON.stringify({ detail: "Invalid email or password." }), status: 401 },
    ]);

    await expect(api.login("employee@example.invalid", "test-crix-password")).rejects.toMatchObject({
      status: 401,
      message: "Invalid email or password.",
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("surfaces the original 401 when the refresh itself fails", async () => {
    setTokens("stale-access", "csrf");
    const fetcher = replyQueue([
      { body: JSON.stringify({ detail: "Access token expired." }), status: 401 },
      { body: JSON.stringify({ detail: "No refresh token." }), status: 401 },
    ]);

    await expect(api.listAccounts()).rejects.toMatchObject({
      status: 401,
      message: "Access token expired.",
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("coalesces concurrent 401s into a single refresh rotation", async () => {
    setTokens("stale-access", "csrf");
    let refreshCalls = 0;
    let accountCalls = 0;
    const fetcher = vi.fn().mockImplementation((url: string, _init: RequestInit) => {
      if (url === "/api/auth/refresh") {
        refreshCalls += 1;
        return Promise.resolve(
          new Response(JSON.stringify({ access_token: "fresh", csrf_token: "c2" }), {
            status: 200,
            headers: json,
          }),
        );
      }
      accountCalls += 1;
      if (accountCalls <= 2) {
        return Promise.resolve(
          new Response(JSON.stringify({ detail: "expired" }), { status: 401, headers: json }),
        );
      }
      return Promise.resolve(new Response(JSON.stringify([]), { status: 200, headers: json }));
    });
    vi.stubGlobal("fetch", fetcher);

    const [first, second] = await Promise.all([api.listAccounts(), api.listAccounts()]);

    expect(first).toEqual([]);
    expect(second).toEqual([]);
    // Presenting the same refresh token twice would trip reuse detection and
    // revoke the session — exactly one rotation must happen.
    expect(refreshCalls).toBe(1);
    expect(fetcher).toHaveBeenCalledTimes(5);
  });
});
