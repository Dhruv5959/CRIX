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
  });

  it("keeps cookie credentials, access tokens, and CSRF on successful auth requests", async () => {
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
