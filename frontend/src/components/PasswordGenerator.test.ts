// Rendering tests for the "Generate a safe password" UI (spec §5: copy/use
// controls and password-reset behavior).
//
// The app has no DOM test library and none is being added (same convention as
// breach.test.ts), so components render to markup with react-dom/server. All
// interaction logic lives in @/lib/passwordGenerator and is unit-tested there;
// these tests pin the controls, their intent-specific copy, and the invariant
// that nothing here submits a form or claims safety it does not have.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import ResetPasswordPage from "../pages/ResetPasswordPage";
import { PasswordBreachWarning, PasswordGenerator, PasswordGeneratorView } from "./PasswordGenerator";
import { generatePassword, type VerificationOutcome } from "@/lib/passwordGenerator";

const VERIFIED: Extract<VerificationOutcome, { status: "VERIFIED" }> = {
  status: "VERIFIED",
  password: generatePassword(),
  attempts: 1,
};

interface ViewOverrides {
  phase?: "working" | "verified" | "error";
  outcome?: VerificationOutcome | null;
  revealing?: boolean;
  copied?: boolean;
  surface?: "register" | "login" | "reset";
}

function renderView(overrides: ViewOverrides = {}): string {
  const props = {
    phase: overrides.phase ?? "verified",
    outcome: overrides.outcome ?? VERIFIED,
    revealing: overrides.revealing ?? false,
    copied: overrides.copied ?? false,
    surface: overrides.surface ?? "register",
    onGenerateAnother: () => undefined,
    onToggleReveal: () => undefined,
    onCopy: () => undefined,
    onUse: () => undefined,
  };
  return renderToStaticMarkup(createElement(PasswordGeneratorView, props));
}

function renderWarning(count: number, surface: "login" | "register"): string {
  return renderToStaticMarkup(
    createElement(PasswordBreachWarning, { count, surface, onGenerate: () => undefined }),
  );
}

function renderReset(url: string): string {
  return renderToStaticMarkup(
    createElement(MemoryRouter, { initialEntries: [url] }, createElement(ResetPasswordPage)),
  );
}

describe("breach warning on the auth screen", () => {
  it("shows the breach count and the generate button directly below the warning", () => {
    const html = renderWarning(126414, "register");

    expect(html).toContain(`${(126414).toLocaleString()} times in known breach data`);
    const alertAt = html.indexOf('role="alert"');
    const alertEnd = html.indexOf("</div>", alertAt);
    const buttonAt = html.indexOf("Generate a safe password");
    expect(alertAt).toBeGreaterThanOrEqual(0);
    expect(buttonAt).toBeGreaterThan(alertEnd);
    // Nothing but markup sits between the warning and its button — they read
    // as one block.
    const between = html.slice(alertEnd, buttonAt);
    expect(between.replace(/<[^>]*>/g, "").trim()).toBe("");
    expect(html).toContain('data-testid="generate-safe-password"');
  });

  it("keeps the warning non-blocking: the trigger is a button, never a submit", () => {
    const html = renderWarning(126414, "login");
    const buttonAt = html.indexOf("<button");
    const buttonTag = html.slice(buttonAt, html.indexOf(">", buttonAt) + 1);
    expect(buttonAt).toBeGreaterThanOrEqual(0);
    expect(buttonTag).toContain('type="button"');
    // Non-blocking: no control here is ever disabled.
    expect(html).not.toMatch(/\sdisabled(="")?>/);
  });

  it("guides a compromised login password to the reset flow instead of replacing it", () => {
    const html = renderWarning(126414, "login");
    expect(html).toContain("do not keep it");
    expect(html).toContain("saved to your account");

    const register = renderWarning(126414, "register");
    expect(register).toContain("generate a password that is verified");
    expect(register).not.toContain("saved to your account");
  });
});

describe("password generator controls", () => {
  it("offers Generate another, Show/Hide, Copy password and Use this password", () => {
    const html = renderView();

    for (const label of ["Generate another", "Copy password", "Use this password", "Show"]) {
      expect(html).toContain(label);
    }
    for (const testid of [
      "generate-another",
      "toggle-reveal",
      "copy-password",
      "use-password",
      "generated-password",
    ]) {
      expect(html).toContain(`data-testid="${testid}"`);
    }
    // Every control is type="button": the panel lives inside a <form> and must
    // never submit it.
    const buttons = html.match(/<button/g) ?? [];
    const typedButtons = html.match(/<button[^>]*type="button"/g) ?? [];
    expect(buttons.length).toBeGreaterThanOrEqual(4);
    expect(typedButtons.length).toBe(buttons.length);
  });

  it("masks the generated password until Show is pressed", () => {
    const masked = renderView({ revealing: false });
    expect(masked).not.toContain(VERIFIED.password);
    expect(masked).toContain("•".repeat(VERIFIED.password.length));

    const revealed = renderView({ revealing: true });
    expect(revealed).toContain(VERIFIED.password);
    expect(revealed).toContain("Hide");
  });

  it("shows the verified state with its honesty caveat", () => {
    const html = renderView();
    expect(html).toContain("Verified — 0 matches in breach data");
    expect(html).toContain("not proof of safety");
    expect(html).toContain("cryptographic random source");
  });

  it("flips Copy password to Copied after a copy", () => {
    expect(renderView({ copied: true })).toContain("Copied");
    expect(renderView({ copied: false })).toContain("Copy password");
  });

  it("tells the login surface that using it does not change the password", () => {
    expect(renderView({ surface: "login" })).toContain("does not change your password");
    expect(renderView({ surface: "register" })).not.toContain("does not change your password");
  });

  it("renders the container in its initial verifying state without using anything", () => {
    const onUse = vi.fn();
    const html = renderToStaticMarkup(
      createElement(PasswordGenerator, { surface: "register", onUse }),
    );

    expect(html).toContain('data-testid="password-generator-working"');
    expect(html).toContain("5-character SHA-1 hash prefix");
    expect(html).not.toContain("Use this password");
    expect(onUse).not.toHaveBeenCalled();
  });
});

describe("verification failures render as errors, never as safety", () => {
  const failures: Array<[string, VerificationOutcome]> = [
    [
      "unavailable",
      { status: "UNAVAILABLE", attempts: 1, reason: "CRIX is temporarily unavailable (HTTP 503)." },
    ],
    ["malformed", { status: "MALFORMED", attempts: 1, reason: "no suffix list" }],
    ["retries exhausted", { status: "BREACH_REJECTED", attempts: 5, reason: "all found" }],
  ];

  it.each(failures)("shows a clear %s error with no safety claim", (_name, outcome) => {
    const html = renderView({ phase: "error", outcome });

    expect(html).toContain('data-testid="password-generator-error"');
    expect(html).toContain("No password was recommended");
    expect(html).toContain("Try again");
    // No verified badge, no zero-match claim, no controls that imply a
    // recommendation exists.
    expect(html).not.toContain("0 matches in breach data");
    expect(html).not.toContain("Use this password");
    expect(html).not.toContain("Copy password");
    expect(html).not.toContain("is safe");
  });

  it("never renders the candidate alongside an error", () => {
    const html = renderView({
      phase: "error",
      outcome: { status: "UNAVAILABLE", attempts: 1, reason: "timeout" },
    });
    expect(html).not.toContain(VERIFIED.password);
  });
});

describe("password-reset behavior", () => {
  it("offers the generator on the reset screen", () => {
    const html = renderReset("/reset-password?token=single-use-token");

    expect(html).toContain('data-testid="generate-safe-password"');
    expect(html).toContain("Generate a safe password");
    expect(html).toContain("Set new password");
  });

  it("accepts a generated 20-character value in both fields", () => {
    const html = renderReset("/reset-password?token=single-use-token").toLowerCase();

    expect(html.match(/minlength="10"/g)).toHaveLength(2);
    expect(html.match(/maxlength="128"/g)).toHaveLength(2);
    expect(generatePassword()).toHaveLength(20);
  });

  it("does not offer the generator without a token — nothing can be saved", () => {
    const html = renderReset("/reset-password");

    expect(html).toContain("missing its token");
    expect(html).not.toContain("Generate a safe password");
    expect(html).not.toContain('data-testid="password-generator"');
  });
});
