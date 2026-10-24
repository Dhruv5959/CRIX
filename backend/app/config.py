"""Application configuration loaded from environment variables.

All secrets come from the environment (Rule §14). The defaults are obvious
dev-only placeholders so a fresh clone can boot; production MUST override them.
"""
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# pydantic-settings resolves a *relative* ``env_file`` against the process's
# current working directory. The API is normally launched from ``backend/``,
# while ``.env.example`` lives at the repo root — so a plain ``".env"`` would
# silently ignore the file the README tells you to create. Anchor both
# locations explicitly so configuration no longer depends on where you started
# the server from.
_BACKEND_DIR = Path(__file__).resolve().parents[1]  # .../backend
_PROJECT_ROOT = _BACKEND_DIR.parent  # .../ (repo root)

# Later entries override earlier ones, so the repo-root `.env` — the location
# `.env.example` documents and the one the README creates — wins if both exist.
ENV_FILES = (str(_BACKEND_DIR / ".env"), str(_PROJECT_ROOT / ".env"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CRIX_",
        env_file=ENV_FILES,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: str = "development"
    database_url: str = "sqlite:///./crix.db"

    # Auth
    jwt_secret: str = "dev-only-insecure-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    bcrypt_rounds: int = 12

    # CORS. `NoDecode` hands the raw string to `_split_origins` instead of
    # requiring JSON — without it, `.env.example`'s plain comma-separated value
    # makes Settings() raise a JSONDecodeError at import time.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )

    # HIBP — used for the (keyless) Pwned Passwords range check, and optionally
    # for the email breach lookup when a key is present.
    hibp_api_key: str = ""

    # Email breach lookup provider (§3.A).
    #   "auto"        -> HIBP when CRIX_HIBP_API_KEY is set, else XposedOrNot
    #   "xposedornot" -> always the free XposedOrNot community API (no key)
    #   "hibp"        -> always HIBP (also reports which data classes leaked)
    # The resolved provider is reported by /api/health and recorded on every
    # breach event, so the UI never has to guess where a result came from.
    # Modelled as a Literal so a typo in .env fails loudly at startup instead of
    # silently falling back to a different provider.
    breach_email_provider: Literal["auto", "xposedornot", "hibp"] = "auto"

    # XposedOrNot. The published free-tier limits for GET /v1/check-email/{email}
    # are 2 requests/second and 25/hour per IP; CRIX throttles its own outbound
    # calls to whatever is configured here and backs off after an HTTP 429.
    xposedornot_base_url: str = "https://api.xposedornot.com"
    xposedornot_timeout_seconds: float = 10.0
    xposedornot_requests_per_second: int = 2
    xposedornot_requests_per_hour: int = 25

    # Rate limiting (requests per minute)
    login_rate_limit_per_minute: int = 5
    password_check_rate_limit_per_minute: int = 30
    # Inbound cap on the breach-check endpoint: protects the shared provider
    # quota from one client hammering the API.
    breach_check_rate_limit_per_minute: int = 10
    # Unauthenticated endpoints that are expensive (bcrypt) or email-sending.
    register_rate_limit_per_minute: int = 20
    password_reset_rate_limit_per_minute: int = 10
    invite_accept_rate_limit_per_minute: int = 20

    # Public base URL the backend builds emailed links from (password reset,
    # invitations). Never bake a hardcoded localhost link into an email.
    public_base_url: str = "http://localhost:5173"

    # Only honor X-Forwarded-For when the app is actually deployed behind a
    # trusted reverse proxy. Otherwise a client could spoof the header to
    # rotate rate-limit buckets or forge recorded IPs.
    trust_proxy_headers: bool = False

    # --- SMTP (production email transport) ------------------------------------
    # Dev writes .eml files to backend/artifacts/outbox/. Production must
    # configure a real SMTP host or refuse to start (assert_production_safe):
    # password reset and invitations are dead ends without working email.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = "no-reply@crix.local"
    smtp_start_tls: bool = True

    # --- Risk model (Phase 6b) ------------------------------------------------
    # The DependencyExposure term adds the org dependency graph's documented
    # blast radius to the contextual score (docs/RISK_MODEL.md §1.3). Default
    # ON; set to false to ABLATE the term (evaluation ablation runs, and any
    # operator who wants the pure Phase 4/6b-without-graph formula). The status
    # is recorded on every score as DISABLED, so an ablated run is never
    # mistaken for a run that found no exposure.
    risk_dependency_exposure_enabled: bool = True

    # --- OAuth providers (live account connections) — FROZEN (§1.4) ---
    # CRIX-SMB does NOT connect to third-party providers. The connectors stay in
    # the codebase behind this flag, but it defaults to OFF *in code* (not just
    # in .env): no provider app is registered, no credentials are configured,
    # and the connector surface is absent from the UI and the demo. The reason
    # is documented: these platforms do not expose breach, MFA, or
    # connected-app data to third-party apps, so a connection proves nothing
    # about security. Instagram was removed entirely (no official API for
    # personal accounts since 2024-12-04).
    oauth_connectors_enabled: bool = False
    google_client_id: str = ""
    google_client_secret: str = ""
    linkedin_client_id: str = ""
    linkedin_client_secret: str = ""
    # Where the backend sends the browser after the OAuth callback completes.
    oauth_frontend_redirect: str = "http://localhost:5173/connections"
    # Base URL the provider redirects back to; must match the registered URI.
    oauth_redirect_base: str = "http://127.0.0.1:8000/api/oauth"
    # Fernet key for encrypting stored OAuth tokens at rest. If unset it is
    # derived from jwt_secret (dev convenience) and a warning-worthy default.
    token_encryption_key: str = ""
    # Allow the clearly-labeled FIXTURE connector for local demos without real
    # provider credentials. Never used to masquerade as REAL. Only has any
    # effect when oauth_connectors_enabled is on.
    allow_fixture_connectors: bool = True

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Accept either a JSON array or a plain comma-separated list.

        Both spellings are documented, so neither may crash config loading.
        """
        if not isinstance(value, str):
            return value
        text = value.strip()
        if text.startswith("["):
            try:
                import json

                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        return [item.strip() for item in text.split(",") if item.strip()]

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"production", "prod"}

    def assert_production_safe(self) -> None:
        """Fail loudly if we'd run in prod with dev secrets (Rule §14)."""
        if self.is_production:
            if self.jwt_secret == "dev-only-insecure-change-me":
                raise RuntimeError(
                    "CRIX_JWT_SECRET must be set to a strong random value in production."
                )
            if "*" in self.cors_origins:
                raise RuntimeError("CORS wildcard is not allowed in production.")
            if not self.token_encryption_key:
                raise RuntimeError(
                    "CRIX_TOKEN_ENCRYPTION_KEY must be set in production (Fernet key)."
                )
            if not self.smtp_host:
                raise RuntimeError(
                    "CRIX_SMTP_HOST must be set in production: password reset and "
                    "invitations are unusable without it."
                )
            if self.public_base_url.startswith("http://localhost"):
                raise RuntimeError(
                    "CRIX_PUBLIC_BASE_URL must be a real public URL in production; "
                    "emailed reset/invite links would be dead."
                )
            if self.oauth_connectors_enabled and not (
                self.google_client_id or self.linkedin_client_id
            ):
                # Not fatal: the product runs without OAuth. Surfaced so ops knows.
                pass

    def oauth_client_secret(self, provider: str) -> str:
        return {
            "google": self.google_client_secret,
            "linkedin": self.linkedin_client_secret,
        }.get(provider, "")

    def oauth_client_id(self, provider: str) -> str:
        return {
            "google": self.google_client_id,
            "linkedin": self.linkedin_client_id,
        }.get(provider, "")


@lru_cache
def get_settings() -> Settings:
    return Settings()