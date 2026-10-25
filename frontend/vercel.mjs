// Keep browser calls same-origin: Vercel proxies /api to Render, so CRIX's
// secure httpOnly refresh cookie stays first-party and CSRF checks keep their
// intended browser behavior. CRIX_BACKEND_URL is a Vercel Config variable,
// never a browser-exposed secret.
function requiredBackendOrigin(rawValue) {
  const value = rawValue?.trim();
  if (!value) {
    throw new Error(
      "CRIX_BACKEND_URL is required and must be the HTTPS origin of the CRIX API."
    );
  }

  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(
      "CRIX_BACKEND_URL must be an HTTPS API origin, for example https://api.example.com."
    );
  }

  // A route or credential in this value could turn the rewrite into an
  // unintended proxy target. Accept only an origin (a trailing slash is fine).
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      "CRIX_BACKEND_URL must be an exact HTTPS API origin with no path, credentials, query, or fragment."
    );
  }

  return url.origin;
}

const backendOrigin = requiredBackendOrigin(process.env.CRIX_BACKEND_URL);
const apiDestination = `${backendOrigin}/api/:path*`;

export const config = {
  framework: "vite",
  buildCommand: "npm run build",
  outputDirectory: "dist",
  rewrites: [
    // Keep this concrete string in the generated config: every rewrite object
    // Vercel receives has the required `destination` property.
    { source: "/api/:path*", destination: apiDestination },
    // This documented catch-all is intentionally last so API traffic never
    // falls through to the SPA shell.
    { source: "/(.*)", destination: "/index.html" },
  ],
};
