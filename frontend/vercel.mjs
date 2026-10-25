// Keep browser calls same-origin: Vercel proxies /api to Render, so CRIX's
// secure httpOnly refresh cookie stays first-party and CSRF checks keep their
// intended browser behavior. CRIX_BACKEND_URL is a Vercel Config variable,
// never a browser-exposed secret.
const backendUrl = process.env.CRIX_BACKEND_URL?.replace(/\/+$/, "");

if (!backendUrl || !/^https:\/\//.test(backendUrl)) {
  throw new Error("CRIX_BACKEND_URL must be an HTTPS Render API origin.");
}

export const config = {
  framework: "vite",
  buildCommand: "npm run build",
  outputDirectory: "dist",
  rewrites: [
    { source: "/api/:path*", destination: `${backendUrl}/api/:path*` },
    { source: "/:path*", destination: "/index.html" },
  ],
};
