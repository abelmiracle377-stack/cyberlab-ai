export function isPublicPath(path) {
  return path === "/login"
    || path === "/pricing"
    || path === "/admin/login"
    || path.startsWith("/auth/callback")
    || path === "/api/paystack/webhook";
}

export function authConfigurationDecision(path, hasUrl, hasKey) {
  if (hasUrl && hasKey) return "configured";
  return isPublicPath(path) ? "allow-public" : "unavailable";
}
