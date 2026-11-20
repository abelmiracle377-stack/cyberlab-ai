export function isPublicPath(path: string): boolean;
export function authConfigurationDecision(
  path: string,
  hasUrl: boolean,
  hasKey: boolean
): "configured" | "allow-public" | "unavailable";
