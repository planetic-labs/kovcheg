export function contentSecurityPolicy(nonce: string, isDevelopment: boolean): string {
  const scriptDevelopmentFallback = isDevelopment ? " 'unsafe-eval'" : '';
  const stylePolicy = isDevelopment ? "'self' 'unsafe-inline'" : `'self' 'nonce-${nonce}'`;

  return [
    "default-src 'self'",
    "base-uri 'self'",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "img-src 'self' data: blob:",
    "object-src 'none'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${scriptDevelopmentFallback}`,
    `style-src ${stylePolicy}`,
  ].join('; ');
}
