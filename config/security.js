'use strict';

/**
 * config/security.js
 * -----------------------------------------------------------------------------
 * Centralized, secure-by-default configuration for the net-new Node.js/Express
 * application. This module is the SINGLE SOURCE OF TRUTH for every
 * security-relevant setting consumed by the app's middleware and transport
 * layers.
 *
 * Design principles (per AAP Sections 0.5.1, 0.6.3, 0.9.1):
 *   - Reads ONLY from `process.env` (documented in the git-ignored `.env`,
 *     described by the secret-free `.env.example`).
 *   - Contains NO secrets: no TLS key/cert material, tokens, passwords, or real
 *     hostnames — only environment-variable references and safe placeholders.
 *   - Secure-by-default fallbacks: the CORS allowlist is NEVER `*` (a wildcard
 *     can never enter the allowlist, even if misconfigured), HSTS is enabled,
 *     and rate limiting is bounded.
 *   - CommonJS module system (`require` / `module.exports`) — the root
 *     `package.json` intentionally does not set `"type": "module"`.
 *
 * Consumers (built against this exact shape):
 *   - src/middleware/security.js -> `contentSecurityPolicy`, `hsts`,
 *     `allowedOrigins`, `rateLimit` (helmet, cors, express-rate-limit).
 *   - src/server.js             -> `tls.keyPath`, `tls.certPath`, `port`
 *     (https.createServer bootstrap).
 *   - src/app.js                -> `jsonBodyLimit` (express.json({ limit })).
 *
 * Environment variable contract (names MUST match `.env.example` exactly):
 *   PORT, ALLOWED_ORIGINS, TLS_KEY_PATH, TLS_CERT_PATH,
 *   RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX
 * -----------------------------------------------------------------------------
 */

/**
 * Parse a comma-separated list of trusted CORS origins into a sanitized array.
 *
 * Behavior:
 *   - When `raw` is unset/empty, returns an empty array `[]`. This is the
 *     secure default: no cross-origin request is allowed until origins are
 *     explicitly configured (same-origin requests continue to work).
 *   - Otherwise splits on `,`, trims whitespace around each entry, and drops
 *     empty entries.
 *   - Defensively removes any `*` (wildcard) entry so an over-permissive origin
 *     can never enter the allowlist — mitigating OWASP A05 (Security
 *     Misconfiguration) and preventing an unsafe wildcard-with-credentials
 *     combination downstream.
 *
 * @param {string|undefined|null} raw - Raw `ALLOWED_ORIGINS` value.
 * @returns {string[]} Sanitized allowlist of explicit origins (never contains `*`).
 */
function parseAllowedOrigins(raw) {
  if (!raw) {
    // Secure default: deny-all cross-origin until explicitly configured.
    return [];
  }

  return raw
    .split(',')
    .map((origin) => origin.trim())
    // Keep only non-empty, explicit origins; never allow a wildcard.
    .filter((origin) => origin.length > 0 && origin !== '*');
}

/**
 * Parse a base-10 integer from an environment value, falling back to a safe
 * default when the value is missing, non-numeric, negative, zero, or otherwise
 * not a finite positive integer.
 *
 * This guards configuration numerics (port, rate-limit window, rate-limit max)
 * against `NaN`, negative, and garbage input so the application always boots
 * with sane, bounded values.
 *
 * @param {string|undefined|null} raw - Raw environment value.
 * @param {number} fallback - Safe default used when `raw` does not parse to a
 *   finite positive number.
 * @returns {number} The parsed positive integer, or `fallback`.
 */
function parseIntEnv(raw, fallback) {
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * The consolidated, secure-by-default security configuration object.
 * Consumers access these top-level keys directly (e.g. `config.allowedOrigins`,
 * `config.port`).
 *
 * @type {{
 *   port: number,
 *   allowedOrigins: string[],
 *   contentSecurityPolicy: { useDefaults: boolean },
 *   hsts: { maxAge: number, includeSubDomains: boolean, preload: boolean },
 *   rateLimit: { windowMs: number, limit: number, standardHeaders: string, legacyHeaders: boolean },
 *   tls: { keyPath: (string|undefined), certPath: (string|undefined) },
 *   jsonBodyLimit: string
 * }}
 */
module.exports = {
  // ---------------------------------------------------------------------------
  // Server / transport (R4 — HTTPS host)
  // Default 8443 matches `.env.example`. Consumed by src/server.js to bind the
  // https.createServer listener.
  // ---------------------------------------------------------------------------
  port: parseIntEnv(process.env.PORT, 8443),

  // ---------------------------------------------------------------------------
  // CORS allowlist (R7 — proper CORS policy)
  // An explicit array of trusted origins. NEVER `*`, and never combined with a
  // wildcard-with-credentials configuration downstream. Comma-separated in the
  // environment, e.g. "https://app.example.com,https://admin.example.com".
  // ---------------------------------------------------------------------------
  allowedOrigins: parseAllowedOrigins(process.env.ALLOWED_ORIGINS),

  // ---------------------------------------------------------------------------
  // Security headers (R1 / R6 — helmet)
  // `contentSecurityPolicy` is passed to helmet's contentSecurityPolicy option;
  // `useDefaults: true` applies helmet's hardened default CSP directives.
  // ---------------------------------------------------------------------------
  contentSecurityPolicy: { useDefaults: true },

  // ---------------------------------------------------------------------------
  // HTTP Strict Transport Security (R4 reinforcement)
  // Mapped by consumers to helmet's strictTransportSecurity (a.k.a. hsts)
  // option. Values are fixed per AAP Section 0.6.3:
  //   maxAge 63072000s (2 years), includeSubDomains, preload.
  // ---------------------------------------------------------------------------
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },

  // ---------------------------------------------------------------------------
  // Rate limiting (R3 — express-rate-limit)
  // Bounded fixed window. Defaults: 15-minute window (900000 ms) and 100
  // requests per window per client. `standardHeaders: 'draft-8'` emits the
  // standard `RateLimit-*` headers; `legacyHeaders: false` suppresses the
  // legacy `X-RateLimit-*` headers.
  // ---------------------------------------------------------------------------
  rateLimit: {
    windowMs: parseIntEnv(process.env.RATE_LIMIT_WINDOW_MS, 900000),
    limit: parseIntEnv(process.env.RATE_LIMIT_MAX, 100),
    standardHeaders: 'draft-8',
    legacyHeaders: false,
  },

  // ---------------------------------------------------------------------------
  // TLS material (R4 — HTTPS support)
  // PATHS ONLY. The actual key/certificate contents are provisioned out-of-band
  // and referenced by filesystem path; no key/cert material is ever committed.
  // When unset, these are `undefined` and src/server.js surfaces a clear error
  // rather than starting in cleartext.
  // ---------------------------------------------------------------------------
  tls: {
    keyPath: process.env.TLS_KEY_PATH,
    certPath: process.env.TLS_CERT_PATH,
  },

  // ---------------------------------------------------------------------------
  // Request body size cap (R2 — input validation hardening)
  // Consumed by src/app.js as `express.json({ limit: config.jsonBodyLimit })`
  // to reject oversized payloads before validation runs.
  // ---------------------------------------------------------------------------
  jsonBodyLimit: '10kb',
};
