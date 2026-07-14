'use strict';

/**
 * src/middleware/security.js
 * -----------------------------------------------------------------------------
 * Centralized, secure-by-default security middleware for the net-new
 * Node.js/Express application.
 *
 * This module is the SINGLE PLACE where the three request-pipeline security
 * middleware are constructed. It only *wires* configuration values into
 * middleware instances — it defines no policy numbers of its own. Every policy
 * value is read from `config/security.js`, the single source of truth.
 *
 *   - helmet             -> hardened HTTP response headers          (R1 / R6)
 *   - cors               -> cross-origin policy (explicit allowlist)(R7)
 *   - express-rate-limit -> per-client request throttling           (R3)
 *
 * Public API (authoritative contract consumed by src/app.js):
 *   module.exports = { helmetMiddleware, corsMiddleware, rateLimiter }
 * Each value is a middleware FUNCTION produced by calling the respective
 * package. The keys, spelling, and count are fixed — src/app.js destructures
 * exactly these three names, so no extra exports may be added or renamed.
 *
 * Security invariants enforced here:
 *   - Secure-by-default: the CORS origin is the `config.allowedOrigins` array
 *     (default `[]`, NEVER `*`); a wildcard origin is never combined with
 *     credentials.
 *   - HSTS is enabled via helmet's v8 canonical `strictTransportSecurity`
 *     option, sourced from `config.hsts`.
 *   - Rate limiting is bounded (window + max) via `config.rateLimit`.
 *   - No secrets: this file contains no keys, certs, tokens, hostnames, or
 *     literal policy values — only `require`s and middleware construction.
 *
 * CommonJS module system (`require` / `module.exports`): the root
 * `package.json` intentionally does not set `"type": "module"`.
 * -----------------------------------------------------------------------------
 */

// External security packages (declared and pinned in the root package.json:
// helmet ^8.3.0, cors ^2.8.6, express-rate-limit ^8.5.2). Resolved from
// node_modules at runtime after `npm install` / `npm ci`.
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// Single source of truth for all security policy values. The `../../` prefix
// climbs from `src/middleware/` up to the repository root, then into `config/`.
const config = require('../../config/security');

/**
 * R1 / R6 — Hardened HTTP response headers (helmet).
 *
 * `helmet()` returns a single middleware that sets roughly a dozen hardened
 * response headers. We explicitly wire two policy-bearing options from config:
 *
 *   - contentSecurityPolicy: `config.contentSecurityPolicy` (`{ useDefaults:
 *     true }`) applies helmet's hardened default Content-Security-Policy
 *     directives, mitigating cross-site scripting and mixed-content risks.
 *   - strictTransportSecurity: `config.hsts` enables HTTP Strict Transport
 *     Security (the v8 canonical key; the legacy `hsts` alias also works but
 *     `strictTransportSecurity` is preferred for the pinned ^8.3.0). This
 *     instructs conformant browsers to use HTTPS exclusively.
 *
 * All remaining hardened defaults are intentionally left enabled: helmet also
 * emits `X-Content-Type-Options: nosniff`, an `X-Frame-Options` /
 * frame-ancestors control, a `Referrer-Policy`, and REMOVES the `X-Powered-By`
 * header. These defaults satisfy the security header regression tests and are
 * deliberately not disabled here.
 *
 * @type {import('express').RequestHandler}
 */
const helmetMiddleware = helmet({
  contentSecurityPolicy: config.contentSecurityPolicy,
  strictTransportSecurity: config.hsts,
});

/**
 * R7 — Cross-Origin Resource Sharing policy (cors).
 *
 * The `origin` is bound to `config.allowedOrigins`, an explicit array of
 * trusted origins whose secure default is `[]` (deny-all cross-origin until
 * origins are configured). The allowlist can NEVER contain `*` — the config
 * layer strips any wildcard — so an over-permissive origin cannot leak in, and
 * a wildcard is never paired with `credentials: true` (an unsafe combination
 * that browsers reject and that would defeat the allowlist). `credentials:
 * true` permits cookies/authorization headers for the explicitly trusted
 * origins only.
 *
 * Note: the `cors` package sets response headers only; actual cross-origin
 * enforcement is performed by the browser. A disallowed origin is simply not
 * reflected in `Access-Control-Allow-Origin`.
 *
 * @type {import('express').RequestHandler}
 */
const corsMiddleware = cors({
  origin: config.allowedOrigins,
  credentials: true,
});

/**
 * R3 — Per-client request throttling (express-rate-limit).
 *
 * The entire `config.rateLimit` object is passed straight through. It carries
 * the bounded window (`windowMs`), the per-window request cap (`limit`),
 * `standardHeaders: 'draft-8'` (emitting the standard `RateLimit-*` headers),
 * and `legacyHeaders: false` (suppressing the deprecated `X-RateLimit-*`
 * headers). Once a client exceeds `limit` within `windowMs`, the middleware
 * responds with HTTP `429 Too Many Requests`, mitigating brute-force,
 * credential-stuffing, and denial-of-service abuse.
 *
 * @type {import('express').RequestHandler}
 */
const rateLimiter = rateLimit(config.rateLimit);

// Authoritative export contract — EXACTLY these three middleware functions.
// src/app.js destructures `{ helmetMiddleware, corsMiddleware, rateLimiter }`;
// do not add, remove, or rename keys.
module.exports = { helmetMiddleware, corsMiddleware, rateLimiter };
