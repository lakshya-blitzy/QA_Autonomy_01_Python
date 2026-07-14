'use strict';

/**
 * src/routes/index.js
 * ---------------------------------------------------------------------------
 * HTTP router for the security-hardened Node.js/Express application.
 *
 * SECURITY REQUIREMENT R2 — INPUT VALIDATION (AAP Sections 0.5, 0.6.1, 0.6.2):
 * This module enforces field-level validation at the HTTP trust boundary using
 * `express-validator`. Every request-accepting route validates and sanitizes
 * its inputs BEFORE any business logic executes, rejecting malformed input with
 * an HTTP 400 response and a structured `errors` array. This mitigates the
 * OWASP A03:2021 (Injection) and malformed-input attack classes.
 *
 * RESPONSIBILITY BOUNDARY (do NOT duplicate upstream concerns here):
 *   - The JSON body-size cap (`express.json({ limit: '10kb' })`) and the
 *     normalization of malformed/oversized bodies to HTTP 400 are owned by
 *     `src/app.js` (via its JSON parser + error-handling middleware).
 *   - Security headers (helmet), CORS allowlist, and rate limiting are also
 *     wired UPSTREAM in `src/app.js` / `src/middleware/`.
 *   - This router owns ONLY the field-level express-validator checks and the
 *     preserved business behavior of the two endpoints below.
 *
 * MODULE SYSTEM: CommonJS (`require` / `module.exports`). The root
 * `package.json` intentionally does not declare `"type": "module"`.
 *
 * EXPORT CONTRACT (authoritative): this module exports the configured
 * `express.Router()` INSTANCE. The consumer `src/app.js` mounts it at the
 * application root with `app.use(require('./routes'))` (Node resolves
 * `./routes` to this `./routes/index.js`). Because the router is mounted
 * WITHOUT a base-path prefix, the paths declared here (`/hello`, `/add`) are
 * the full, externally observable request paths.
 *
 * PRESERVED BEHAVIOR (referenced, never imported):
 *   - `main.py`  -> `hello()` prints "Hello QA"; `GET /hello` mirrors this text.
 *   - `utils.py` -> `add(a, b) => a + b`; `POST /add` mirrors this as NUMERIC
 *     addition (never string concatenation), so `{ a: 2, b: 3 }` yields `5`.
 * ---------------------------------------------------------------------------
 */

const express = require('express');
const { body, validationResult } = require('express-validator');

// The router instance that is configured below and exported as the module's
// public API. It is intentionally created with no options so it inherits the
// parent application's settings when mounted by `src/app.js`.
const router = express.Router();

/**
 * Validation chain for `POST /add`.
 *
 * Declared once at module scope so the same, immutable set of validators is
 * reused for every request (the chains are stateless and safe to share).
 *
 *   - `body('a').isNumeric()` / `body('b').isNumeric()` enforce that each field
 *     is present and numeric. A missing field is treated as an empty value by
 *     express-validator and fails `isNumeric`, producing a validation error.
 *   - `.toFloat()` sanitizes each validated value into a real JavaScript number
 *     (rather than a string), guaranteeing that downstream arithmetic performs
 *     numeric addition instead of string concatenation.
 *
 * @type {import('express-validator').ValidationChain[]}
 */
const addValidationChain = [
  body('a')
    .isNumeric()
    .withMessage('Field "a" must be a numeric value.')
    .toFloat(),
  body('b')
    .isNumeric()
    .withMessage('Field "b" must be a numeric value.')
    .toFloat(),
];

/**
 * GET /hello
 *
 * Simple, side-effect-free success endpoint that mirrors the preserved
 * `main.py` `hello()` concept. Requires no request body and performs no
 * validation.
 *
 * @returns {200} JSON `{ message: 'Hello QA' }`.
 */
router.get('/hello', (req, res) => {
  res.status(200).json({ message: 'Hello QA' });
});

/**
 * POST /add
 *
 * Validated arithmetic endpoint that mirrors `utils.py` `add(a, b) => a + b`
 * as NUMERIC addition. The express-validator chain runs as route middleware
 * (R2 trust boundary) BEFORE the handler body executes.
 *
 * Request body (JSON): `{ "a": <number>, "b": <number> }`.
 *
 * @returns {400} JSON `{ errors: [...] }` when either field is missing or
 *   non-numeric — returned BEFORE any arithmetic is performed.
 * @returns {200} JSON `{ result: <number> }` — the numeric sum `a + b`.
 */
router.post('/add', addValidationChain, (req, res) => {
  // Trust boundary: reject invalid/missing input before computing anything.
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  // Numeric semantics: coerce explicitly to numbers so the result is the
  // arithmetic sum (e.g. 2 + 3 === 5), never a string concatenation ("23").
  // Values were already sanitized to floats by `.toFloat()`; the `Number(...)`
  // wrappers make the numeric intent explicit and defensive.
  const result = Number(req.body.a) + Number(req.body.b);

  return res.status(200).json({ result });
});

// Public API: export the configured Router INSTANCE (not an app, object, or
// factory) so `src/app.js` can mount it directly via `app.use(routes)`.
module.exports = router;
