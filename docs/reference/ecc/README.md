# ECC references used for the Mini SOC dashboard

Source: https://github.com/affaan-m/ECC

Pinned commit: `d2ef2680594f9a17526a6e1a2e18b3d242c5d17b`.

The two adjacent reference documents are unmodified copies of
`skills/security-review/SKILL.md` and `skills/e2e-testing/SKILL.md`.
Their MIT license is included in `LICENSE`.

Applied to this dashboard:

- Security review: no embedded credentials, bearer token kept only in memory,
  authenticated API calls, untrusted alert content rendered as text, strict CSP,
  and tests that unauthenticated read/write requests fail.
- E2E testing: browser locators, response/element-based waits, isolated API
  fixtures, login/filter/detail/status/empty/error/session-expiry coverage,
  and desktop/mobile layout checks.

These are development references, not runtime dependencies. ECC's global
installers, hooks, MCP configuration and unrelated rules were not installed.
The FastAPI bearer-token API is retained; reloading the dashboard requires login.
This scoped review does not certify production readiness or replace the
project's outstanding HTTPS/rate-limit/dependency-hardening work.
