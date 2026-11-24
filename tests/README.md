# Tests

Two checks, no test framework. Both exit non-zero on failure and run in CI.

```bash
dotnet run --project tests          # OIDC logic
node tests/callback-page.mjs        # SSO callback page
```

## `Checks.cs`

Calls the plugin's own methods (reaching the private static ones by reflection),
so it exercises shipped code rather than a copy of the logic.

- **`TryGetSessionClaims`** against KDNX-shaped ID tokens (`server/src/auth.rs`
  in the KDNX repo builds these): every base64 length residue, base64url `-`/`_`
  alphabet, and rejection cases (missing or zero `auth_time`, missing
  `session_max_age`, stringly-typed claims, malformed segments).
- **`TryGetOidcRedirectUri`** must match what KDNX accepts. KDNX resolves
  `client_id` case-insensitively but compares `redirect_uri` byte-for-byte
  against its own lowercase host, so mixed case, stray whitespace (host or
  provider name) and a trailing FQDN dot all have to converge on one string.
  Invalid client IDs and provider names are rejected.
- **`SsoSessionRegistry`** clamps to the same `[3600, 90d]` range as KDNX's
  `normalize_oidc_session_max_age_secs`, rejects `auth_time` overflow, persists
  with `0600` permissions on Unix, reloads across restarts, and surfaces corrupt
  JSON files while keeping subsequent writes working.
- **`WebResponse.Generator`** escapes `</script>` breakout sequences, injects
  the CSP nonce, and replaces every template placeholder.

## `callback-page.mjs`

Runs the real `<script>` block out of `Views/callback.html` in a stubbed
browser (`localStorage`, `fetch`, and an iframe whose `src` setter simulates
jellyfin-web re-bootstrapping the credential blob).

Covers multi-server preservation (including restoring prior credentials on auth
failure), first-ever login, corrupt prior blobs, `NativeShell.AppHost` device ID
seeding, and Chromium Edge/Opera User-Agent detection.
