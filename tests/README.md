# Tests

Two checks, no test framework. Both exit non-zero on failure and run in CI.

```bash
dotnet run --project tests          # OIDC logic
node tests/callback-page.mjs        # SSO callback page
```

## `Checks.cs`

Calls the plugin's own methods, reaching the private static ones by reflection,
so it exercises shipped code rather than a copy of the logic.

- **`TryGetSessionClaims`** against KDNX-shaped ID tokens (`server/src/auth.rs`
  in the KDNX repo builds these): every base64 length residue, payloads that
  use the base64url `-`/`_` alphabet, and the rejection cases — missing or zero
  `auth_time`, missing `session_max_age`, a stringly-typed claim, malformed
  segments.
- **`TryGetOidcRedirectUri`** must match what KDNX accepts. KDNX resolves
  `client_id` case-insensitively but compares `redirect_uri` byte-for-byte
  against its own lowercase host, so mixed case, stray whitespace and a
  trailing FQDN dot all have to converge on one string. Client IDs carrying a
  scheme, path, query, fragment or space are rejected.
- **`SsoSessionRegistry.ComputeExpiresAt`** clamps to the same `[3600, 90d]`
  range as KDNX's `normalize_oidc_session_max_age_secs`.
- **`SsoFlowCache`** stays bounded: 50k unauthenticated inserts compact back to
  the cap, and an entry without a size throws — which is what makes the
  `SetSize` calls in `SSOController` load-bearing rather than decorative. It
  also prints the measured cost per in-flight login, which is where the
  `MaxEntries` value comes from.

## `callback-page.mjs`

Runs the real `<script>` block out of `Views/callback.html` in a stubbed
browser (`localStorage`, `fetch`, and an iframe whose `src` setter simulates
jellyfin-web re-bootstrapping the credential blob).

Covers the multi-server case: a login must not destroy another server's saved
credentials, and the new token must land on the server matching the
authenticated `ServerId` rather than whatever sits at index 0. Also covers a
first-ever login and a corrupt prior blob.

To confirm a check still has teeth, point it at an older copy of the page:

```bash
git show 417a07b:kdnx-jellyfin-oidc/Views/callback.html > /tmp/old.html
CALLBACK_HTML=/tmp/old.html node tests/callback-page.mjs   # expected to fail
```
