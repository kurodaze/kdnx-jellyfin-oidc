# kdnx-jellyfin-oidc

A Jellyfin plugin for OpenID Connect (OIDC) authentication. This plugin allows users to log into Jellyfin using an external OIDC Provider (typically KDNX).

## Installation

### Add to Jellyfin Plugin Repository
1. Go to your Jellyfin Dashboard -> **Plugins** -> **Repositories**.
2. Click **Add**.
3. Name: `KDNX OIDC`
4. Repository URL: `https://raw.githubusercontent.com/kurodaze/kdnx-jellyfin-oidc/manifest-release/manifest.json`
5. Go to the **Catalog** tab, find "KDNX OIDC" under Authentication, and click Install.
6. Restart Jellyfin.

## Configuration
After installing and restarting Jellyfin, navigate to `Dashboard -> Plugins -> KDNX OIDC`.

Typical KDNX pairing:
- **Provider name**: `KDNX` (callback path becomes `/sso/OID/redirect/KDNX`)
- **OpenID Endpoint**: `https://kdnx-auth.yourdomain.tld`
- **Client ID**: `fin.yourdomain.tld` (public resource hostname only — also used as OIDC `redirect_uri` host)

Scopes are fixed to `openid profile` (what KDNX issues).

KDNX resource: auth **Passthrough**, OIDC redirect path `/sso/OID/redirect/KDNX`.
See the companion guide in the KDNX repo: `docs/jellyfin-sso.md`.

### Session max age (re-authentication)

KDNX advertises a global OIDC session policy (default **7 days**) via:

- ID/access token claims: `auth_time`, `session_max_age`
- Discovery document field: `session_max_age`

This plugin enforces it by:

1. **Requiring** `auth_time` and `session_max_age` on the KDNX identity token (login fails without them)
2. Computing `SessionExpiresAt = auth_time + session_max_age`
3. Tracking the Jellyfin access token in process memory and calling `ISessionManager.Logout(accessToken)` when expired
4. Storing `kdnx_session_expires_at` in `localStorage`

Tracking is in-memory: a Jellyfin restart clears the registry, so already-issued sessions then follow normal Jellyfin lifetime until the next SSO login. Requires a current KDNX server that issues those claims. Change the policy in KDNX admin → Authentication → **OIDC session max age**.

## Minimal SSO Button

In Jellyfin admin -> `Dashboard -> General -> Branding`:

Login disclaimer:

```html
<form action="/sso/OID/start/KDNX">
  <button type="submit" class="kdnx-sso">KDNX SSO</button>
</form>
```

Custom CSS:

```css
.kdnx-sso {
  display: inline-block;
  padding: .55rem .8rem;
  border: 1px solid currentColor;
  background: transparent;
  color: #fff;
  text-decoration: none;
  cursor: pointer;
  border-radius: 4px;
}
.kdnx-sso:hover {
  color: #fff;
  text-decoration: none;
}
```

## Mobile apps (Android and similar WebView clients)

### Why SSO used to hang on "Logging in..."

Jellyfin Web stores the client device id in `localStorage` under `_deviceId2`.
The official Android app exposes the real device id via `window.NativeShell.AppHost.deviceId()`
and **does not** write `_deviceId2`.

The SSO callback used to wait only for `_deviceId2`, so mobile sessions never completed.

### Built-in fix (plugin ≥ 1.0.4)

The callback page now:

1. Seeds `_deviceId2` from `NativeShell.AppHost.deviceId()` **before** loading jellyfin-web
2. Falls back to the same API if localStorage is still empty
3. Uses NativeShell for app name / version / device name when present

No `index.html` patch and no extra scripts under `/usr/share/jellyfin/web/` are required
for in-app WebView SSO.

**Requirements for mobile SSO to complete in the app:**

- Start login from the **Jellyfin app WebView** (not a random external browser tab)
- Complete the OIDC redirect back into that same WebView (same origin as Jellyfin)

This plugin only supports OIDC that starts and finishes in that Jellyfin web context.
There is no Quick Connect path and no alternate client login flow.

After installing/updating the plugin, restart Jellyfin and clear the Android app cache once
if an old half-login is stuck.
