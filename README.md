# kdnx-jellyfin-oidc

A Jellyfin plugin for OpenID Connect (OIDC) authentication. This plugin allows users to log into Jellyfin using the KDNX OIDC Provider.

## Installation

### Add to Jellyfin Plugin Repository
1. Go to your Jellyfin Dashboard -> **Plugins** -> **Repositories**.
2. Click **Add**.
3. Name: `KDNX OIDC`
4. Repository URL: `https://raw.githubusercontent.com/kurodaze/kdnx-jellyfin-oidc/manifest-release/manifest.json`
5. Go to the **Catalog** tab, find "KDNX OIDC" under Authentication, and click Install.
6. Restart Jellyfin.

## Configuration

### 1. KDNX Resource Setup
In KDNX Admin under Resources, configure your Jellyfin resource (e.g. `fin.yourdomain.tld`):
- **Authentication**: `Passthrough` (Do **not** use `Edge Discord` — edge gating intercepts every HTTP request at the proxy and breaks Jellyfin's login and client API flows).
- **OIDC Redirect Path**: `/sso/OID/redirect/KDNX` (case-sensitive; must match the provider name configured in Jellyfin).
- **Authorization (Allowed Discord Roles)**: *(Optional)* Select specific Discord roles to restrict access. KDNX validates these roles during the OIDC token exchange; users lacking the role receive a 403 Access Denied.

### 2. Jellyfin Plugin Settings
After installing and restarting Jellyfin, navigate to `Dashboard -> Plugins -> KDNX OIDC`:
- **Provider name**: `KDNX` (callback becomes `/sso/OID/redirect/KDNX`)
- **OpenID Endpoint**: `https://kdnx-auth.yourdomain.tld`
- **Client ID**: `fin.yourdomain.tld` (your public Jellyfin resource hostname)

*Notes:*
- Scopes are fixed to `openid profile` (what KDNX issues).
- KDNX strictly enforces PKCE (`S256`) for authorization codes, which this plugin handles automatically via Duende `OidcClient`.
- The provider name and redirect path are case-sensitive and must match exactly on both ends (`KDNX` pairs with `/sso/OID/redirect/KDNX`).

### Session max age (re-authentication)

KDNX advertises a global OIDC session policy (default **7 days**) via:
- ID/access token claims: `auth_time`, `session_max_age`
- Discovery document field: `session_max_age`

This plugin enforces it by:
1. **Requiring** `auth_time` and `session_max_age` on the KDNX identity token (login fails without them)
2. Computing `SessionExpiresAt = auth_time + session_max_age`
3. Tracking the Jellyfin access token and calling `ISessionManager.Logout(accessToken)` when expired

Tracking is persistent: active sessions are saved to disk (`sso-sessions.json` in the plugin data directory). If Jellyfin or its container restarts, unexpired sessions continue to be monitored, and any sessions that expired while offline are immediately revoked on startup. Requires a current KDNX server that issues those claims. Change the policy in KDNX admin → Authentication → **OIDC session max age**.

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

## Mobile Apps (Android & WebView Clients)

Jellyfin Web keys the client device id off `localStorage._deviceId2`, which the official Android app never writes — it exposes the real id through `window.NativeShell.AppHost.deviceId()` instead. The plugin seeds `_deviceId2` from NativeShell before loading jellyfin-web on the callback page, preventing the Android app from hanging on "Logging in...".

Requirements:
- Start SSO from the app WebView (login disclaimer button).
- Complete OIDC so the redirect lands back in that WebView.
- There is no Quick Connect path and no alternate client login flow.

## Verification

1. Open a private/incognito browser window.
2. Navigate to `https://fin.yourdomain.tld/sso/OID/start/KDNX` (or click your login button).
3. Complete Discord login on `kdnx-auth.yourdomain.tld`.
4. Verify you are redirected back to Jellyfin logged in.
