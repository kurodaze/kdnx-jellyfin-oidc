# kdnx-jellyfin-oidc

A Jellyfin plugin for OpenID Connect (OIDC) authentication using the KDNX OIDC Provider.

## Installation

### Add to Jellyfin Plugin Repository
1. Go to Jellyfin Dashboard -> **Plugins** -> **Repositories**.
2. Click **Add**.
3. Name: `KDNX OIDC`
4. Repository URL: `https://raw.githubusercontent.com/kurodaze/kdnx-jellyfin-oidc/manifest-release/manifest.json`
5. Go to the **Catalog** tab, find "KDNX OIDC" under Authentication, and click Install.
6. Restart Jellyfin.

## Configuration

### 1. KDNX Resource Setup
In KDNX Admin under Resources, configure your Jellyfin resource (e.g. `fin.yourdomain.tld`):
- **Authentication**: `Passthrough` (Do **not** use `Edge Discord`; edge gating intercepts proxy requests and breaks Jellyfin API and client logins).
- **OIDC Redirect Path**: `/sso/OID/redirect/KDNX` (case-sensitive; must match the provider name in Jellyfin).
- **Authorization (Allowed Discord Roles)**: *(Optional)* Restrict access to specific Discord roles. KDNX validates roles during token exchange and returns 403 Access Denied if missing.

### 2. Jellyfin Plugin Settings
In Jellyfin Dashboard -> `Plugins` -> `KDNX OIDC`:
- **Provider name**: `KDNX` (callback: `/sso/OID/redirect/KDNX`)
- **OpenID Endpoint**: `https://kdnx-auth.yourdomain.tld`
- **Client ID**: `fin.yourdomain.tld` (public Jellyfin hostname)

*Notes:*
- Scopes are fixed to `openid profile`.
- PKCE (`S256`) is enforced by KDNX and handled automatically via Duende `OidcClient`.
- Provider name and redirect path are case-sensitive and must match on both ends (`KDNX` with `/sso/OID/redirect/KDNX`).

### Session max age (re-authentication)

KDNX advertises a global OIDC session policy (default **7 days**) via `auth_time` and `session_max_age` claims.

This plugin enforces it by:
1. Requiring `auth_time` and `session_max_age` on the identity token.
2. Computing `SessionExpiresAt = auth_time + session_max_age`.
3. Revoking the Jellyfin session when expired via `ISessionManager.Logout(accessToken)`.

Active sessions are saved to disk (`sso-sessions.json` in the plugin data directory) so lifetimes survive restarts. Any sessions that expired while offline are revoked on startup. Change the policy in KDNX admin -> Authentication -> **OIDC session max age**.

## SSO Button

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

The official Android app exposes its device ID via `window.NativeShell.AppHost.deviceId()` instead of writing `localStorage._deviceId2`. The callback page seeds this automatically before loading jellyfin-web to prevent login hangs.
