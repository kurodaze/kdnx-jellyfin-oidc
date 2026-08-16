# kdnx-jellyfin-oidc

A Jellyfin plugin for OpenID Connect (OIDC) authentication. This plugin allows users to log into Jellyfin using KDNX OIDC Provider.

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

KDNX resource: auth **Passthrough**, OIDC redirect path `/sso/OID/redirect/KDNX`
(KDNX defaults to `/callback`, so this has to be changed).
See the companion guide in the KDNX repo: `docs/jellyfin-sso.md`.

The provider name and the redirect path are compared exactly, case included, so
whatever you pick must be identical on both ends — provider name `KDNX` pairs with
`/sso/OID/redirect/KDNX`, while `kdnx` would need `/sso/OID/redirect/kdnx`.

### Session max age (re-authentication)

KDNX advertises a global OIDC session policy (default **7 days**) via:

- ID/access token claims: `auth_time`, `session_max_age`
- Discovery document field: `session_max_age`

This plugin enforces it by:

1. **Requiring** `auth_time` and `session_max_age` on the KDNX identity token (login fails without them)
2. Computing `SessionExpiresAt = auth_time + session_max_age`
3. Tracking the Jellyfin access token in process memory and calling `ISessionManager.Logout(accessToken)` when expired

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

Jellyfin Web keys the client device id off `localStorage._deviceId2`, which the
official Android app never writes — it exposes the real id through
`window.NativeShell.AppHost.deviceId()` instead. The callback page seeds
`_deviceId2` from NativeShell before loading jellyfin-web, and takes app name,
version and device name from the same API when present.

Login starts and finishes in the Jellyfin web context. There is no Quick Connect
path and no alternate client login flow.
