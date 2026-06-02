# kdnx-jellyfin-oidc

A Jellyfin plugin for OpenID Connect (OIDC) authentication. This plugin allows users to log into Jellyfin using an external OIDC Provider.

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

## Mobile App Fix (Infinite "Logging in...")

The official Jellyfin Android app has a known bug where external OIDC redirects lose the internal device ID, causing the app to hang infinitely on "Logging in...". 

Because the Jellyfin web UI sanitizes inline JavaScript in the branding settings, you must inject a patch script directly into the Jellyfin web files.

**1. Create `add-oauth-button.js` in your Jellyfin `web` folder** (e.g., `/usr/share/jellyfin/web/add-oauth-button.js`):
```javascript
(function waitForBody() {
  if (!document.body) {
    return setTimeout(waitForBody, 100);
  }
  function oAuthInitDeviceId() {
    if (!localStorage.getItem('_deviceId2') && window.NativeShell?.AppHost?.deviceId) {
      localStorage.setItem('_deviceId2', window.NativeShell.AppHost.deviceId());
    }
  }
  const observer = new MutationObserver(() => {
    const ssoButton = document.querySelector('.kdnx-sso');
    if (ssoButton) {
      ssoButton.onclick = oAuthInitDeviceId;
      observer.disconnect();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
```

**2. Modify `index.html`**
Because Jellyfin's `index.html` is heavily minified (all on one line), the easiest way to insert the script is to run this command in your Jellyfin container/server terminal:

```bash
sed -i 's|<head>|<head><script type="text/javascript" src="add-oauth-button.js"></script>|' /usr/share/jellyfin/web/index.html
```

Restart your Jellyfin container/server and clear the Android app cache. The login flow will now correctly link your device ID and complete successfully.
