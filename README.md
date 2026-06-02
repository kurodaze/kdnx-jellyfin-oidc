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
