const ssoConfigurationPage = {
  pluginUniqueId: "241e75a6-d3d4-4345-8bae-a53c8a2034c1",
  loadConfiguration: (page) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId)
      .then((config) => {
        const provider = (config.OidConfigs && config.OidConfigs.length > 0) ? config.OidConfigs[0] : {};

        page.querySelector("#OidProviderName").value = provider.ProviderName || "";
        page.querySelector("#OidEndpoint").value = provider.OidEndpoint || "";
        page.querySelector("#OidClientId").value = provider.OidClientId || "";
        page.querySelector("#Enabled").checked = !!provider.Enabled;
      })
      .catch(() => {
        Dashboard.alert("Failed to load KDNX OIDC configuration.");
      });
  },
  saveConfiguration: (page) => {
    const providerName = page.querySelector("#OidProviderName").value.trim();
    const endpoint = page.querySelector("#OidEndpoint").value.trim();
    const clientId = page.querySelector("#OidClientId").value.trim();

    if (!providerName || /[/\\ ?#]/.test(providerName)) {
      Dashboard.alert("Please specify a valid, URL-safe provider name (e.g. KDNX).");
      return;
    }

    let parsedEndpoint;
    try {
      parsedEndpoint = new URL(endpoint);
    } catch {
      parsedEndpoint = null;
    }
    if (!parsedEndpoint || parsedEndpoint.protocol !== "https:" || !parsedEndpoint.hostname) {
      Dashboard.alert("OpenID Endpoint must be an absolute https:// URL.");
      return;
    }

    if (!clientId || clientId.includes("://") || /[/\\ ?#]/.test(clientId)) {
      Dashboard.alert("OpenID Client ID must be the public hostname only (e.g. fin.example.com).");
      return;
    }

    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId)
      .then((config) => {
        config.OidConfigs = [{
          ProviderName: providerName,
          OidEndpoint: endpoint,
          OidClientId: clientId,
          Enabled: page.querySelector("#Enabled").checked,
        }];

        return ApiClient.updatePluginConfiguration(
          ssoConfigurationPage.pluginUniqueId,
          config,
        );
      })
      .then(Dashboard.processPluginConfigurationUpdateResult)
      .catch(() => {
        Dashboard.alert("Failed to save KDNX OIDC configuration.");
      });
  },
  addStyle: (view) => {
    const style = document.createElement("link");
    style.rel = "stylesheet";
    style.href =
      ApiClient.getUrl("web/configurationpage") + "?name=kdnx-jellyfin-oidc.css";
    view.appendChild(style);
  },
};

export default function (view) {
  ssoConfigurationPage.addStyle(view);
  ssoConfigurationPage.loadConfiguration(view);

  view.querySelector("#sso-new-oidc-provider").addEventListener("submit", (e) => {
    e.preventDefault();
    ssoConfigurationPage.saveConfiguration(view);
  });
}
