const ssoConfigurationPage = {
  pluginUniqueId: "241e75a6-d3d4-4345-8bae-a53c8a2034c1",
  loadConfiguration: (page) => {
    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then(
      (config) => {
        const provider = (config.OidConfigs && config.OidConfigs.length > 0) ? config.OidConfigs[0] : {};

        page.querySelector("#OidProviderName").value = provider.ProviderName || "";
        page.querySelector("#OidEndpoint").value = provider.OidEndpoint || "";
        page.querySelector("#OidClientId").value = provider.OidClientId || "";
        page.querySelector("#Enabled").checked = !!provider.Enabled;
      },
    );
  },
  saveConfiguration: (page) => {
    const provider_name = page.querySelector("#OidProviderName").value;
    if (!provider_name) {
      Dashboard.alert("Please specify a provider name.");
      return;
    }

    ApiClient.getPluginConfiguration(ssoConfigurationPage.pluginUniqueId).then((config) => {
      config.OidConfigs = [{
        ProviderName: provider_name,
        OidEndpoint: page.querySelector("#OidEndpoint").value || null,
        OidClientId: page.querySelector("#OidClientId").value || null,
        Enabled: page.querySelector("#Enabled").checked,
      }];

      ApiClient.updatePluginConfiguration(
        ssoConfigurationPage.pluginUniqueId,
        config,
      ).then(function (result) {
        Dashboard.processPluginConfigurationUpdateResult(result);
        ssoConfigurationPage.loadConfiguration(page);
        Dashboard.alert("Settings saved.");
      });
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

  view.querySelector("#SaveProvider").addEventListener("click", (e) => {
    ssoConfigurationPage.saveConfiguration(view);
    e.preventDefault();
    return false;
  });
}
