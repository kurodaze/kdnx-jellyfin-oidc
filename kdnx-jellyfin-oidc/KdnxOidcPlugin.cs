using System;
using System.Collections.Generic;
using Kdnx.Jellyfin.Oidc.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Kdnx.Jellyfin.Oidc;

public class KdnxOidcPlugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    public KdnxOidcPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        Instance = this;
    }

    public static KdnxOidcPlugin Instance { get; private set; }

    public override string Name => "KDNX OIDC";

    public override Guid Id => Guid.Parse("241e75a6-d3d4-4345-8bae-a53c8a2034c1");

    public IEnumerable<PluginPageInfo> GetPages()
    {
        return new[]
        {
            new PluginPageInfo
            {
                Name = Name,
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.configPage.html"
            },
            new PluginPageInfo
            {
                Name = "kdnx-jellyfin-oidc.js",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.config.js"
            },
            new PluginPageInfo
            {
                Name = "kdnx-jellyfin-oidc.css",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.style.css"
            }
        };
    }
}
