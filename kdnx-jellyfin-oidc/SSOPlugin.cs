using System;
using System.Collections.Generic;
using Kdnx.Jellyfin.Oidc.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Kdnx.Jellyfin.Oidc;

/// <summary>
/// The OIDC plugin class.
/// </summary>
public class KdnxOidcPlugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    private PluginPageInfo[] _pages;

    /// <summary>
    /// Initializes a new instance of the <see cref="KdnxOidcPlugin"/> class.
    /// </summary>
    /// <param name="applicationPaths">Internal Jellyfin interface for the ApplicationPath.</param>
    /// <param name="xmlSerializer">Internal Jellyfin interface for the XML information.</param>
    public KdnxOidcPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        Instance = this;
    }

    /// <summary>
    /// Gets the instance of the OIDC plugin.
    /// </summary>
    public static KdnxOidcPlugin Instance { get; private set; }

    /// <summary>
    /// Gets the name of the OIDC plugin.
    /// </summary>
    public override string Name => "kdnx-jellyfin-oidc";

    /// <summary>
    /// Gets the GUID of the OIDC plugin.
    /// </summary>
    public override Guid Id => Guid.Parse("241e75a6-d3d4-4345-8bae-a53c8a2034c1");

    /// <summary>
    /// Returns the available internal web pages of this plugin.
    /// </summary>
    /// <returns>A list of internal webpages in this application.</returns>
    public IEnumerable<PluginPageInfo> GetPages()
    {
        return _pages ??= new[]
        {
            new PluginPageInfo
            {
                Name = Name,
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.configPage.html"
            },
            new PluginPageInfo
            {
                Name = Name + ".js",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.config.js"
            },
            new PluginPageInfo
            {
                Name = Name + ".css",
                EmbeddedResourcePath = $"{GetType().Namespace}.Config.style.css"
            }
        };
    }
}
