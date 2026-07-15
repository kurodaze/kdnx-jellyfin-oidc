using System.Collections.Generic;
using MediaBrowser.Model.Plugins;

namespace Kdnx.Jellyfin.Oidc.Config;

/// <summary>
/// Plugin Configuration.
/// </summary>
public class PluginConfiguration : BasePluginConfiguration
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PluginConfiguration"/> class.
    /// </summary>
    public PluginConfiguration()
    {
        OidConfigs = new List<OidConfig>();
        UserMappings = new List<UserMapping>();
    }

    /// <summary>
    /// Gets or sets the OpenID configurations available.
    /// </summary>
    public List<OidConfig> OidConfigs { get; set; }

    /// <summary>
    /// Gets or sets the mappings of OIDC sub claims to Jellyfin User IDs.
    /// </summary>
    public List<UserMapping> UserMappings { get; set; }
}

/// <summary>
/// The configuration required for an OpenID flow.
/// </summary>
public class OidConfig
{
    /// <summary>
    /// Gets or sets the provider name.
    /// </summary>
    public string ProviderName { get; set; }

    /// <summary>
    /// Gets or sets the OpenID well-known information endpoint.
    /// </summary>
    public string OidEndpoint { get; set; }

    /// <summary>
    /// Gets or sets OpenID client ID.
    /// </summary>
    public string OidClientId { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the provider is enabled.
    /// </summary>
    public bool Enabled { get; set; }
}

/// <summary>
/// A mapping between an external OIDC sub claim and a Jellyfin User ID.
/// </summary>
public class UserMapping
{
    /// <summary>
    /// Gets or sets the subject claim from the OIDC provider.
    /// </summary>
    public string SubClaim { get; set; }

    /// <summary>
    /// Gets or sets the internal Jellyfin User Guid.
    /// </summary>
    public System.Guid UserId { get; set; }
}
