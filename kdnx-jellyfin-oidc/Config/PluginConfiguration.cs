using System;
using System.Collections.Generic;
using MediaBrowser.Model.Plugins;

namespace Kdnx.Jellyfin.Oidc.Config;

public class PluginConfiguration : BasePluginConfiguration
{
    public List<OidConfig> OidConfigs { get; set; } = new();

    /// <summary>Maps an OIDC sub claim to the Jellyfin user it owns.</summary>
    public List<UserMapping> UserMappings { get; set; } = new();
}

public class OidConfig
{
    public string ProviderName { get; set; }

    /// <summary>Authority base URL; must serve /.well-known/openid-configuration.</summary>
    public string OidEndpoint { get; set; }

    /// <summary>Public resource hostname as registered with KDNX, e.g. fin.example.com.</summary>
    public string OidClientId { get; set; }

    public bool Enabled { get; set; }
}

public class UserMapping
{
    public string SubClaim { get; set; }

    public Guid UserId { get; set; }
}
