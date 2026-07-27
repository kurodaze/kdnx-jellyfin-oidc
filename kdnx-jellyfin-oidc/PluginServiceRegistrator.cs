using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Kdnx.Jellyfin.Oidc;

/// <summary>
/// In-flight SSO login state. Separate from Jellyfin's shared cache because
/// <c>/sso/OID/start</c> is unauthenticated and inserts an entry per request.
/// </summary>
public sealed class SsoFlowCache : MemoryCache
{
    /// <summary>
    /// Concurrent in-flight logins, not requests: entries are Size = 1 and expire with
    /// the 10 minute state TTL. At ~1.2 KB each this caps the cache near 1 MB. Past the
    /// limit it compacts, so a flood drops pending logins instead of growing unbounded.
    /// </summary>
    public const long MaxEntries = 1_000;

    /// <summary>
    /// Initializes a new instance of the <see cref="SsoFlowCache"/> class.
    /// </summary>
    public SsoFlowCache()
        : base(Options.Create(new MemoryCacheOptions { SizeLimit = MaxEntries }))
    {
    }
}

/// <summary>
/// Registers plugin services with the Jellyfin host.
/// </summary>
public class PluginServiceRegistrator : IPluginServiceRegistrator
{
    /// <inheritdoc />
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<SsoFlowCache>();
        serviceCollection.AddHostedService<SsoSessionWatchdog>();
    }
}
