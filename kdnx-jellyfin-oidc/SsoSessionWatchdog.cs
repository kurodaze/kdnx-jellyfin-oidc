using System;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kdnx.Jellyfin.Oidc;

/// <summary>
/// Once a minute, revokes Jellyfin sessions whose KDNX OIDC absolute session max age has
/// elapsed. Uses <see cref="ISessionManager.Logout(string)"/> with the access token string.
/// </summary>
public sealed class SsoSessionWatchdog : BackgroundService
{
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<SsoSessionWatchdog> _logger;

    public SsoSessionWatchdog(ISessionManager sessionManager, ILogger<SsoSessionWatchdog> logger)
    {
        _sessionManager = sessionManager;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var dataFolder = KdnxOidcPlugin.Instance?.DataFolderPath;
            if (!string.IsNullOrEmpty(dataFolder))
            {
                SsoSessionRegistry.Initialize(dataFolder);
                if (SsoSessionRegistry.Count > 0)
                {
                    _logger.LogInformation(
                        "Loaded {Count} active SSO session(s) from persistent storage",
                        SsoSessionRegistry.Count);
                }
            }
        }
        catch (Exception ex)
        {
            // Sessions in an unreadable file are no longer tracked, so they will not be revoked.
            _logger.LogWarning(ex, "Failed to load persistent SSO session registry");
        }

        // The first pass revokes sessions that expired while the server was down. One loop,
        // so a slow Logout never overlaps the next pass. Nothing may escape: an unhandled
        // exception from a hosted service stops the Jellyfin host.
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        do
        {
            await RevokeExpiredAsync().ConfigureAwait(false);
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    private async Task RevokeExpiredAsync()
    {
        try
        {
            var expired = SsoSessionRegistry.CollectExpired(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (expired.Count == 0)
            {
                return;
            }

            var revoked = 0;
            foreach (var accessToken in expired)
            {
                try
                {
                    await _sessionManager.Logout(accessToken).ConfigureAwait(false);
                    revoked++;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to logout expired SSO access token");
                }
            }

            // Dropped either way: a token Jellyfin no longer knows is already logged out.
            SsoSessionRegistry.RemoveRange(expired);

            if (revoked > 0)
            {
                _logger.LogInformation("Revoked {Count} KDNX OIDC session(s) past session_max_age", revoked);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SSO session watchdog tick failed");
        }
    }
}
