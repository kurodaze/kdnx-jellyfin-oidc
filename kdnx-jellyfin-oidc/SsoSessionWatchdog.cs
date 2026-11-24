using System;
using System.Collections.Generic;
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
                SsoSessionRegistry.Initialize(dataFolder, _logger);
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
        try
        {
            do
            {
                await RevokeExpiredAsync().ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
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

            var completed = new List<string>(expired.Count);
            foreach (var accessToken in expired)
            {
                try
                {
                    // SessionManager.Logout(string) returns cleanly when a token is already gone;
                    // an exception indicates a transient failure, so keep the token to retry next tick.
                    await _sessionManager.Logout(accessToken).ConfigureAwait(false);
                    completed.Add(accessToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to logout expired SSO access token; will retry on next tick");
                }
            }

            if (completed.Count > 0)
            {
                SsoSessionRegistry.RemoveRange(completed);
                _logger.LogInformation("Revoked {Count} KDNX OIDC session(s) past session_max_age", completed.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SSO session watchdog tick failed");
        }
    }
}
