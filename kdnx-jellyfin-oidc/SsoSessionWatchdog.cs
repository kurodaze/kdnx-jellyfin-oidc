using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Controller.Session;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kdnx.Jellyfin.Oidc;

/// <summary>
/// Periodically revokes Jellyfin sessions whose KDNX OIDC absolute session max age has elapsed.
/// Uses <see cref="ISessionManager.Logout(string)"/> with the access token string.
/// </summary>
public sealed class SsoSessionWatchdog : IHostedService, IDisposable
{
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<SsoSessionWatchdog> _logger;
    private Timer _timer;
    private int _tickRunning;

    public SsoSessionWatchdog(ISessionManager sessionManager, ILogger<SsoSessionWatchdog> logger)
    {
        _sessionManager = sessionManager;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
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

            // Immediately purge and logout any sessions that expired while offline
            await RunTickAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to initialize persistent SSO session registry");
        }

        _timer = new Timer(OnTick, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _timer?.Dispose();
    }

    private void OnTick(object state)
    {
        // Prevent overlapping ticks if Logout is slow.
        if (Interlocked.Exchange(ref _tickRunning, 1) == 1)
        {
            return;
        }

        _ = RunTickAsync();
    }

    private async Task RunTickAsync()
    {
        try
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var expired = SsoSessionRegistry.CollectExpired(now);
            if (expired.Count == 0)
            {
                return;
            }

            var revoked = 0;
            var tokensToRemove = new List<string>(expired.Count);

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
                finally
                {
                    tokensToRemove.Add(accessToken);
                }
            }

            SsoSessionRegistry.RemoveRange(tokensToRemove);

            if (revoked > 0)
            {
                _logger.LogInformation(
                    "Revoked {Count} KDNX OIDC session(s) past session_max_age",
                    revoked);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SSO session watchdog tick failed");
        }
        finally
        {
            Interlocked.Exchange(ref _tickRunning, 0);
        }
    }
}
