using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Kdnx.Jellyfin.Oidc;

/// <summary>
/// Tracks Jellyfin access tokens minted via KDNX OIDC and their absolute session expiry
/// (<c>auth_time + session_max_age</c> from the IdP).
/// </summary>
public static class SsoSessionRegistry
{
    private static readonly ConcurrentDictionary<string, long> Sessions = new(StringComparer.Ordinal);

    /// <summary>Matches KDNX's own clamp on session_max_age.</summary>
    public static readonly long MinSessionMaxAgeSecs = 3600;

    /// <inheritdoc cref="MinSessionMaxAgeSecs"/>
    public static readonly long MaxSessionMaxAgeSecs = 90L * 24 * 60 * 60;

    public static void Register(string accessToken, long expiresAtUnix)
    {
        if (string.IsNullOrEmpty(accessToken) || expiresAtUnix <= 0)
        {
            return;
        }

        Sessions[accessToken] = expiresAtUnix;
    }

    public static void Remove(string accessToken)
    {
        if (string.IsNullOrEmpty(accessToken))
        {
            return;
        }

        Sessions.TryRemove(accessToken, out _);
    }

    public static IReadOnlyList<string> CollectExpired(long nowUnix)
    {
        return Sessions
            .Where(kv => kv.Value <= nowUnix)
            .Select(kv => kv.Key)
            .ToList();
    }

    /// <summary>Null unless the IdP supplied both claims; there are no silent defaults.</summary>
    public static long? ComputeExpiresAt(long authTimeUnix, long sessionMaxAgeSecs)
    {
        if (authTimeUnix <= 0 || sessionMaxAgeSecs <= 0)
        {
            return null;
        }

        sessionMaxAgeSecs = Math.Clamp(sessionMaxAgeSecs, MinSessionMaxAgeSecs, MaxSessionMaxAgeSecs);
        return authTimeUnix + sessionMaxAgeSecs;
    }
}
