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

    /// <summary>
    /// Minimum session_max_age accepted from the IdP (1 hour). Matches KDNX clamp.
    /// </summary>
    public const long MinSessionMaxAgeSecs = 3600;

    /// <summary>
    /// Maximum session_max_age accepted from the IdP (90 days). Matches KDNX clamp.
    /// </summary>
    public const long MaxSessionMaxAgeSecs = 90L * 24 * 60 * 60;

    /// <summary>
    /// Registers an SSO-issued access token with absolute Unix expiry seconds.
    /// </summary>
    /// <param name="accessToken">Jellyfin access token.</param>
    /// <param name="expiresAtUnix">Absolute expiry (Unix seconds).</param>
    public static void Register(string accessToken, long expiresAtUnix)
    {
        if (string.IsNullOrEmpty(accessToken) || expiresAtUnix <= 0)
        {
            return;
        }

        Sessions[accessToken] = expiresAtUnix;
    }

    /// <summary>
    /// Removes a tracked token (logout or expiry).
    /// </summary>
    /// <param name="accessToken">Jellyfin access token.</param>
    public static void Remove(string accessToken)
    {
        if (string.IsNullOrEmpty(accessToken))
        {
            return;
        }

        Sessions.TryRemove(accessToken, out _);
    }

    /// <summary>
    /// Snapshot of tokens whose absolute session lifetime has elapsed.
    /// </summary>
    /// <param name="nowUnix">Current Unix seconds.</param>
    /// <returns>Expired access tokens.</returns>
    public static IReadOnlyList<string> CollectExpired(long nowUnix)
    {
        return Sessions
            .Where(kv => kv.Value <= nowUnix)
            .Select(kv => kv.Key)
            .ToList();
    }

    /// <summary>
    /// Computes absolute session expiry. Requires positive <paramref name="authTimeUnix"/>
    /// and <paramref name="sessionMaxAgeSecs"/> from the IdP (no silent defaults).
    /// </summary>
    /// <param name="authTimeUnix">OIDC auth_time claim.</param>
    /// <param name="sessionMaxAgeSecs">OIDC/IdP session_max_age seconds.</param>
    /// <returns>Absolute expiry Unix seconds, or null if claims are invalid.</returns>
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
