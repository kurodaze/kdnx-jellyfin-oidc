using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Kdnx.Jellyfin.Oidc;

/// <summary>
/// Tracks Jellyfin access tokens minted via KDNX OIDC and their absolute session expiry
/// (<c>auth_time + session_max_age</c> from the IdP).
/// Persisted to disk so session lifetimes survive server and container restarts.
/// </summary>
public static class SsoSessionRegistry
{
    private static readonly ConcurrentDictionary<string, long> Sessions = new(StringComparer.Ordinal);
    private static readonly object FileLock = new();
    private static string _storageFilePath;

    /// <summary>Matches KDNX's own clamp on session_max_age.</summary>
    public static readonly long MinSessionMaxAgeSecs = 3600;

    /// <inheritdoc cref="MinSessionMaxAgeSecs"/>
    public static readonly long MaxSessionMaxAgeSecs = 90L * 24 * 60 * 60;

    /// <summary>
    /// Initializes persistent storage in the specified folder and reloads active sessions.
    /// Throws on an unreadable file, so the caller can log that those sessions are lost;
    /// storage stays set, so new sessions still persist.
    /// </summary>
    public static void Initialize(string dataFolderPath)
    {
        if (string.IsNullOrWhiteSpace(dataFolderPath))
        {
            return;
        }

        lock (FileLock)
        {
            Directory.CreateDirectory(dataFolderPath);
            _storageFilePath = Path.Combine(dataFolderPath, "sso-sessions.json");

            if (File.Exists(_storageFilePath))
            {
                var json = File.ReadAllText(_storageFilePath);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    var loaded = JsonSerializer.Deserialize<Dictionary<string, long>>(json);
                    foreach (var (token, expiresAt) in loaded ?? [])
                    {
                        if (!string.IsNullOrEmpty(token) && expiresAt > 0)
                        {
                            Sessions[token] = expiresAt;
                        }
                    }
                }
            }
        }
    }

    public static void Register(string accessToken, long expiresAtUnix)
    {
        if (string.IsNullOrEmpty(accessToken) || expiresAtUnix <= 0)
        {
            return;
        }

        Sessions[accessToken] = expiresAtUnix;
        SaveToFile();
    }

    public static void RemoveRange(IEnumerable<string> accessTokens)
    {
        if (accessTokens == null)
        {
            return;
        }

        var removedAny = false;
        foreach (var token in accessTokens)
        {
            if (!string.IsNullOrEmpty(token) && Sessions.TryRemove(token, out _))
            {
                removedAny = true;
            }
        }

        if (removedAny)
        {
            SaveToFile();
        }
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

    /// <summary>
    /// Clears all entries and optionally unsets the storage path. (Used for testing).
    /// </summary>
    public static void Clear(bool resetStorage = false)
    {
        lock (FileLock)
        {
            Sessions.Clear();
            if (resetStorage)
            {
                _storageFilePath = null;
            }
        }
    }

    /// <summary>Current count of tracked sessions.</summary>
    public static int Count => Sessions.Count;

    private static void SaveToFile()
    {
        if (string.IsNullOrEmpty(_storageFilePath))
        {
            return;
        }

        lock (FileLock)
        {
            try
            {
                var tempFile = _storageFilePath + ".tmp";
                var json = JsonSerializer.Serialize(Sessions);
                File.WriteAllText(tempFile, json);
                File.Move(tempFile, _storageFilePath, overwrite: true);
            }
            catch
            {
                // Suppress disk write failures so authentication flow is not interrupted.
            }
        }
    }
}
