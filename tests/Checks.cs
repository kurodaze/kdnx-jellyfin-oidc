using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Kdnx.Jellyfin.Oidc;
using Kdnx.Jellyfin.Oidc.Api;
using Kdnx.Jellyfin.Oidc.Config;

// Invokes the REAL methods in the built plugin assembly, so this checks shipped
// code rather than a reimplementation.
static class Program
{
    static int _fail;

    static void Check(bool ok, string label, object got = null)
    {
        Console.WriteLine((ok ? "  PASS  " : "  FAIL  ") + label + (ok ? "" : $"   got: {got}"));
        if (!ok) _fail++;
    }

    // Mirrors Rust jsonwebtoken: base64url, NO padding.
    static string B64Url(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static string KdnxToken(string payloadJson)
    {
        var header = B64Url(Encoding.UTF8.GetBytes("{\"alg\":\"EdDSA\",\"kid\":\"kdnx-oidc-key\"}"));
        var payload = B64Url(Encoding.UTF8.GetBytes(payloadJson));
        var sig = B64Url(new byte[64]); // Ed25519 sig length
        return $"{header}.{payload}.{sig}";
    }

    static readonly Type Ctl = typeof(SSOController);

    static bool SessionClaims(string token, out long authTime, out long maxAge)
    {
        var m = Ctl.GetMethod("TryGetSessionClaims", BindingFlags.NonPublic | BindingFlags.Static);
        var args = new object[] { token, 0L, 0L };
        var r = (bool)m.Invoke(null, args);
        authTime = (long)args[1];
        maxAge = (long)args[2];
        return r;
    }

    static bool RedirectUri(OidConfig cfg, out string uri, out string err)
    {
        var m = Ctl.GetMethod("TryGetOidcRedirectUri", BindingFlags.NonPublic | BindingFlags.Static);
        var args = new object[] { cfg, null, null };
        var r = (bool)m.Invoke(null, args);
        uri = (string)args[1];
        err = (string)args[2];
        return r;
    }

    static int Main()
    {
        Console.WriteLine("== TryGetSessionClaims: real KDNX ID token shape ==");

        // Faithful KDNX claim set (server/src/auth.rs generate_oidc_id_token).
        // Pad `name` to sweep every base64 length residue; includes base64url '-' and '_'.
        for (int pad = 0; pad < 4; pad++)
        {
            var json = JsonSerializer.Serialize(new
            {
                iss = "https://kdnx-auth.example.com",
                sub = "308451923847239847",
                aud = "fin.example.com",
                exp = 1753600900,
                iat = 1753600000,
                auth_time = 1753599000,
                session_max_age = 604800,
                jti = "b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                preferred_username = "kuro" + new string('z', pad),
                name = "~~~ ~~~ ??? ???" + new string('z', pad),
                guild_id = "902384029384",
                roles = new[] { "member", "plex" }
            });
            var tok = KdnxToken(json);
            var seg = tok.Split('.')[1];
            var residue = seg.Length % 4;
            var ok = SessionClaims(tok, out var at, out var sma);
            Check(ok && at == 1753599000 && sma == 604800,
                $"decodes (payload len residue {residue}) -> auth_time/session_max_age", $"{ok} {at} {sma}");
            if (pad == 0)
            {
                Check(seg.Contains('-') && seg.Contains('_'), "payload exercises base64url '-' and '_' alphabet", seg);
            }
        }

        // Rejections
        var baseClaims = "\"iss\":\"https://kdnx-auth.example.com\",\"sub\":\"1\",\"aud\":\"fin.example.com\"";
        Check(!SessionClaims(KdnxToken("{" + baseClaims + ",\"session_max_age\":604800}"), out _, out _),
            "rejects missing auth_time");
        Check(!SessionClaims(KdnxToken("{" + baseClaims + ",\"auth_time\":1753599000}"), out _, out _),
            "rejects missing session_max_age");
        Check(!SessionClaims(KdnxToken("{" + baseClaims + ",\"auth_time\":0,\"session_max_age\":604800}"), out _, out _),
            "rejects auth_time = 0");
        Check(!SessionClaims(KdnxToken("{" + baseClaims + ",\"auth_time\":1753599000,\"session_max_age\":\"604800\"}"), out _, out _),
            "rejects session_max_age as JSON string");
        Check(!SessionClaims("not.a.jwt", out _, out _), "rejects non-base64 payload");
        Check(!SessionClaims("onlyonepart", out _, out _), "rejects single-segment token");
        Check(!SessionClaims("", out _, out _), "rejects empty token");
        Check(!SessionClaims(null, out _, out _), "rejects null token");
        Check(!SessionClaims("aaaa.abcde.cccc", out _, out _), "rejects base64 length residue 1 (malformed)");

        Console.WriteLine();
        Console.WriteLine("== TryGetOidcRedirectUri: must match KDNX byte-for-byte ==");
        // KDNX builds https://{subdomain}.{domain}{oidc_redirect_path} and compares with !=
        const string Expected = "https://fin.example.com/sso/OID/redirect/KDNX";

        foreach (var (clientId, providerName, label) in new[]
        {
            ("fin.example.com", "KDNX", "lowercase host"),
            ("Fin.Example.COM", "KDNX", "MIXED-CASE host (the interop trap)"),
            ("  fin.example.com  ", "KDNX", "surrounding host whitespace"),
            ("fin.example.com.", "KDNX", "FQDN trailing dot"),
            ("fin.example.com", "  KDNX  ", "surrounding provider whitespace"),
        })
        {
            var ok = RedirectUri(new OidConfig { OidClientId = clientId, ProviderName = providerName }, out var uri, out _);
            Check(ok && uri == Expected, $"{label,-34} -> expected URI", uri);
        }

        foreach (var (clientId, label) in new[]
        {
            ("https://fin.example.com", "scheme"),
            ("fin.example.com/sso", "path"),
            ("fin.example.com?a=b", "query"),
            ("fin.example.com#f", "fragment"),
            ("fin.example.com\\x", "backslash"),
            ("fin example.com", "space"),
            ("", "empty"),
            (null, "null"),
        })
        {
            var ok = RedirectUri(new OidConfig { OidClientId = clientId, ProviderName = "KDNX" }, out var uri, out var err);
            Check(!ok && uri == null && !string.IsNullOrEmpty(err), $"rejects client id with {label}", uri);
        }

        foreach (var (provider, label) in new[]
        {
            ("KDNX/evil", "path"),
            ("KDNX?evil", "query"),
            ("KDNX#evil", "fragment"),
            ("KDNX\\evil", "backslash"),
            ("KDNX evil", "space"),
            ("", "empty"),
            (null, "null"),
        })
        {
            var ok = RedirectUri(new OidConfig { OidClientId = "fin.example.com", ProviderName = provider }, out var uri, out var err);
            Check(!ok && uri == null && !string.IsNullOrEmpty(err), $"rejects provider name with {label}", uri);
        }

        Console.WriteLine();
        Console.WriteLine("== SsoSessionRegistry.ComputeExpiresAt vs KDNX clamp [3600, 90d] ==");
        Check(SsoSessionRegistry.ComputeExpiresAt(1000, 604800) == 1000 + 604800, "7d default passes through");
        Check(SsoSessionRegistry.ComputeExpiresAt(1000, 100) == 1000 + 3600, "below-min clamps up to 3600");
        Check(SsoSessionRegistry.ComputeExpiresAt(1000, long.MaxValue) == 1000 + 90L * 24 * 60 * 60, "above-max clamps to 90d");
        Check(SsoSessionRegistry.ComputeExpiresAt(0, 604800) == null, "auth_time 0 -> null");
        Check(SsoSessionRegistry.ComputeExpiresAt(1000, 0) == null, "session_max_age 0 -> null");
        Check(SsoSessionRegistry.ComputeExpiresAt(long.MaxValue, 3600) == null, "auth_time overflow -> null");

        Console.WriteLine();
        Console.WriteLine("== SsoSessionRegistry: Persistent storage across restarts ==");
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "kdnx_test_" + Guid.NewGuid().ToString("N"));
            try
            {
                SsoSessionRegistry.Clear(resetStorage: true);
                SsoSessionRegistry.Initialize(tempDir);
                Check(SsoSessionRegistry.Count == 0, "initializes empty");

                SsoSessionRegistry.Register("tok_active", 2000000000);
                SsoSessionRegistry.Register("tok_expired", 1000);
                Check(SsoSessionRegistry.Count == 2, "registers 2 tokens");

                var storageFile = Path.Combine(tempDir, "sso-sessions.json");
                Check(File.Exists(storageFile), "persists sso-sessions.json to disk");
                var rawBytes = File.ReadAllBytes(storageFile);
                Check(rawBytes.Length > 0 && rawBytes[0] == (byte)'{',
                    "sso-sessions.json is BOM-free UTF-8 JSON", rawBytes.Length > 0 ? rawBytes[0] : -1);
                if (!OperatingSystem.IsWindows())
                {
                    var mode = File.GetUnixFileMode(storageFile);
                    Check(mode == (UnixFileMode.UserRead | UnixFileMode.UserWrite),
                        "sso-sessions.json is written with 0600 permissions", mode);
                }

                // Simulate server restart: clear memory, re-initialize from same tempDir
                SsoSessionRegistry.Clear(resetStorage: true);
                SsoSessionRegistry.Initialize(tempDir);
                Check(SsoSessionRegistry.Count == 2, "reloads 2 tokens from disk after restart");

                var expired = SsoSessionRegistry.CollectExpired(5000);
                Check(expired.Count == 1 && expired[0] == "tok_expired", "collects expired token");

                SsoSessionRegistry.RemoveRange(expired);
                Check(SsoSessionRegistry.Count == 1, "removes expired token");

                // Simulate second restart: verify deletion was persisted
                SsoSessionRegistry.Clear(resetStorage: true);
                SsoSessionRegistry.Initialize(tempDir);
                Check(SsoSessionRegistry.Count == 1, "reloads only remaining active token after restart");

                // A corrupt file must surface (the watchdog logs that its sessions are
                // lost), yet leave storage set so new sessions still persist.
                SsoSessionRegistry.Clear(resetStorage: true);
                File.WriteAllText(storageFile, "{not json");
                bool threwOnCorrupt = false;
                try { SsoSessionRegistry.Initialize(tempDir); }
                catch (JsonException) { threwOnCorrupt = true; }
                Check(threwOnCorrupt, "corrupt sso-sessions.json throws instead of loading silently");
                SsoSessionRegistry.Register("tok_new", 2000000000);
                Check(File.ReadAllText(storageFile).Contains("tok_new"), "new sessions persist after a corrupt load");

                SsoSessionRegistry.Clear(resetStorage: true);
            }
            finally
            {
                if (Directory.Exists(tempDir))
                {
                    Directory.Delete(tempDir, true);
                }
            }
        }

        Console.WriteLine();
        Console.WriteLine("== WebResponse.Generator: escaping and placeholder substitution ==");
        {
            var html = WebResponse.Generator("tok123", "KDNX", "/jf</script><script>alert(1)</script>", "nonceABC");
            Check(!html.Contains("</script><script>alert(1)", StringComparison.Ordinal),
                "escapes </script> in substituted values");
            Check(html.Contains("nonce=\"nonceABC\"", StringComparison.Ordinal),
                "injects CSP nonce");
            Check(!html.Contains("___jsonPathBase___", StringComparison.Ordinal)
                && !html.Contains("___jsonData___", StringComparison.Ordinal)
                && !html.Contains("___jsonAuthUrl___", StringComparison.Ordinal)
                && !html.Contains("___nonce___", StringComparison.Ordinal),
                "replaces all template placeholders");
        }

        Console.WriteLine();
        Console.WriteLine(_fail == 0 ? "ALL CHECKS PASSED" : $"{_fail} CHECK(S) FAILED");
        return _fail == 0 ? 0 : 1;
    }
}
