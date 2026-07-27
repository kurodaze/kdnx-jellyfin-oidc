using System;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Duende.IdentityModel.OidcClient;
using Kdnx.Jellyfin.Oidc;
using Kdnx.Jellyfin.Oidc.Api;
using Kdnx.Jellyfin.Oidc.Config;

// Invokes the REAL private statics in the built SSOController via reflection,
// so this checks shipped code, not a reimplementation.
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
        // Pad `name` to sweep every base64 length residue.
        for (int pad = 0; pad < 6; pad++)
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
                name = "Kuro" + new string('z', pad),
                guild_id = "902384029384",
                roles = new[] { "member", "plex" }
            });
            var tok = KdnxToken(json);
            var residue = tok.Split('.')[1].Length % 4;
            var ok = SessionClaims(tok, out var at, out var sma);
            Check(ok && at == 1753599000 && sma == 604800,
                $"decodes (payload len residue {residue}) -> auth_time/session_max_age", $"{ok} {at} {sma}");
        }

        // base64url alphabet: payload MUST contain '-' and/or '_' to prove the swap.
        {
            // '~' (0x7E) and DEL (0x7F) land on base64 sextets 62/63 -> '+'/'/' -> '-'/'_'
            // once byte alignment is right, so sweep a pad until both appear.
            string tok = null, seg = null;
            for (int i = 0; i < 64; i++)
            {
                var json = "{\"iss\":\"https://kdnx-auth.example.com\",\"sub\":\"308451923847239849\","
                         + "\"aud\":\"fin.example.com\",\"auth_time\":1753599000,\"session_max_age\":604800,"
                         + "\"name\":\"" + new string('x', i) + "~~~\"}";
                tok = KdnxToken(json);
                seg = tok.Split('.')[1];
                if (seg.Contains('-') && seg.Contains('_')) break;
            }
            var ok = SessionClaims(tok, out var at, out var sma);
            Check(seg.Contains('-') && seg.Contains('_'), "payload uses base64url '-' AND '_' alphabet", seg);
            Check(ok && at == 1753599000 && sma == 604800, "  ...and it still decodes correctly", $"{ok} {at} {sma}");
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
        // KDNX builds  https://{subdomain}.{domain}{oidc_redirect_path}  and compares with !=
        const string Expected = "https://fin.example.com/sso/OID/redirect/KDNX";

        foreach (var (clientId, label) in new[]
        {
            ("fin.example.com", "lowercase host"),
            ("Fin.Example.COM", "MIXED-CASE host (the interop trap)"),
            ("  fin.example.com  ", "surrounding whitespace"),
            ("fin.example.com.", "FQDN trailing dot"),
        })
        {
            var ok = RedirectUri(new OidConfig { OidClientId = clientId, ProviderName = "KDNX" }, out var uri, out _);
            Check(ok && uri == Expected, $"{label,-34} -> expected URI", uri);
        }

        // Provider name casing comes from config, never the request URL.
        {
            var ok = RedirectUri(new OidConfig { OidClientId = "fin.example.com", ProviderName = "KDNX" }, out var uri, out _);
            Check(ok && uri.EndsWith("/redirect/KDNX", StringComparison.Ordinal),
                "path segment preserves configured ProviderName casing", uri);
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

        Console.WriteLine();
        Console.WriteLine("== SanitizeLogInput: no line break survives, on any return path ==");
        {
            var m = Ctl.GetMethod("SanitizeLogInput", BindingFlags.NonPublic | BindingFlags.Static);
            string San(string s) => (string)m.Invoke(null, new object[] { s });

            foreach (var (raw, label) in new[]
            {
                ("kuro\nADMIN logged in", "LF"),
                ("kuro\rADMIN logged in", "CR"),
                ("kuro\r\nADMIN logged in", "CRLF"),
                ("kuro\u0085ADMIN logged in", "NEL"),
                ("kuro\u2028ADMIN logged in", "line separator"),
                ("kuro\u2029ADMIN logged in", "paragraph separator"),
                ("kuro\fADMIN logged in", "form feed"),
            })
            {
                var s = San(raw);
                Check(s == "kuroADMIN logged in", $"strips {label}", s);
            }

            Check(San("kuro") == "kuro", "leaves a clean value alone");
            Check(San("") == "", "empty string round-trips");
            Check(San(null) == null, "null is not dereferenced");
        }

        Console.WriteLine();
        Console.WriteLine("== SsoSessionRegistry.ComputeExpiresAt vs KDNX clamp [3600, 90d] ==");
        Check(SsoSessionRegistry.ComputeExpiresAt(1000, 604800) == 1000 + 604800, "7d default passes through");
        Check(SsoSessionRegistry.ComputeExpiresAt(1000, 100) == 1000 + 3600, "below-min clamps up to 3600");
        Check(SsoSessionRegistry.ComputeExpiresAt(1000, long.MaxValue) == 1000 + 90L * 24 * 60 * 60, "above-max clamps to 90d");
        Check(SsoSessionRegistry.ComputeExpiresAt(0, 604800) == null, "auth_time 0 -> null");
        Check(SsoSessionRegistry.ComputeExpiresAt(1000, 0) == null, "session_max_age 0 -> null");
        Check(SsoSessionRegistry.MinSessionMaxAgeSecs == 3600 && SsoSessionRegistry.MaxSessionMaxAgeSecs == 90L * 24 * 60 * 60,
            "bounds equal KDNX MIN/MAX_OIDC_SESSION_MAX_AGE_SECS");

        Console.WriteLine();
        Console.WriteLine("== SsoFlowCache: unauthenticated /OID/start cannot grow it without bound ==");
        {
            var cache = new SsoFlowCache();
            var opts = new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromMinutes(10)).SetSize(1);

            cache.Set("oidcstate_abc", new object(), opts);
            Check(cache.TryGetValue("oidcstate_abc", out object _), "sized entry round-trips");
            cache.Remove("oidcstate_abc");
            Check(!cache.TryGetValue("oidcstate_abc", out object _), "remove works");

            // If any Set in the controller forgot SetSize, login would throw at runtime.
            var threw = false;
            try
            {
                cache.Set("nosize", new object(), new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromMinutes(10)));
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            Check(threw, "un-sized entry throws (so SetSize on all 3 sites is load-bearing)");

            const int flood = 50_000;
            for (int i = 0; i < flood; i++)
            {
                cache.Set($"oidcstate_flood{i}", new object(), opts);
            }

            for (int i = 0; i < 100 && cache.Count > SsoFlowCache.MaxEntries; i++)
            {
                System.Threading.Thread.Sleep(20); // compaction runs on the thread pool
            }

            Check(cache.Count <= SsoFlowCache.MaxEntries,
                $"{flood} unauthenticated inserts compact to <= {SsoFlowCache.MaxEntries}", cache.Count);
            cache.Dispose();
        }

        Console.WriteLine();
        Console.WriteLine("== how much memory does one cached login flow actually cost? ==");
        {
            // A realistic KDNX authorize URL, as Duende PrepareLoginAsync would produce.
            static TimedAuthorizeState Realistic(int i) => new(new AuthorizeState
            {
                State = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)),
                CodeVerifier = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(64)),
                RedirectUri = "https://fin.example.com/sso/OID/redirect/KDNX",
                StartUrl = "https://kdnx-auth.example.com/authorize?client_id=fin.example.com"
                         + "&redirect_uri=https%3A%2F%2Ffin.example.com%2Fsso%2FOID%2Fredirect%2FKDNX"
                         + "&response_type=code&scope=openid%20profile&state=" + i.ToString("x8")
                         + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16))
                         + "&code_challenge=" + Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
                         + "&code_challenge_method=S256&nonce="
                         + Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)),
            });

            const int n = 20_000;
            var cache = new MemoryCache(Options.Create(new MemoryCacheOptions()));
            var opts = new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromMinutes(10));

            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            var before = GC.GetTotalMemory(true);
            for (int i = 0; i < n; i++)
            {
                cache.Set($"oidcstate_{i:x8}", Realistic(i), opts);
            }

            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            var perEntry = (GC.GetTotalMemory(true) - before) / (double)n;
            GC.KeepAlive(cache);

            Console.WriteLine($"  measured  ~{perEntry:F0} bytes per in-flight login");
            foreach (var cap in new long[] { 500, 1_000, 10_000 })
            {
                Console.WriteLine($"  cap {cap,6} -> worst case {(cap * perEntry) / (1024 * 1024),6:F1} MB pinned for up to 10 min");
            }

            Console.WriteLine($"  configured cap is {SsoFlowCache.MaxEntries} -> "
                + $"{(SsoFlowCache.MaxEntries * perEntry) / (1024 * 1024):F1} MB");
            cache.Dispose();
        }

        Console.WriteLine();
        Console.WriteLine(_fail == 0 ? "ALL CHECKS PASSED" : $"{_fail} CHECK(S) FAILED");
        return _fail == 0 ? 0 : 1;
    }
}
