using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
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

    static string ResolveRemoteEndPoint(System.Net.IPAddress ip, Microsoft.AspNetCore.Http.IHeaderDictionary headers)
    {
        var m = Ctl.GetMethod("ResolveClientRemoteEndPoint", BindingFlags.NonPublic | BindingFlags.Static);
        return (string)m.Invoke(null, new object[] { ip, headers });
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
            Check(seg != null && seg.Contains('-') && seg.Contains('_'), "payload uses base64url '-' AND '_' alphabet", seg);
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

                // Simulate server restart: clear memory, re-initialize from same tempDir
                SsoSessionRegistry.Clear(resetStorage: true);
                Check(SsoSessionRegistry.Count == 0, "cleared memory simulated restart");

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

                SsoSessionRegistry.Remove("tok_active");
                Check(SsoSessionRegistry.Count == 0, "removed last token");

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

        Console.WriteLine("== SSOController.ResolveClientRemoteEndPoint: Client IP extraction ==");
        {
            var publicIp = System.Net.IPAddress.Parse("203.0.113.195");
            var v4Mapped = System.Net.IPAddress.Parse("::ffff:203.0.113.195");
            var lanProxy = System.Net.IPAddress.Parse("10.0.0.2");
            var loopback = System.Net.IPAddress.Parse("127.0.0.1");
            const string clientIp = "198.51.100.42";

            // 1. Direct public IP connection without headers
            Check(ResolveRemoteEndPoint(publicIp, null) == "203.0.113.195",
                "direct public IP without headers returns public IP");

            // 2. IPv4-mapped IPv6 public IP normalized
            Check(ResolveRemoteEndPoint(v4Mapped, null) == "203.0.113.195",
                "IPv4-mapped IPv6 unmapped to clean IPv4 string");

            // 3. Known/local proxy IP with X-Forwarded-For unwrapped
            var headersXff = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", $"{clientIp}, 10.0.0.2" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersXff) == clientIp,
                "proxy connection with X-Forwarded-For unwraps client IP");

            // 4. Local proxy with X-Real-IP
            var headersRealIp = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Real-IP", clientIp }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersRealIp) == clientIp,
                "proxy connection with X-Real-IP unwraps client IP");

            // 5. Local proxy with X-KDNX-Client-IP
            var headersKdnxIp = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-KDNX-Client-IP", clientIp }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersKdnxIp) == clientIp,
                "proxy connection with X-KDNX-Client-IP unwraps client IP");

            // 6. Direct LAN client without proxy headers
            var lanClient = System.Net.IPAddress.Parse("192.168.1.100");
            Check(ResolveRemoteEndPoint(lanClient, new Microsoft.AspNetCore.Http.HeaderDictionary()) == "192.168.1.100",
                "direct LAN client without proxy headers preserves LAN IP");

            // 7. Loopback with forwarded header
            Check(ResolveRemoteEndPoint(loopback, headersXff) == clientIp,
                "loopback connection with X-Forwarded-For extracts client IP");

            // 8. Forwarded IP with port stripped
            var headersWithPort = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", $"{clientIp}:8443, 10.0.0.2" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersWithPort) == clientIp,
                "forwarded IP with port strips port cleanly");

            // 9. IPv6 forwarded IP with brackets and port
            var headersIpv6Port = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "[2001:db8::1]:443" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersIpv6Port) == "2001:db8::1",
                "IPv6 with brackets and port strips port cleanly");

            // 10. IPv6 bracketed candidate WITHOUT port
            var headersIpv6BracketedNoPort = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "[2001:db8::1]" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersIpv6BracketedNoPort) == "2001:db8::1",
                "IPv6 with brackets without port unwraps clean IPv6");

            // 11. IPv6 quoted with port (RFC 7239 style)
            var headersIpv6Quoted = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "\"[2001:db8::1]:8443\"" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersIpv6Quoted) == "2001:db8::1",
                "IPv6 quoted with port unquotes and strips port cleanly");

            // 12. Direct public IPv6 connection without headers
            var publicIpv6 = System.Net.IPAddress.Parse("2001:db8::cafe");
            Check(ResolveRemoteEndPoint(publicIpv6, null) == "2001:db8::cafe",
                "direct public IPv6 connection without headers returns public IPv6");

            // 13. IPv6 ULA local proxy unwraps public IPv6
            var ulaProxy = System.Net.IPAddress.Parse("fd00::1");
            var headersIpv6Client = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "2001:db8::cafe, fd00::1" }
            };
            Check(ResolveRemoteEndPoint(ulaProxy, headersIpv6Client) == "2001:db8::cafe",
                "IPv6 ULA proxy unwraps public IPv6 client");

            // 14. IPv6 Link-Local proxy unwraps public IPv6
            var linkLocalProxy = System.Net.IPAddress.Parse("fe80::1");
            Check(ResolveRemoteEndPoint(linkLocalProxy, headersIpv6Client) == "2001:db8::cafe",
                "IPv6 link-local proxy unwraps public IPv6 client");

            // 15. IPv6 ULA client direct without headers
            var ulaClient = System.Net.IPAddress.Parse("fd00::100");
            Check(ResolveRemoteEndPoint(ulaClient, new Microsoft.AspNetCore.Http.HeaderDictionary()) == "fd00::100",
                "direct IPv6 ULA client without headers preserves ULA IP");

            // 16. Unspecified IPv6 (::) rejected
            var headersUnspecifiedV6 = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "::" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersUnspecifiedV6) == "10.0.0.2",
                "unspecified IPv6 (::) header is rejected and falls back to connection IP");

            // 17. Multicast IPv6 (ff02::1) rejected
            var headersMulticastV6 = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "ff02::1" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersMulticastV6) == "10.0.0.2",
                "multicast IPv6 header is rejected and falls back to connection IP");

            // 18. Unspecified IPv4 (0.0.0.0) rejected
            var headersUnspecifiedV4 = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "0.0.0.0" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersUnspecifiedV4) == "10.0.0.2",
                "unspecified IPv4 (0.0.0.0) header is rejected and falls back to connection IP");

            // 19. Multicast IPv4 (224.0.0.1) rejected
            var headersMulticastV4 = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "224.0.0.1" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersMulticastV4) == "10.0.0.2",
                "multicast IPv4 header is rejected and falls back to connection IP");

            // 20. Malformed or script injection header rejected
            var headersJunk = new Microsoft.AspNetCore.Http.HeaderDictionary
            {
                { "X-Forwarded-For", "<script>alert(1)</script>" }
            };
            Check(ResolveRemoteEndPoint(lanProxy, headersJunk) == "10.0.0.2",
                "malformed header is rejected and falls back to connection IP");

            // 21. Null connection and null headers
            Check(ResolveRemoteEndPoint(null, null) == "",
                "null connection and headers returns empty string");
        }

        Console.WriteLine();
        Console.WriteLine(_fail == 0 ? "ALL CHECKS PASSED" : $"{_fail} CHECK(S) FAILED");
        return _fail == 0 ? 0 : 1;
    }
}
