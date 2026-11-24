using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Database.Implementations.Entities;
using Kdnx.Jellyfin.Oidc.Config;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Kdnx.Jellyfin.Oidc.Api;

[ApiController]
[Route("[controller]")]
public class SSOController : ControllerBase
{
    private const string StateCookieName = "__Host-OidcState";
    private const int MaxClientMetaLength = 256;

    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<SSOController> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly SsoFlowCache _memoryCache;
    private static readonly string _assemblyVersion = typeof(SSOController).Assembly.GetName().Version?.ToString() ?? "0.0.0.0";

    // One account lookup at a time: the sub → user mappings are a plain List in the
    // plugin config, and two first logins for one sub would each create a user.
    private static readonly SemaphoreSlim _userLock = new(1, 1);

    // Kept separate from SsoFlowCache so unauthenticated /OID/start floods cannot
    // evict OIDC discovery/JWKS and amplify requests into KDNX's auth rate limit.
    private static readonly object _oidcClientLock = new();
    private static readonly Dictionary<string, (string CacheKey, OidcClient Client)> _oidcClients = new(StringComparer.OrdinalIgnoreCase);

    public SSOController(
        ILogger<SSOController> logger,
        ILoggerFactory loggerFactory,
        ISessionManager sessionManager,
        IUserManager userManager,
        ICryptoProvider cryptoProvider,
        IHttpClientFactory httpClientFactory,
        SsoFlowCache memoryCache)
    {
        _sessionManager = sessionManager;
        _userManager = userManager;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _loggerFactory = loggerFactory;
        _httpClientFactory = httpClientFactory;
        _memoryCache = memoryCache;
    }

    [HttpGet("OID/redirect/{provider}")]
    public async Task<ActionResult> OidRedirect(
        [FromRoute] string provider,
        [FromQuery] string state)
    {
        var errorResult = GetOidcClient(provider, out var config, out var oidcClient);
        if (errorResult != null)
        {
            return errorResult;
        }

        if (string.IsNullOrEmpty(state))
        {
            return BadRequest("Missing state");
        }

        if (!Request.Cookies.TryGetValue(StateCookieName, out var cookieState)
            || !FixedTimeEqualsString(cookieState, state))
        {
            return BadRequest("CSRF check failed. Please ensure cookies are enabled and try again.");
        }

        // __Host- cookies require Secure + Path=/ on set and delete (MDN cookie prefixes).
        Response.Cookies.Delete(StateCookieName, new CookieOptions
        {
            Path = "/",
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax
        });

        // Prefixed: `state` is caller-supplied and must not address another entry.
        // Remove and consume atomically before awaiting so concurrent callbacks cannot race.
        var stateKey = $"oidcstate_{state}";
        if (!_memoryCache.TryGetValue(stateKey, out PendingAuthorizeState pendingState))
        {
            return BadRequest("Invalid or expired state");
        }

        _memoryCache.Remove(stateKey);
        if (!pendingState.TryConsume())
        {
            return BadRequest("Invalid or expired state");
        }

        var result = await oidcClient.ProcessResponseAsync(Request.QueryString.Value, pendingState.State).ConfigureAwait(false);

        if (result.IsError)
        {
            _logger.LogWarning("OIDC login error for provider {Provider}: {Error} - {Description}", SanitizeLogInput(config.ProviderName), SanitizeLogInput(result.Error), SanitizeLogInput(result.ErrorDescription));
            return ReturnError(StatusCodes.Status400BadRequest, "Authentication failed. Please try again.");
        }

        var usernameClaim = result.User.FindFirst("preferred_username")
                         ?? result.User.FindFirst("name")
                         ?? result.User.FindFirst("sub");

        if (usernameClaim == null || string.IsNullOrWhiteSpace(usernameClaim.Value))
        {
            _logger.LogWarning("OpenID login for provider {Provider} is missing a username claim.", SanitizeLogInput(config.ProviderName));
            return ReturnError(StatusCodes.Status401Unauthorized, "Error. Missing username claim.");
        }

        var username = usernameClaim.Value;
        var subClaim = result.User.FindFirst("sub")?.Value;

        // Require IdP session claims from the identity token (KDNX always issues them).
        if (!TryGetSessionClaims(result.IdentityToken, out var authTime, out var sessionMaxAge)
            || SsoSessionRegistry.ComputeExpiresAt(authTime, sessionMaxAge) is not long expiresAt)
        {
            _logger.LogWarning(
                "KDNX OIDC login missing required auth_time/session_max_age claims for {Username}",
                SanitizeLogInput(username));
            return ReturnError(
                StatusCodes.Status400BadRequest,
                "Identity provider did not return session lifetime claims.");
        }

        if (expiresAt <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            _logger.LogWarning(
                "KDNX OIDC login rejected with already-expired session for {Username}: auth_time={AuthTime} session_max_age={MaxAge}s",
                SanitizeLogInput(username),
                authTime,
                sessionMaxAge);
            return ReturnError(
                StatusCodes.Status401Unauthorized,
                "Identity provider session has already expired. Please sign in again.");
        }

        _logger.LogInformation(
            "KDNX OIDC session for {Username}: auth_time={AuthTime} session_max_age={MaxAge}s expires_at={Expires}",
            SanitizeLogInput(username),
            authTime,
            sessionMaxAge,
            expiresAt);

        string newToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var cacheOptions = new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromMinutes(10)).SetSize(1);
        _memoryCache.Set($"oidcauth_{newToken}", new PendingAuth(username, subClaim, expiresAt), cacheOptions);

        // Assigned, not appended: a second CSP header would intersect with this one.
        string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        Response.Headers.ContentSecurityPolicy = $"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; frame-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';";
        Response.Headers.XContentTypeOptions = "nosniff";
        Response.Headers.XFrameOptions = "DENY";
        Response.Headers["Referrer-Policy"] = "no-referrer";

        // Body carries a single-use credential (RFC 6749 5.1).
        Response.Headers.CacheControl = "no-store";

        var canonicalProvider = config.ProviderName.Trim();
        return Content(WebResponse.Generator(data: newToken, provider: canonicalProvider, pathBase: Request.PathBase.ToString(), nonce: nonce), MediaTypeNames.Text.Html);
    }

    [HttpGet("OID/start/{provider}")]
    public async Task<ActionResult> OidChallenge(string provider)
    {
        var errorResult = GetOidcClient(provider, out var config, out var oidcClient);
        if (errorResult != null)
        {
            return errorResult;
        }

        var state = await oidcClient.PrepareLoginAsync().ConfigureAwait(false);

        if (state.IsError)
        {
            _logger.LogWarning("OIDC prepare login error for provider {Provider}: {Error} - {Description}", SanitizeLogInput(config.ProviderName), SanitizeLogInput(state.Error), SanitizeLogInput(state.ErrorDescription));
            return ReturnError(StatusCodes.Status400BadRequest, "Unable to start login. Please try again.");
        }

        if (!Uri.TryCreate(state.StartUrl, UriKind.Absolute, out Uri startUri)
            || !Uri.TryCreate(config.OidEndpoint?.Trim(), UriKind.Absolute, out Uri authorityUri)
            || startUri.Scheme != Uri.UriSchemeHttps
            || startUri.Host != authorityUri.Host
            || startUri.Port != authorityUri.Port
            || !string.IsNullOrEmpty(startUri.UserInfo))
        {
            _logger.LogWarning("OIDC redirect URL host validation failed for provider {Provider}", SanitizeLogInput(config.ProviderName));
            return ReturnError(StatusCodes.Status400BadRequest, "Invalid redirect URL generated.");
        }

        Response.Cookies.Append(StateCookieName, state.State, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            MaxAge = TimeSpan.FromMinutes(10),
            Path = "/"
        });

        var cacheOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromMinutes(10))
            .SetSize(1);
        _memoryCache.Set($"oidcstate_{state.State}", new PendingAuthorizeState(state), cacheOptions);

        Response.Headers.CacheControl = "no-store";
        return Redirect(state.StartUrl);
    }

    // Single sanitized return path, so callers cannot receive the value unchanged.
    // ReplaceLineEndings covers CR, LF, CRLF, FF, NEL and the Unicode line and
    // paragraph separators. Vertical tab is not a newline and is left alone.
    private static string SanitizeLogInput(string input) => input?.ReplaceLineEndings(string.Empty);

    private static bool FixedTimeEqualsString(string a, string b)
    {
        if (a == null || b == null)
        {
            return false;
        }

        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    private static bool IsValidClientMeta(string value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaxClientMetaLength;

    [HttpPost("OID/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidAuth(string provider, [FromBody] AuthResponse response)
    {
        if (FindProvider(provider) == null)
        {
            return BadRequest("No matching provider found or provider disabled");
        }

        if (string.IsNullOrEmpty(response?.Data))
        {
            return BadRequest("Missing authentication data");
        }

        if (!IsValidClientMeta(response.DeviceID)
            || !IsValidClientMeta(response.DeviceName)
            || !IsValidClientMeta(response.AppName)
            || !IsValidClientMeta(response.AppVersion))
        {
            return BadRequest("Missing or invalid client metadata");
        }

        var authKey = $"oidcauth_{response.Data}";
        if (!_memoryCache.TryGetValue(authKey, out PendingAuth pending))
        {
            return BadRequest("Invalid or expired authentication data");
        }

        // Remove and consume atomically before awaiting so concurrent POSTs cannot double-mint tokens.
        _memoryCache.Remove(authKey);
        if (!pending.TryConsume())
        {
            return BadRequest("Invalid or expired authentication data");
        }

        User user;
        await _userLock.WaitAsync().ConfigureAwait(false);
        try
        {
            user = await GetOrCreateUser(pending.Username, pending.SubClaim).ConfigureAwait(false);
        }
        finally
        {
            _userLock.Release();
        }

        var authenticationResult = await Authenticate(user, response).ConfigureAwait(false);
        SsoSessionRegistry.Register(authenticationResult.AccessToken, pending.SessionExpiresAtUnix);

        // Response carries a live Jellyfin bearer token (RFC 6749 5.1).
        Response.Headers.CacheControl = "no-store";

        // Only the fields the callback page reads.
        return Ok(new { authenticationResult.User, authenticationResult.AccessToken });
    }

    private async Task<User> GetOrCreateUser(string canonicalName, string subClaim)
    {
        var pluginConfig = KdnxOidcPlugin.Instance.Configuration;
        User user = null;

        // Identity is the OIDC `sub`, never username alone.
        if (!string.IsNullOrEmpty(subClaim) && pluginConfig.UserMappings != null)
        {
            var mapping = pluginConfig.UserMappings.FirstOrDefault(m => m.SubClaim == subClaim);
            if (mapping != null)
            {
                user = _userManager.GetUserById(mapping.UserId);
                if (user != null && user.Username != canonicalName)
                {
                    var existingUser = _userManager.GetUserByName(canonicalName);
                    if (existingUser == null || existingUser.Id == user.Id)
                    {
                        _logger.LogInformation("Updating username for {SubClaim} from {OldName} to {NewName}", SanitizeLogInput(subClaim), SanitizeLogInput(user.Username), SanitizeLogInput(canonicalName));
                        user.Username = canonicalName;
                        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                    }
                }
            }
        }

        if (user == null)
        {
            if (_userManager.GetUserByName(canonicalName) != null)
            {
                // Username taken by an unrelated account — do not link by name.
                int counter = 1;
                string newName = $"{canonicalName}{counter}";
                while (_userManager.GetUserByName(newName) != null)
                {
                    counter++;
                    newName = $"{canonicalName}{counter}";
                }

                _logger.LogInformation("Username {OriginalName} is already taken. Generated new username {NewName} for sub {SubClaim}", SanitizeLogInput(canonicalName), SanitizeLogInput(newName), SanitizeLogInput(subClaim));
                canonicalName = newName;
            }

            _logger.LogInformation("OIDC user {CanonicalName} doesn't exist, creating...", SanitizeLogInput(canonicalName));
            user = await _userManager.CreateUserAsync(canonicalName).ConfigureAwait(false);
            user.AuthenticationProviderId = GetType().FullName;
            user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();
            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

            // Persist or heal sub → user mapping (covers first login and deleted-user remaps).
            if (!string.IsNullOrEmpty(subClaim))
            {
                pluginConfig.UserMappings ??= new List<UserMapping>();
                var mapping = pluginConfig.UserMappings.FirstOrDefault(m => m.SubClaim == subClaim);
                if (mapping == null)
                {
                    pluginConfig.UserMappings.Add(new UserMapping { SubClaim = subClaim, UserId = user.Id });
                    KdnxOidcPlugin.Instance.SaveConfiguration();
                }
                else if (mapping.UserId != user.Id)
                {
                    _logger.LogInformation(
                        "Updating stale user mapping for {SubClaim}: {OldUserId} -> {NewUserId}",
                        SanitizeLogInput(subClaim),
                        mapping.UserId,
                        user.Id);
                    mapping.UserId = user.Id;
                    KdnxOidcPlugin.Instance.SaveConfiguration();
                }
            }
        }

        return user;
    }

    private async Task<AuthenticationResult> Authenticate(User user, AuthResponse authResponse)
    {
        var authRequest = new AuthenticationRequest
        {
            UserId = user.Id,
            Username = user.Username,
            App = authResponse.AppName,
            AppVersion = authResponse.AppVersion,
            DeviceId = authResponse.DeviceID,
            DeviceName = authResponse.DeviceName,
            // As Jellyfin's own logins record it: forwarding headers count only from
            // Dashboard -> Networking -> Known proxies (the KDNX connector's address).
            RemoteEndPoint = HttpContext.GetNormalizedRemoteIP().ToString()
        };

        return await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);
    }

    // Reads required session policy claims from the KDNX identity token.
    private static bool TryGetSessionClaims(string identityToken, out long authTime, out long sessionMaxAge)
    {
        authTime = 0;
        sessionMaxAge = 0;
        if (string.IsNullOrEmpty(identityToken))
        {
            return false;
        }

        try
        {
            var parts = identityToken.Split('.');
            if (parts.Length < 2)
            {
                return false;
            }

            var json = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[1]));
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("auth_time", out var at) || at.ValueKind != JsonValueKind.Number || !at.TryGetInt64(out authTime) || authTime <= 0)
            {
                return false;
            }

            if (!root.TryGetProperty("session_max_age", out var sma) || sma.ValueKind != JsonValueKind.Number || !sma.TryGetInt64(out sessionMaxAge) || sessionMaxAge <= 0)
            {
                return false;
            }

            return true;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    private static OidConfig FindProvider(string provider)
    {
        var normalized = provider?.Trim();
        if (string.IsNullOrEmpty(normalized))
        {
            return null;
        }

        return KdnxOidcPlugin.Instance?.Configuration?.OidConfigs?.FirstOrDefault(
            x => x.Enabled && string.Equals(x.ProviderName?.Trim(), normalized, StringComparison.OrdinalIgnoreCase));
    }

    private ActionResult GetOidcClient(string provider, out OidConfig config, out OidcClient oidcClient)
    {
        config = FindProvider(provider);
        oidcClient = null;

        if (config == null)
        {
            return BadRequest("No matching provider found or provider disabled");
        }

        var endpoint = config.OidEndpoint?.Trim();
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri oidEndpointUri)
            || oidEndpointUri.Scheme != Uri.UriSchemeHttps)
        {
            return ReturnError(StatusCodes.Status500InternalServerError, "OIDC Endpoint must be an absolute https URL.");
        }

        // redirect_uri must match KDNX registration. Client ID is the public FQDN
        // (fin.example.com) — never take Host / X-Forwarded-Host from the request.
        if (!TryGetOidcRedirectUri(config, out var redirectUri, out var redirectError))
        {
            return ReturnError(StatusCodes.Status500InternalServerError, redirectError);
        }

        var providerName = config.ProviderName.Trim();
        var cacheKey = $"{providerName}|{endpoint}|{config.OidClientId?.Trim()}";
        lock (_oidcClientLock)
        {
            if (!_oidcClients.TryGetValue(providerName, out var cached) || cached.CacheKey != cacheKey)
            {
                cached = (cacheKey, CreateOidcClient(config, redirectUri));
                _oidcClients[providerName] = cached;
            }

            oidcClient = cached.Client;
        }

        return null;
    }

    // KDNX expects https://{client_id}/sso/OID/redirect/{ProviderName} and compares it
    // byte-for-byte against its own lowercase host, so normalize rather than echo
    // the casing the request URL happened to carry.
    private static bool TryGetOidcRedirectUri(OidConfig config, out string redirectUri, out string error)
    {
        redirectUri = null;
        error = null;

        var clientId = config.OidClientId?.Trim();
        if (string.IsNullOrEmpty(clientId))
        {
            error = "OIDC Client ID is not configured.";
            return false;
        }

        // Must be a bare hostname (no scheme/path). Matches KDNX resource FQDN.
        if (clientId.Contains("://", StringComparison.Ordinal)
            || clientId.Contains('/')
            || clientId.Contains('\\')
            || clientId.Contains(' ')
            || clientId.Contains('?')
            || clientId.Contains('#'))
        {
            error = "OIDC Client ID must be the public hostname only (e.g. fin.example.com).";
            return false;
        }

        var providerName = config.ProviderName?.Trim();
        if (string.IsNullOrEmpty(providerName)
            || providerName.Contains('/')
            || providerName.Contains('\\')
            || providerName.Contains(' ')
            || providerName.Contains('?')
            || providerName.Contains('#'))
        {
            error = "OIDC Provider Name must be a valid, single URL-safe identifier.";
            return false;
        }

        redirectUri = $"https://{clientId.TrimEnd('.').ToLowerInvariant()}/sso/OID/redirect/{providerName}";
        return true;
    }

    private ContentResult ReturnError(int code, string message)
    {
        return new ContentResult
        {
            Content = message,
            ContentType = MediaTypeNames.Text.Plain,
            StatusCode = code
        };
    }

    private OidcClient CreateOidcClient(OidConfig config, string redirectUri)
    {
        // KDNX issues openid + profile only, and embeds sub/preferred_username/name
        // directly in the ID token; LoadProfile = false skips a redundant /userinfo
        // call, and RefreshDiscoveryDocumentForLogin = false caches discovery/JWKS so
        // /OID/start makes zero outbound calls and /OID/redirect makes only POST /token.
        var options = new OidcClientOptions
        {
            Authority = config.OidEndpoint?.Trim(),
            ClientId = config.OidClientId?.Trim(),
            RedirectUri = redirectUri,
            Scope = "openid profile",
            LoggerFactory = _loggerFactory,
            LoadProfile = false,
            RefreshDiscoveryDocumentForLogin = false,
            HttpClientFactory = o =>
            {
                var client = _httpClientFactory.CreateClient();
                client.Timeout = TimeSpan.FromSeconds(15);
                client.DefaultRequestHeaders.UserAgent.ParseAdd($"kdnx-jellyfin-oidc +{_assemblyVersion} (https://github.com/kurodaze/kdnx-jellyfin-oidc)");
                return client;
            }
        };

        // KDNX signs with EdDSA only (discovery advertises ["EdDSA"]).
        // OidcClient v6 defaults to NoValidationIdentityTokenValidator, relying on direct
        // backchannel TLS to the token endpoint per OIDC Core §3.1.3.7 (Auth Code + PKCE).
        options.Policy.ValidSignatureAlgorithms.Clear();
        options.Policy.ValidSignatureAlgorithms.Add("EdDSA");

        // Already Duende defaults; pinned so a library change can't relax them.
        options.Policy.Discovery.ValidateEndpoints = true;
        options.Policy.Discovery.RequireHttps = true;
        options.Policy.Discovery.ValidateIssuerName = true;
        return new OidcClient(options);
    }
}

/// <summary>Client details posted by the callback page to redeem a one-time Data token.</summary>
public class AuthResponse
{
    public string DeviceID { get; set; }

    public string DeviceName { get; set; }

    public string AppName { get; set; }

    public string AppVersion { get; set; }

    public string Data { get; set; }
}

/// <summary>An in-flight authorization, from /OID/start until /OID/redirect consumes it once.</summary>
internal sealed class PendingAuthorizeState
{
    private int _consumed;

    public PendingAuthorizeState(AuthorizeState state)
    {
        State = state;
    }

    public AuthorizeState State { get; }

    public bool TryConsume() => Interlocked.Exchange(ref _consumed, 1) == 0;
}

/// <summary>A completed OIDC login waiting for /OID/Auth to redeem it once.</summary>
internal sealed class PendingAuth
{
    private int _consumed;

    public PendingAuth(string username, string subClaim, long sessionExpiresAtUnix)
    {
        Username = username;
        SubClaim = subClaim;
        SessionExpiresAtUnix = sessionExpiresAtUnix;
    }

    public string Username { get; }

    public string SubClaim { get; }

    /// <summary>Absolute Unix time when the KDNX OIDC session must re-authenticate.</summary>
    public long SessionExpiresAtUnix { get; }

    public bool TryConsume() => Interlocked.Exchange(ref _consumed, 1) == 0;
}
