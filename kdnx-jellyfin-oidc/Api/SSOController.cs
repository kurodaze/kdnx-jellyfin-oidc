using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Database.Implementations.Entities;

using Kdnx.Jellyfin.Oidc.Config;

using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Kdnx.Jellyfin.Oidc.Api;

/// <summary>
/// The sso api controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOController : ControllerBase
{
    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<SSOController> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _memoryCache;
    private static readonly string _assemblyVersion = typeof(SSOController).Assembly.GetName().Version.ToString();

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOController"/> class.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="loggerFactory">The logger factory.</param>
    /// <param name="sessionManager">The session manager.</param>
    /// <param name="userManager">The user manager.</param>
    /// <param name="cryptoProvider">The crypto provider.</param>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="memoryCache">The memory cache.</param>
    public SSOController(
        ILogger<SSOController> logger,
        ILoggerFactory loggerFactory,
        ISessionManager sessionManager,
        IUserManager userManager,
        ICryptoProvider cryptoProvider,
        IHttpClientFactory httpClientFactory,
        IMemoryCache memoryCache)
    {
        _sessionManager = sessionManager;
        _userManager = userManager;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _loggerFactory = loggerFactory;
        _httpClientFactory = httpClientFactory;
        _memoryCache = memoryCache;
    }

    /// <summary>
    /// Handles the OpenID post callback.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="state">The state parameter.</param>
    /// <returns>A <see cref="Task{ActionResult}"/> representing the asynchronous operation.</returns>
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

        string cookieName = "__Host-OidcState";
        if (!Request.Cookies.TryGetValue(cookieName, out var cookieState) || cookieState != state)
        {
            return BadRequest("CSRF check failed. Please ensure cookies are enabled and try again.");
        }

        Response.Cookies.Delete(cookieName, new CookieOptions { Path = "/" });

        if (!_memoryCache.TryGetValue(state, out TimedAuthorizeState timedState))
        {
            return BadRequest("Invalid or expired state");
        }

        try
        {
            var currentState = timedState.State;
            var result = await oidcClient.ProcessResponseAsync(Request.QueryString.Value, currentState).ConfigureAwait(false);

            if (result.IsError)
            {
                _logger.LogWarning("OIDC login error for provider {Provider}: {Error} - {Description}", SanitizeLogInput(provider), SanitizeLogInput(result.Error), SanitizeLogInput(result.ErrorDescription));
                return ReturnError(StatusCodes.Status400BadRequest, "Authentication failed. Please try again.");
            }

            var usernameClaim = result.User.FindFirst("preferred_username")
                             ?? result.User.FindFirst("name")
                             ?? result.User.FindFirst("sub");

            if (usernameClaim != null)
            {
                timedState.Username = usernameClaim.Value;
                timedState.SubClaim = result.User.FindFirst("sub")?.Value;
                timedState.Valid = true;
            }

            if (timedState.Valid)
            {
                string newToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                var cacheOptions = new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromMinutes(10));
                _memoryCache.Set(newToken, timedState, cacheOptions);

                string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                Response.Headers.Append("Content-Security-Policy", $"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; frame-src 'self'; connect-src 'self'; base-uri 'none';");
                Response.Headers.Append("X-Content-Type-Options", "nosniff");
                Response.Headers.Append("X-Frame-Options", "SAMEORIGIN");

                return Content(WebResponse.Generator(data: newToken, provider: provider, pathBase: Request.PathBase.ToString(), mode: "OID", nonce: nonce), MediaTypeNames.Text.Html);
            }
            else
            {
                _logger.LogWarning("OpenID user {Username} missing username claim.", timedState.Username);
                return ReturnError(StatusCodes.Status401Unauthorized, "Error. Missing username claim.");
            }
        }
        finally
        {
            _memoryCache.Remove(state);
        }
    }

    /// <summary>
    /// Starts the OpenID challenge.
    /// </summary>
    /// <param name="provider">The provider.</param>
    /// <returns>A <see cref="Task{ActionResult}"/> representing the asynchronous operation.</returns>
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
            _logger.LogWarning("OIDC prepare login error for provider {Provider}: {Error} - {Description}", SanitizeLogInput(provider), SanitizeLogInput(state.Error), SanitizeLogInput(state.ErrorDescription));
            return ReturnError(StatusCodes.Status400BadRequest, "Unable to start login. Please try again.");
        }

        var requestBase = GetRequestBase();
        var dummyRedirectUri = $"https://___OIDC_DUMMY_REDIRECT___/sso/OID/redirect/{provider}";
        var actualRedirectUri = requestBase + $"/sso/OID/redirect/{provider}";
        state.StartUrl = state.StartUrl.Replace(Uri.EscapeDataString(dummyRedirectUri), Uri.EscapeDataString(actualRedirectUri));
        state.RedirectUri = actualRedirectUri;

        string cookieName = "__Host-OidcState";
        Response.Cookies.Append(cookieName, state.State, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            MaxAge = TimeSpan.FromMinutes(10),
            Path = "/"
        });

        var cacheOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromMinutes(10));
        _memoryCache.Set(state.State, new TimedAuthorizeState(state), cacheOptions);

        if (!Uri.TryCreate(state.StartUrl, UriKind.Absolute, out Uri startUri) ||
            !Uri.TryCreate(config.OidEndpoint, UriKind.Absolute, out Uri authorityUri) ||
            startUri.Host != authorityUri.Host)
        {
            _logger.LogWarning("OIDC redirect URL host validation failed for provider {Provider}", SanitizeLogInput(provider));
            return ReturnError(StatusCodes.Status400BadRequest, "Invalid redirect URL generated.");
        }

        return Redirect(state.StartUrl);
    }

    private string SanitizeLogInput(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        return input.Replace(Environment.NewLine, "").Replace("\n", "").Replace("\r", "");
    }

    /// <summary>
    /// Gets the names of all registered OpenID providers.
    /// </summary>
    /// <returns>An <see cref="ActionResult"/> containing the provider names.</returns>
    [HttpGet("OID/GetNames")]
    public ActionResult OidProviderNames()
    {
        return Ok(KdnxOidcPlugin.Instance.Configuration.OidConfigs.Select(x => x.ProviderName));
    }

    /// <summary>
    /// Authenticates a user with a provider callback.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="response">The authentication response details.</param>
    /// <returns>A <see cref="Task{ActionResult}"/> representing the asynchronous operation.</returns>
    [HttpPost("OID/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidAuth(string provider, [FromBody] AuthResponse response)
    {
        OidConfig config = KdnxOidcPlugin.Instance.Configuration.OidConfigs.FirstOrDefault(x => string.Equals(x.ProviderName, provider, StringComparison.OrdinalIgnoreCase));
        if (config == null || !config.Enabled)
        {
            return BadRequest("No matching provider found or provider disabled");
        }

        if (string.IsNullOrEmpty(response?.Data))
        {
            return BadRequest("Missing authentication data");
        }

        if (_memoryCache.TryGetValue(response.Data, out TimedAuthorizeState timedState))
        {
            try
            {
                if (timedState.Valid)
                {
                    Guid? userId = await GetOrCreateUser(timedState.Username, timedState.SubClaim, config).ConfigureAwait(false);
                    if (userId == null)
                    {
                        return ReturnError(StatusCodes.Status401Unauthorized, "Account linking to administrator accounts is disabled.");
                    }

                    var authenticationResult = await Authenticate(userId.Value, response).ConfigureAwait(false);
                    return Ok(authenticationResult);
                }
            }
            finally
            {
                _memoryCache.Remove(response.Data);
            }
        }

        return Problem("Something went wrong");
    }

    private async Task<Guid?> GetOrCreateUser(string canonicalName, string subClaim, OidConfig config)
    {
        var pluginConfig = KdnxOidcPlugin.Instance.Configuration;
        User user = null;

        if (!string.IsNullOrEmpty(subClaim) && pluginConfig.UserMappings != null)
        {
            var mapping = pluginConfig.UserMappings.FirstOrDefault(m => m.SubClaim == subClaim);
            if (mapping != null)
            {
                user = _userManager.GetUserById(mapping.UserId);
                if (user != null && user.Username != canonicalName && _userManager.GetUserByName(canonicalName) == null)
                {
                    _logger.LogInformation("Updating username for {SubClaim} from {OldName} to {NewName}", subClaim, user.Username, canonicalName);
                    user.Username = canonicalName;
                    await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                }
            }
        }

        if (user == null)
        {
            user = _userManager.GetUserByName(canonicalName);

            if (user != null)
            {
                // Username is taken. Discord IDs are used for identity, don't link by name.
                // Generate a new, unique username by appending a number.
                int counter = 1;
                string newName = $"{canonicalName}{counter}";
                while (_userManager.GetUserByName(newName) != null)
                {
                    counter++;
                    newName = $"{canonicalName}{counter}";
                }

                _logger.LogInformation("Username {OriginalName} is already taken. Generated new username {NewName} for Discord ID {SubClaim}", canonicalName, newName, subClaim);
                canonicalName = newName;
                user = null;
            }

            if (user == null)
            {
                _logger.LogInformation("OIDC user {CanonicalName} doesn't exist, creating...", canonicalName);
                user = await _userManager.CreateUserAsync(canonicalName).ConfigureAwait(false);
                user.AuthenticationProviderId = GetType().FullName;
                user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();
                await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            }

            if (!string.IsNullOrEmpty(subClaim))
            {
                if (pluginConfig.UserMappings == null)
                {
                    pluginConfig.UserMappings = new List<UserMapping>();
                }

                var mapping = pluginConfig.UserMappings.FirstOrDefault(m => m.SubClaim == subClaim);
                if (mapping == null)
                {
                    pluginConfig.UserMappings.Add(new UserMapping { SubClaim = subClaim, UserId = user.Id });
                    KdnxOidcPlugin.Instance.SaveConfiguration();
                }
            }
        }

        return user.Id;
    }

    private async Task<AuthenticationResult> Authenticate(Guid userId, AuthResponse authResponse)
    {
        User user = _userManager.GetUserById(userId);

        var authRequest = new AuthenticationRequest
        {
            UserId = user.Id,
            Username = user.Username,
            App = authResponse.AppName,
            AppVersion = authResponse.AppVersion,
            DeviceId = authResponse.DeviceID,
            DeviceName = authResponse.DeviceName
        };

        _logger.LogInformation("Auth request created...");
        return await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);
    }

    private ActionResult GetOidcClient(string provider, out OidConfig config, out OidcClient oidcClient)
    {
        config = KdnxOidcPlugin.Instance.Configuration.OidConfigs.FirstOrDefault(x => string.Equals(x.ProviderName, provider, StringComparison.OrdinalIgnoreCase));
        oidcClient = null;

        if (config == null || !config.Enabled)
        {
            return BadRequest("No matching provider found or provider disabled");
        }

        var endpoint = config.OidEndpoint?.Trim();
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri oidEndpointUri))
        {
            return ReturnError(StatusCodes.Status500InternalServerError, "Invalid OIDC Endpoint configured.");
        }

        var cacheKey = $"oidcclient_{provider}";
        var capturedConfig = config;
        oidcClient = _memoryCache.GetOrCreate(cacheKey, entry =>
        {
            entry.SetSlidingExpiration(TimeSpan.FromMinutes(15));
            return CreateOidcClient(capturedConfig, oidEndpointUri, provider, "https://___OIDC_DUMMY_REDIRECT___");
        });

        return null;
    }

    private string GetRequestBase()
    {
        var request = Request;
        var scheme = request.Headers["X-Forwarded-Proto"].FirstOrDefault() ?? request.Scheme;
        var host = request.Headers["X-Forwarded-Host"].FirstOrDefault() ?? request.Host.ToString();
        var pathBase = request.PathBase.ToString();
        
        return $"{scheme}://{host}{pathBase}".TrimEnd('/');
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

    private OidcClient CreateOidcClient(OidConfig config, Uri oidEndpointUri, string provider, string requestBase)
    {
        var scopes = config.OidScopes ?? Array.Empty<string>();
        var options = new OidcClientOptions
        {
            Authority = config.OidEndpoint?.Trim(),
            ClientId = config.OidClientId?.Trim(),
            RedirectUri = requestBase + $"/sso/OID/redirect/{provider}",
            Scope = string.Join(" ", scopes.Prepend("openid profile")),
            DisablePushedAuthorization = false,
            LoggerFactory = _loggerFactory,
            LoadProfile = true,
            HttpClientFactory = o =>
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.UserAgent.ParseAdd($"kdnx-jellyfin-oidc +{_assemblyVersion} (https://github.com/kdnx-jellyfin-oidc)");
                return client;
            }
        };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(oidEndpointUri.GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.ValidateEndpoints = true;
        options.Policy.Discovery.RequireHttps = true;
        options.Policy.Discovery.ValidateIssuerName = true;
        return new OidcClient(options);
    }
}

/// <summary>
/// Represents the authentication response parameters from the client.
/// </summary>
public class AuthResponse
{
    /// <summary>
    /// Gets or sets the device ID.
    /// </summary>
    public string DeviceID { get; set; }

    /// <summary>
    /// Gets or sets the name of the device.
    /// </summary>
    public string DeviceName { get; set; }

    /// <summary>
    /// Gets or sets the name of the application.
    /// </summary>
    public string AppName { get; set; }

    /// <summary>
    /// Gets or sets the application version.
    /// </summary>
    public string AppVersion { get; set; }

    /// <summary>
    /// Gets or sets the authentication data payload.
    /// </summary>
    public string Data { get; set; }
}

/// <summary>
/// Represents the state of an active OpenID authorization flow with timestamp tracking.
/// </summary>
public class TimedAuthorizeState
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TimedAuthorizeState"/> class.
    /// </summary>
    /// <param name="state">The authorization state.</param>
    public TimedAuthorizeState(AuthorizeState state)
    {
        State = state;
        Valid = false;
    }

    /// <summary>
    /// Gets or sets the OIDC client authorization state.
    /// </summary>
    public AuthorizeState State { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this state is valid.
    /// </summary>
    public bool Valid { get; set; }

    /// <summary>
    /// Gets or sets the resolved username.
    /// </summary>
    public string Username { get; set; }

    /// <summary>
    /// Gets or sets the original subject claim (e.g. Discord ID).
    /// </summary>
    public string SubClaim { get; set; }
}
