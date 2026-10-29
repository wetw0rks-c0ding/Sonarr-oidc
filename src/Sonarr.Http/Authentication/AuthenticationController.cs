using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using NLog;
using NzbDrone.Common.EnvironmentInfo;
using NzbDrone.Common.Extensions;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;

namespace Sonarr.Http.Authentication
{
    public record OidcExchangeRequest([property: JsonPropertyName("subject_token")] string SubjectToken, [property: JsonPropertyName("subjectToken")] string SubjectTokenCamel = null)
    {
        public string ResolvedSubjectToken => string.IsNullOrWhiteSpace(SubjectToken) ? SubjectTokenCamel : SubjectToken;
    }

    [AllowAnonymous]
    [ApiController]
    public class AuthenticationController : Controller
    {
        private readonly IAuthenticationService _authService;
        private readonly IConfigFileProvider _configFileProvider;
        private readonly IAppFolderInfo _appFolderInfo;
        private readonly Logger _logger;

        public AuthenticationController(IAuthenticationService authService, IConfigFileProvider configFileProvider, IAppFolderInfo appFolderInfo, Logger logger)
        {
            _authService = authService;
            _configFileProvider = configFileProvider;
            _appFolderInfo = appFolderInfo;
            _logger = logger;
        }

        [HttpGet("login/sso")]
        [ProducesResponseType(StatusCodes.Status302Found)]
        public Results<RedirectHttpResult, ChallengeHttpResult> LoginSso([FromQuery] string returnUrl = null, [FromQuery] bool rememberMe = false)
        {
            if (_configFileProvider.AuthenticationMethod != AuthenticationType.Oidc)
            {
                return TypedResults.Redirect(_configFileProvider.UrlBase + "/login");
            }

            if (!_configFileProvider.IsOidcConfigured())
            {
                _logger.Error("OIDC authentication is enabled, but Authority, Client ID, Client Secret, User and Scopes are not all configured");

                return TypedResults.Redirect(_configFileProvider.UrlBase + "/login");
            }

            return TypedResults.Challenge(
                new AuthenticationProperties
                {
                    RedirectUri = GetRedirectUrl(returnUrl),
                    IsPersistent = rememberMe
                },
                [nameof(AuthenticationType.Oidc)]);
        }

        [HttpPost("login")]
        [ProducesResponseType(StatusCodes.Status302Found)]
        [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized, "application/json")]
        public async Task<Results<RedirectHttpResult, UnauthorizedHttpResult>> Login([FromForm] LoginResource resource, [FromQuery] string returnUrl = null)
        {
            var user = _authService.Login(HttpContext.Request, resource.Username, resource.Password);

            if (user == null)
            {
                var lockoutEndTime = _authService.GetLockoutEndTime(HttpContext.Request);

                if (lockoutEndTime.HasValue)
                {
                    var lockoutUntil = new DateTimeOffset(lockoutEndTime.Value, TimeSpan.Zero).ToUnixTimeMilliseconds();

                    return TypedResults.Redirect($"~/login?returnUrl={returnUrl}&loginFailed=true&lockoutUntil={lockoutUntil}");
                }

                return TypedResults.Redirect($"~/login?returnUrl={returnUrl}&loginFailed=true");
            }

            var claims = new List<Claim>
            {
                new Claim("user", user.Username),
                new Claim("identifier", user.Identifier.ToString()),
                new Claim("AuthType", AuthenticationType.Forms.ToString())
            };

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = resource.RememberMe
            };

            try
            {
                await HttpContext.SignInAsync(AuthenticationType.Forms.ToString(), new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies", "user", "identifier")), authProperties);
            }
            catch (CryptographicException e)
            {
                if (e.InnerException is XmlException)
                {
                    _logger.Error(e, "Failed to authenticate user due to corrupt XML. Please remove all XML files from {0} and restart Sonarr", Path.Combine(_appFolderInfo.AppDataFolder, "asp"));
                }
                else
                {
                    _logger.Error(e, "Failed to authenticate user. {0}", e.Message);
                }

                return TypedResults.Unauthorized();
            }

            return TypedResults.Redirect(GetRedirectUrl(returnUrl));
        }

        [HttpPost("reset-password/request")]
        [ProducesResponseType(StatusCodes.Status302Found)]
        public RedirectHttpResult RequestPasswordReset()
        {
            var token = _authService.RequestPasswordReset(HttpContext.Request);

            if (token == null)
            {
                return TypedResults.Redirect("~/login?resetPassword=true&tokenSent=true&tokenUnavailable=true");
            }

            return TypedResults.Redirect("~/login?resetPassword=true&tokenSent=true");
        }

        [HttpPost("reset-password")]
        [ProducesResponseType(StatusCodes.Status302Found)]
        public RedirectHttpResult ResetPassword([FromForm] ResetPasswordResource resource)
        {
            if (resource.Username.IsNullOrWhiteSpace() ||
                resource.Password.IsNullOrWhiteSpace() ||
                resource.Password != resource.PasswordConfirmation)
            {
                return TypedResults.Redirect("~/login?resetPassword=true&tokenSent=true&resetInvalid=true");
            }

            if (!_authService.ResetPassword(HttpContext.Request, resource.Token, resource.Username, resource.Password))
            {
                return TypedResults.Redirect("~/login?resetPassword=true&tokenSent=true&resetFailed=true");
            }

            return TypedResults.Redirect("~/login?passwordReset=true");
        }

        [HttpGet("logout")]
        [ProducesResponseType(StatusCodes.Status302Found)]
        public async Task<Results<RedirectHttpResult, EmptyHttpResult>> Logout()
        {
            _authService.Logout(HttpContext);

            if (_configFileProvider.EffectiveAuthenticationMethod() == AuthenticationType.Oidc)
            {
                var loggedOutUrl = _configFileProvider.UrlBase + "/loggedout";
                var signedOut = false;

                try
                {
                    await HttpContext.SignOutAsync(nameof(AuthenticationType.Oidc), new AuthenticationProperties { RedirectUri = loggedOutUrl });

                    signedOut = true;
                }
                catch (Exception e)
                {
                    _logger.Warn(e, "Unable to sign out of the OIDC provider, signing out locally only");
                }

                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignOutAsync(AuthenticationType.Forms.ToString());

                if (signedOut || Response.HasStarted)
                {
                    return TypedResults.Empty;
                }

                return TypedResults.Redirect(loggedOutUrl);
            }

            await HttpContext.SignOutAsync(AuthenticationType.Forms.ToString());
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return TypedResults.Redirect(_configFileProvider.UrlBase + "/");
        }

        [HttpPost("logout/backchannel")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> BackchannelLogout([FromForm] string logout_token)
        {
            if (string.IsNullOrWhiteSpace(logout_token))
            {
                return BadRequest();
            }

            string sub = null;
            string sid = null;
            var hasEvent = false;

            try
            {
                var parts = logout_token.Split('.');
                if (parts.Length != 3)
                {
                    _logger.Warn("Backchannel logout token is not a JWT");
                    return BadRequest();
                }

                var payloadJson = DecodeBase64Url(parts[1]);
                using var doc = JsonDocument.Parse(payloadJson);
                var root = doc.RootElement;

                if (root.TryGetProperty("sub", out var subEl) && subEl.ValueKind == JsonValueKind.String)
                {
                    sub = subEl.GetString();
                }

                if (root.TryGetProperty("sid", out var sidEl) && sidEl.ValueKind == JsonValueKind.String)
                {
                    sid = sidEl.GetString();
                }

                if (root.TryGetProperty("events", out var eventsEl))
                {
                    if (eventsEl.ValueKind == JsonValueKind.Object)
                    {
                        hasEvent = eventsEl.TryGetProperty("http://schemas.openid.net/event/backchannel-logout", out _);
                    }
                    else if (eventsEl.ValueKind == JsonValueKind.String)
                    {
                        hasEvent = string.Equals(eventsEl.GetString(), "http://schemas.openid.net/event/backchannel-logout", StringComparison.Ordinal);
                    }
                }
            }
            catch (Exception e)
            {
                _logger.Warn(e, "Failed to decode backchannel logout token");
                return BadRequest();
            }

            if (!hasEvent || (string.IsNullOrWhiteSpace(sub) && string.IsNullOrWhiteSpace(sid)))
            {
                _logger.Warn("Backchannel logout token missing required claims");
                return BadRequest();
            }

            if (!string.IsNullOrWhiteSpace(sub))
            {
                try
                {
                    var repo = HttpContext.RequestServices.GetService(typeof(IUserRepository)) as IUserRepository;
                    var user = repo?.FindBySubject(sub);
                    if (user != null)
                    {
                        _logger.Info("Backchannel logout for subject {0} (user {1})", sub, user.Username);
                    }
                    else
                    {
                        _logger.Info("Backchannel logout for unknown subject {0}", sub);
                    }
                }
                catch (Exception e)
                {
                    _logger.Warn(e, "User lookup failed during backchannel logout");
                }
            }

            try
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }
            catch (Exception e)
            {
                _logger.Warn(e, "SignOut cookie failed during backchannel logout");
            }

            try
            {
                await HttpContext.SignOutAsync(AuthenticationType.Forms.ToString());
            }
            catch (Exception e)
            {
                _logger.Warn(e, "SignOut forms failed during backchannel logout");
            }

            return NoContent();
        }

        private static string DecodeBase64Url(string input)
        {
            var s = input.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2:
                    s += "==";
                    break;
                case 3:
                    s += "=";
                    break;
            }

            var bytes = Convert.FromBase64String(s);
            return Encoding.UTF8.GetString(bytes);
        }

        private static readonly ConcurrentDictionary<string, Queue<DateTime>> ExchangeRateLimits = new(StringComparer.Ordinal);
        private static readonly object ExchangeRateLock = new();

        private static bool TryAcquireExchangeRateLimit(string clientIp)
        {
            var now = DateTime.UtcNow;
            var window = TimeSpan.FromMinutes(1);

            lock (ExchangeRateLock)
            {
                if (!ExchangeRateLimits.TryGetValue(clientIp, out var queue))
                {
                    queue = new Queue<DateTime>();
                    ExchangeRateLimits[clientIp] = queue;
                }

                while (queue.Count > 0 && (now - queue.Peek()) > window)
                {
                    queue.Dequeue();
                }

                if (queue.Count >= 10)
                {
                    return false;
                }

                queue.Enqueue(now);
                return true;
            }
        }

        public Task<IResult> Exchange(OidcExchangeRequest request) => ExchangeOidc(request);

        public Task<IResult> OidcExchange(OidcExchangeRequest request) => ExchangeOidc(request);

        [HttpPost("api/auth/oidc/exchange")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
        public async Task<IResult> ExchangeOidc([FromBody] OidcExchangeRequest request)
        {
            var httpContext = HttpContext ?? new DefaultHttpContext();

            var clientIp = httpContext.Connection?.RemoteIpAddress?.ToString();
            if (string.IsNullOrWhiteSpace(clientIp))
            {
                clientIp = "unknown";
            }

            if (!TryAcquireExchangeRateLimit(clientIp))
            {
                return TypedResults.Json(new { message = "rate_limit_exceeded" }, statusCode: StatusCodes.Status429TooManyRequests);
            }

            var subjectToken = request?.ResolvedSubjectToken;

            if (string.IsNullOrWhiteSpace(subjectToken))
            {
                var authHeader = httpContext.Request.Headers.Authorization.ToString();
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    subjectToken = authHeader.Substring(7).Trim();
                }
            }

            if (string.IsNullOrWhiteSpace(subjectToken))
            {
                return TypedResults.Json(new { message = "subject_token is required" }, statusCode: StatusCodes.Status400BadRequest);
            }

            var authentik = httpContext.RequestServices?.GetService(typeof(IAuthentikTokenValidationService)) as IAuthentikTokenValidationService;
            if (authentik == null)
            {
                return TypedResults.Json(new { message = "service_unavailable" }, statusCode: StatusCodes.Status500InternalServerError);
            }

            var validation = await authentik.ValidateAsync(subjectToken);
            if (!validation.Success)
            {
                return TypedResults.Json(new { message = "invalid_token" }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var role = OidcGroupMapping.Resolve(validation.Groups);
            if (role == null)
            {
                return TypedResults.Json(new { message = "insufficient_group" }, statusCode: StatusCodes.Status403Forbidden);
            }

            var userService = httpContext.RequestServices?.GetService(typeof(IUserService)) as IUserService;
            userService?.UpsertOidcUser(validation.Subject, validation.Username, string.Join(",", validation.Groups), role.Value);

            var tokenService = httpContext.RequestServices?.GetService(typeof(ISonarrServiceTokenService)) as ISonarrServiceTokenService;
            var sonarrToken = tokenService != null ? tokenService.MintToken(validation.Subject, role.Value) : null;

            return TypedResults.Json(new
            {
                token = sonarrToken,
                token_type = "Bearer",
                expires_in = 300,
                role = role.Value.ToString(),
                permissions = SonarrRolePermissions.ForRole(role.Value),
            },
            statusCode: StatusCodes.Status200OK);
        }

        public IResult Me() => GetMe();

        public IResult CurrentUser() => GetMe();

        public IResult GetCurrentUser() => GetMe();

        [HttpGet("api/auth/me")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public IResult GetMe()
        {
            var httpContext = HttpContext ?? new DefaultHttpContext();

            var authHeader = httpContext.Request.Headers.Authorization.ToString();
            string token = null;
            if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                token = authHeader.Substring(7).Trim();
            }

            var tokenService = httpContext.RequestServices?.GetService(typeof(ISonarrServiceTokenService)) as ISonarrServiceTokenService;
            var principal = tokenService != null ? tokenService.ValidateToken(token) : null;
            if (principal == null)
            {
                return TypedResults.Json(new { message = "invalid_token" }, statusCode: StatusCodes.Status401Unauthorized);
            }

            var sub = principal.FindFirst("sub")?.Value;

            var repo = httpContext.RequestServices?.GetService(typeof(IUserRepository)) as IUserRepository;
            var user = repo != null && sub != null ? repo.FindBySubject(sub) : null;
            if (user == null)
            {
                return TypedResults.Json(new { message = "not_found" }, statusCode: StatusCodes.Status404NotFound);
            }

            var groups = string.IsNullOrWhiteSpace(user.OidcGroups)
                ? new List<string>()
                : user.OidcGroups.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

            return TypedResults.Json(new
            {
                username = user.Username,
                role = user.Role.ToString(),
                groups,
                permissions = SonarrRolePermissions.ForRole(user.Role),
            },
            statusCode: StatusCodes.Status200OK);
        }

        private string GetRedirectUrl(string returnUrl)
        {
            var urlBase = _configFileProvider.UrlBase;

            if (returnUrl.IsNullOrWhiteSpace() || !Url.IsLocalUrl(returnUrl))
            {
                return urlBase + "/";
            }

            if (urlBase.IsNullOrWhiteSpace() ||
                returnUrl.Equals(urlBase, StringComparison.OrdinalIgnoreCase) ||
                returnUrl.StartsWith(urlBase + "/", StringComparison.OrdinalIgnoreCase))
            {
                return returnUrl;
            }

            return urlBase + returnUrl;
        }
    }
}
