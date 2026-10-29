using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
