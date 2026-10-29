using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using NLog;

namespace Sonarr.Http.Authentication
{
    public record AuthentikValidationResult(bool Success, string FailureReason, string Subject, string Username, List<string> Groups);

    public interface IAuthentikTokenValidationService
    {
        Task<AuthentikValidationResult> ValidateAsync(string token);
    }

    public class AuthentikTokenValidationService : IAuthentikTokenValidationService
    {
        public const string Issuer = "https://auth.piracyhub.win/application/o/seekarr/";

        public const string RequiredAudienceSubstring = "seekarr";

        public const string AudienceSubstring = "seekarr";

        public const string RequiredAudience = "seekarr";

        public const string Audience = "seekarr";

        private static readonly Logger Logger = LogManager.GetLogger(nameof(AuthentikTokenValidationService));

        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

        public AuthentikTokenValidationService(IConfigurationManager<OpenIdConnectConfiguration> configurationManager = null)
        {
            if (configurationManager == null)
            {
                var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    Issuer + ".well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever())
                {
                    AutomaticRefreshInterval = TimeSpan.FromHours(24),
                    RefreshInterval = TimeSpan.FromHours(24),
                };

                _configurationManager = manager;
            }
            else
            {
                _configurationManager = configurationManager;
            }
        }

        public async Task<AuthentikValidationResult> ValidateAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return new AuthentikValidationResult(false, "invalid_token", null, null, new List<string>());
            }

            var cleanedToken = token.Trim();
            if (cleanedToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                cleanedToken = cleanedToken.Substring(7).Trim();
            }

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            for (var attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    var configuration = await _configurationManager.GetConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

                    var signingKeys = new List<SecurityKey>();
                    if (configuration != null && configuration.SigningKeys != null)
                    {
                        signingKeys.AddRange(configuration.SigningKeys);
                    }

                    if (configuration != null && configuration.JsonWebKeySet != null)
                    {
                        try
                        {
                            signingKeys.AddRange(configuration.JsonWebKeySet.GetSigningKeys());
                        }
                        catch
                        {
                        }
                    }

                    var parameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = Issuer,
                        ValidateAudience = true,
                        AudienceValidator = (audiences, securityToken, validationParameters) =>
                            audiences != null && audiences.Any(audience => !string.IsNullOrWhiteSpace(audience) && audience.Contains(RequiredAudienceSubstring)),
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromMinutes(2),
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKeys = signingKeys,
                    };

                    var validationResult = await handler.ValidateTokenAsync(cleanedToken, parameters).ConfigureAwait(false);
                    if (!validationResult.IsValid)
                    {
                        throw validationResult.Exception ?? new SecurityTokenException("Invalid token");
                    }

                    var principal = new System.Security.Claims.ClaimsPrincipal(validationResult.ClaimsIdentity);

                    var subject = principal.FindFirst("sub")?.Value;
                    if (string.IsNullOrWhiteSpace(subject))
                    {
                        return new AuthentikValidationResult(false, "missing_subject", null, null, new List<string>());
                    }

                    var username = principal.FindFirst("preferred_username")?.Value
                        ?? principal.FindFirst("email")?.Value
                        ?? subject;

                    var groups = AuthenticationBuilderExtensions.GetGroups(principal, "groups").ToList();

                    return new AuthentikValidationResult(true, null, subject, username, groups);
                }
                catch (SecurityTokenSignatureKeyNotFoundException)
                {
                    if (attempt == 0)
                    {
                        try
                        {
                            _configurationManager.RequestRefresh();
                        }
                        catch
                        {
                        }

                        continue;
                    }

                    Logger.Warn("Authentik token validation failed: signature key not found");
                    return new AuthentikValidationResult(false, "invalid_token", null, null, new List<string>());
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "Authentik token validation failed");
                    return new AuthentikValidationResult(false, "invalid_token", null, null, new List<string>());
                }
            }

            return new AuthentikValidationResult(false, "invalid_token", null, null, new List<string>());
        }
    }
}
