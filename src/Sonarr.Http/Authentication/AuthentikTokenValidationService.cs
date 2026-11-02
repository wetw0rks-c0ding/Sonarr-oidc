using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using NLog;

namespace Sonarr.Http.Authentication
{
    public record OidcValidationResult(bool Success, string FailureReason, string Subject, string Username, List<string> Groups);

    public interface IOidcTokenValidationService
    {
        Task<OidcValidationResult> ValidateAsync(string token);
    }

    public class OidcTokenValidationService : IOidcTokenValidationService
    {
        private static readonly Logger Logger = LogManager.GetLogger(nameof(OidcTokenValidationService));

        private IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

        // Accepts either a pre-wired ConfigurationManager or an options monitor for config-driven initialization
        public OidcTokenValidationService(IConfigurationManager<OpenIdConnectConfiguration> configurationManager = null, IOptionsMonitor<NzbDrone.Core.Configuration.IConfigFileProvider> configProvider = null)
        {
            if (configurationManager != null)
            {
                _configurationManager = configurationManager;
            }
            else if (configProvider != null)
            {
                _configFileProvider = configProvider?.CurrentValue;
            }
        }

        // Lazily initialized on first ValidateAsync call when using options monitor pattern
        private NzbDrone.Core.Configuration.IConfigFileProvider _configFileProvider;

        public async Task<OidcValidationResult> ValidateAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return new OidcValidationResult(false, "invalid_token", null, null, new List<string>());
            }

            var cleanedToken = token.Trim();
            if (cleanedToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                cleanedToken = cleanedToken.Substring(7).Trim();
            }

            // Lazy-init ConfigurationManager on first call; fail closed if OIDC not configured
            if (_configurationManager == null)
            {
                var authority = _configFileProvider?.OidcAuthority;

                // Fail closed: no configuration, return invalid_token immediately
                if (string.IsNullOrWhiteSpace(authority))
                {
                    Logger.Debug("OIDC token validation skipped: Authority not configured");
                    return new OidcValidationResult(false, "invalid_token", null, null, new List<string>());
                }

                var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    authority.TrimEnd('/') + "/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever())
                {
                    AutomaticRefreshInterval = TimeSpan.FromHours(24),
                    RefreshInterval = TimeSpan.FromHours(24),
                };

                _configurationManager = manager;
            }

            var configuration = await _configurationManager.GetConfigurationAsync(CancellationToken.None).ConfigureAwait(false);

            if (configuration == null)
            {
                Logger.Debug("OIDC token validation skipped: discovery returned null");
                return new OidcValidationResult(false, "invalid_token", null, null, new List<string>());
            }

            var signingKeys = new List<SecurityKey>();
            if (configuration.SigningKeys != null)
            {
                signingKeys.AddRange(configuration.SigningKeys);
            }

            if (configuration.JsonWebKeySet != null)
            {
                try
                {
                    signingKeys.AddRange(configuration.JsonWebKeySet.GetSigningKeys());
                }
                catch (Exception ex)
                {
                    Logger.Debug(ex, "Failed to extract signing keys from JWKS");
                }
            }

            if (!signingKeys.Any())
            {
                Logger.Debug("OIDC token validation skipped: no signing keys available");
                return new OidcValidationResult(false, "invalid_token", null, null, new List<string>());
            }

            var issuer = configuration.Issuer;
            var expectedAudience = _configFileProvider?.OidcClientId?.Trim();

            // Audience rule: clientId set → exact match only; unset/empty → fail closed (no validation attempted)
            OidcValidationResult result;

            if (!string.IsNullOrWhiteSpace(expectedAudience))
            {
                var parameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = true,
                    ValidAudience = expectedAudience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(2),
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = signingKeys,
                    AudienceValidator = (audiences, securityToken, validationParameters) =>
                        audiences != null && audiences.Any(a => string.Equals(a, expectedAudience, StringComparison.Ordinal)),
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
                    return new OidcValidationResult(false, "missing_subject", null, null, new List<string>());
                }

                var username = principal.FindFirst("preferred_username")?.Value
                    ?? principal.FindFirst("email")?.Value
                    ?? subject;

                result = new OidcValidationResult(true, null, subject, username, AuthenticationBuilderExtensions.GetGroups(principal, "groups").ToList());
            }
            else
            {
                // No clientId configured → fail closed without attempting audience validation
                Logger.Debug("OIDC token validation skipped: no client ID configured");
                result = new OidcValidationResult(false, "invalid_token", null, null, new List<string>());
            }

            return result;
        }

        private JwtSecurityTokenHandler handler { get; } = new JwtSecurityTokenHandler();
    }
}
