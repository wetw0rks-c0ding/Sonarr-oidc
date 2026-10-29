using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;
using Sonarr.Http.Authentication;

namespace NzbDrone.Http.Authentication
{
    public class UiAuthorizationPolicyProvider : IAuthorizationPolicyProvider
    {
        private const string PolicyName = "UI";
        private readonly IConfigFileProvider _config;

        private static readonly (string Name, SonarrRole Role)[] PermissionPolicies =
        {
            ("UI.Read", SonarrRole.ReadOnly),
            ("UI.Add", SonarrRole.AddSearch),
            ("UI.Manage", SonarrRole.Manage),
            ("UI.Admin", SonarrRole.Admin)
        };

        public DefaultAuthorizationPolicyProvider FallbackPolicyProvider { get; }

        public UiAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options,
            IConfigFileProvider config)
        {
            FallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
            _config = config;
        }

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => FallbackPolicyProvider.GetDefaultPolicyAsync();

        public Task<AuthorizationPolicy> GetFallbackPolicyAsync() => FallbackPolicyProvider.GetFallbackPolicyAsync();

        public Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            if (policyName.Equals(PolicyName, StringComparison.OrdinalIgnoreCase))
            {
                var authenticationMethod = _config.EffectiveAuthenticationMethod();

                // OIDC signs into the cookie scheme, so authenticate against the cookie.
                // Using the OIDC scheme would challenge the identity provider on every
                // unauthenticated request instead of redirecting to the login page.
                var scheme = authenticationMethod switch
                {
                    AuthenticationType.Oidc => CookieAuthenticationDefaults.AuthenticationScheme,
                    _ => authenticationMethod.ToString()
                };

                var policy = new AuthorizationPolicyBuilder(scheme)
                    .AddRequirements(new BypassableDenyAnonymousAuthorizationRequirement());

                return Task.FromResult(policy.Build());
            }

            foreach (var (name, role) in PermissionPolicies)
            {
                if (policyName.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    var policy = new AuthorizationPolicyBuilder()
                        .AddRequirements(new PermissionRequirement(role));

                    return Task.FromResult(policy.Build());
                }
            }

            return FallbackPolicyProvider.GetPolicyAsync(policyName);
        }
    }
}
