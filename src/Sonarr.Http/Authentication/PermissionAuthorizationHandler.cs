using System;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;

using NzbDrone.Core.Authentication;

namespace Sonarr.Http.Authentication
{
    public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            var roleClaim = context.User?.FindFirst("role")?.Value;
            var hasOidcSub = context.User?.FindFirst("oidc_sub") != null;

            if (roleClaim == null && !hasOidcSub)
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            var role = SonarrRole.Admin;
            if (roleClaim != null && Enum.TryParse<SonarrRole>(roleClaim, true, out var parsedRole))
            {
                role = parsedRole;
            }

            if (role >= requirement.Minimum)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
