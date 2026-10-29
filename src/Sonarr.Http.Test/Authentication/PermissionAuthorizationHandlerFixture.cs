using System.Security.Claims;

using FluentAssertions;

using Microsoft.AspNetCore.Authorization;

using NUnit.Framework;

using NzbDrone.Core.Authentication;

using Sonarr.Http.Authentication;

namespace Sonarr.Http.Test.Authentication
{
    [TestFixture]
    public class PermissionAuthorizationHandlerFixture
    {
        private readonly PermissionAuthorizationHandler _handler = new PermissionAuthorizationHandler();

        private bool IsAuthorized(ClaimsPrincipal principal, SonarrRole minimum)
        {
            var requirement = new PermissionRequirement(minimum);
            var context = new AuthorizationHandlerContext(new[] { requirement }, principal, null);

            _handler.HandleAsync(context).GetAwaiter().GetResult();

            return context.HasSucceeded;
        }

        private static ClaimsPrincipal PrincipalWithRole(string role)
        {
            var identity = new ClaimsIdentity(new[] { new Claim("role", role) }, "test");
            return new ClaimsPrincipal(identity);
        }

        [Test]
        public void admin_succeeds_for_readonly_requirement()
        {
            IsAuthorized(PrincipalWithRole("Admin"), SonarrRole.ReadOnly).Should().BeTrue();
        }

        [Test]
        public void readonly_fails_for_manage_requirement()
        {
            IsAuthorized(PrincipalWithRole("ReadOnly"), SonarrRole.Manage).Should().BeFalse();
        }

        [Test]
        public void no_role_no_oidc_sub_bypasses()
        {
            var identity = new ClaimsIdentity(new[] { new Claim("ApiKey", "true") }, "API Key");
            var principal = new ClaimsPrincipal(identity);

            IsAuthorized(principal, SonarrRole.Manage).Should().BeTrue();
        }

        [Test]
        public void oidc_sub_without_role_defaults_to_admin()
        {
            var identity = new ClaimsIdentity(new[] { new Claim("oidc_sub", "subject-1") }, "Cookies");
            var principal = new ClaimsPrincipal(identity);

            IsAuthorized(principal, SonarrRole.Admin).Should().BeTrue();
        }

        [Test]
        public void unparseable_role_defaults_to_admin()
        {
            var identity = new ClaimsIdentity(new[] { new Claim("role", "garbage") }, "test");
            var principal = new ClaimsPrincipal(identity);

            IsAuthorized(principal, SonarrRole.Admin).Should().BeTrue();
        }
    }
}
