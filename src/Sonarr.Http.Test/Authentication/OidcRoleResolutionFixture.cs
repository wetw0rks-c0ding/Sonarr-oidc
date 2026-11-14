using NUnit.Framework;

using NzbDrone.Core.Authentication;
using Sonarr.Http.Authentication;

namespace Sonarr.Http.Test.Authentication
{
    [TestFixture]
    public class OidcRoleResolutionFixture
    {
        [Test]
        public void configured_mapping_with_unmapped_group_returns_null_even_when_identifier_matches()
        {
            // (a) Mapping configured + matching OidcUserIdentifier but no mapped group ->
            // must NOT grant admin (fail closed), mirroring insufficient_group.
            var role = AuthenticationBuilderExtensions.ResolveOidcRole(
                new[] { "strangers" },
                "homies=ReadOnly;admins=Admin",
                "alice@example.com",
                "subject-1",
                "alice",
                "alice@example.com");

            Assert.That(role, Is.Null);
        }

        [Test]
        public void configured_mapping_with_matching_group_returns_mapped_role()
        {
            // (c) Mapping configured + matching group -> role from mapping.
            var role = AuthenticationBuilderExtensions.ResolveOidcRole(
                new[] { "homies" },
                "homies=ReadOnly;admins=Admin",
                "alice@example.com",
                "subject-1",
                "alice",
                "alice@example.com");

            Assert.That(role, Is.EqualTo(SonarrRole.ReadOnly));
        }

        [Test]
        public void configured_mapping_with_matching_admin_group_returns_admin()
        {
            var role = AuthenticationBuilderExtensions.ResolveOidcRole(
                new[] { "admins" },
                "homies=ReadOnly;admins=Admin",
                "alice@example.com",
                "subject-1",
                "alice",
                "alice@example.com");

            Assert.That(role, Is.EqualTo(SonarrRole.Admin));
        }

        [Test]
        public void unconfigured_mapping_with_matching_identifier_grants_admin_backcompat()
        {
            // (b) No mappings configured + matching OidcUserIdentifier -> admin (legacy).
            var role = AuthenticationBuilderExtensions.ResolveOidcRole(
                new[] { "strangers" },
                string.Empty,
                "alice@example.com",
                "subject-1",
                "alice",
                "alice@example.com");

            Assert.That(role, Is.EqualTo(SonarrRole.Admin));
        }

        [Test]
        public void unconfigured_mapping_with_matching_subject_grants_admin_backcompat()
        {
            var role = AuthenticationBuilderExtensions.ResolveOidcRole(
                new[] { "strangers" },
                "   ",
                "subject-1",
                "subject-1",
                "alice",
                "alice@example.com");

            Assert.That(role, Is.EqualTo(SonarrRole.Admin));
        }

        [Test]
        public void unconfigured_mapping_with_non_matching_identifier_returns_null()
        {
            var role = AuthenticationBuilderExtensions.ResolveOidcRole(
                new[] { "strangers" },
                string.Empty,
                "bob@example.com",
                "subject-1",
                "alice",
                "alice@example.com");

            Assert.That(role, Is.Null);
        }

        [Test]
        public void configured_mapping_with_unmapped_group_returns_null_even_when_mappings_malformed_nonempty()
        {
            // Non-empty but no valid pairs still counts as configured -> fail closed.
            var role = AuthenticationBuilderExtensions.ResolveOidcRole(
                new[] { "homies" },
                "garbage-without-equals",
                "alice@example.com",
                "subject-1",
                "alice",
                "alice@example.com");

            Assert.That(role, Is.Null);
        }
    }
}
