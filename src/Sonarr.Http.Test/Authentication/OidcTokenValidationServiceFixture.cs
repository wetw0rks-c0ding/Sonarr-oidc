using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;
using NzbDrone.Common.Cache;
using NzbDrone.Test.Common;
using Sonarr.Http.Authentication;

namespace Sonarr.Http.Test.Authentication
{
    [TestFixture]
    public class OidcTokenValidationServiceFixture : TestBase<OidcTokenValidationService>
    {
        private Mock<NzbDrone.Core.Configuration.IConfigFileProvider> _configMock;
        private Mock<IOptionsMonitor<NzbDrone.Core.Configuration.IConfigFileProvider>> _configMonitor;

        [SetUp]
        public void Setup()
        {
            _configMock = new Mock<NzbDrone.Core.Configuration.IConfigFileProvider>();
            _configMonitor = new Mock<IOptionsMonitor<NzbDrone.Core.Configuration.IConfigFileProvider>>();
            _configMonitor.Setup(c => c.CurrentValue).Returns(_configMock.Object);

            Mocker.SetConstant<ICacheManager>(new CacheManager());
        }

        private byte[] ReadKey()
        {
            var path = System.IO.Path.Combine(TempFolder, "service-token.key");
            var content = System.IO.File.ReadAllText(path).Trim();
            try
            {
                return Convert.FromBase64String(content);
            }
            catch (FormatException)
            {
                return Encoding.UTF8.GetBytes(content);
            }
        }

        [Test]
        public void should_accept_a_valid_oidc_token()
        {
            _configMock.SetupGet(c => c.OidcAuthority).Returns("https://auth.example.com");
            _configMock.SetupGet(c => c.OidcClientId).Returns("test-client-id");

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);
            var jwt = new JwtSecurityToken(
                issuer: "https://auth.example.com",
                audience: "test-client-id",
                claims: new[] { new Claim("sub", "subject-1"), new Claim("preferred_username", "homies") },
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            var token = handler.WriteToken(jwt);

            var result = Subject.ValidateAsync(token).GetAwaiter().GetResult();

            Assert.That(result.Success, Is.True);
            Assert.That(result.Subject, Is.EqualTo("subject-1"));
            Assert.That(result.Username, Is.EqualTo("homies"));
        }

        [Test]
        public void should_reject_expired_token()
        {
            _configMock.SetupGet(c => c.OidcAuthority).Returns("https://auth.example.com");
            _configMock.SetupGet(c => c.OidcClientId).Returns("test-client-id");

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);
            var jwt = new JwtSecurityToken(
                issuer: "https://auth.example.com",
                audience: "test-client-id",
                claims: new[] { new Claim("sub", "subject-1") },
                notBefore: DateTime.UtcNow.AddMinutes(-20),
                expires: DateTime.UtcNow.AddMinutes(-10),
                signingCredentials: credentials);

            var token = handler.WriteToken(jwt);

            var result = Subject.ValidateAsync(token).GetAwaiter().GetResult();

            Assert.That(result.Success, Is.False);
        }

        [Test]
        public void should_reject_wrong_issuer()
        {
            _configMock.SetupGet(c => c.OidcAuthority).Returns("https://auth.example.com");
            _configMock.SetupGet(c => c.OidcClientId).Returns("test-client-id");

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);
            var jwt = new JwtSecurityToken(
                issuer: "https://evil.example.com",
                audience: "test-client-id",
                claims: new[] { new Claim("sub", "subject-1") },
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            var token = handler.WriteToken(jwt);

            var result = Subject.ValidateAsync(token).GetAwaiter().GetResult();

            Assert.That(result.Success, Is.False);
        }

        [Test]
        public void should_reject_wrong_audience()
        {
            _configMock.SetupGet(c => c.OidcAuthority).Returns("https://auth.example.com");
            _configMock.SetupGet(c => c.OidcClientId).Returns("test-client-id");

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);
            var jwt = new JwtSecurityToken(
                issuer: "https://auth.example.com",
                audience: "wrong-client-id",
                claims: new[] { new Claim("sub", "subject-1") },
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            var token = handler.WriteToken(jwt);

            var result = Subject.ValidateAsync(token).GetAwaiter().GetResult();

            Assert.That(result.Success, Is.False);
        }

        [Test]
        public void should_reject_missing_subject()
        {
            _configMock.SetupGet(c => c.OidcAuthority).Returns("https://auth.example.com");
            _configMock.SetupGet(c => c.OidcClientId).Returns("test-client-id");

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);
            var jwt = new JwtSecurityToken(
                issuer: "https://auth.example.com",
                audience: "test-client-id",
                claims: Array.Empty<Claim>(),
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            var token = handler.WriteToken(jwt);

            var result = Subject.ValidateAsync(token).GetAwaiter().GetResult();

            Assert.That(result.Success, Is.False);
        }

        [Test]
        public void should_handle_empty_audience_config_fails_closed()
        {
            _configMock.SetupGet(c => c.OidcAuthority).Returns("https://auth.example.com");
            _configMock.SetupGet(c => c.OidcClientId).Returns(string.Empty);

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);
            var jwt = new JwtSecurityToken(
                issuer: "https://auth.example.com",
                audience: "test-client-id",
                claims: new[] { new Claim("sub", "subject-1") },
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            var token = handler.WriteToken(jwt);

            var result = Subject.ValidateAsync(token).GetAwaiter().GetResult();

            Assert.That(result.Success, Is.False);
        }

        [Test]
        public void should_handle_null_audience_config_fails_closed()
        {
            _configMock.SetupGet(c => c.OidcAuthority).Returns("https://auth.example.com");
            _configMock.SetupGet(c => c.OidcClientId).Returns((string)null);

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);
            var jwt = new JwtSecurityToken(
                issuer: "https://auth.example.com",
                audience: "test-client-id",
                claims: new[] { new Claim("sub", "subject-1") },
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            var token = handler.WriteToken(jwt);

            var result = Subject.ValidateAsync(token).GetAwaiter().GetResult();

            Assert.That(result.Success, Is.False);
        }

        [Test]
        public void should_handle_missing_oidc_authority_fails_closed()
        {
            _configMock.SetupGet(c => c.OidcAuthority).Returns((string)null!);
            _configMock.SetupGet(c => c.OidcClientId).Returns("test-client-id");

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);
            var jwt = new JwtSecurityToken(
                issuer: "https://auth.example.com",
                audience: "test-client-id",
                claims: new[] { new Claim("sub", "subject-1") },
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            var token = handler.WriteToken(jwt);

            var result = Subject.ValidateAsync(token).GetAwaiter().GetResult();

            Assert.That(result.Success, Is.False);
        }
    }
}
