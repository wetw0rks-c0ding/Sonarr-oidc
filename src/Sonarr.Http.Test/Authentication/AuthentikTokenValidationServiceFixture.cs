using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

using Moq;

using NUnit.Framework;

using Sonarr.Http.Authentication;

namespace Sonarr.Http.Test.Authentication
{
    [TestFixture]
    public class AuthentikTokenValidationServiceFixture
    {
        private const string Issuer = AuthentikTokenValidationService.Issuer;

        private RSA _rsa;
        private RsaSecurityKey _signingKey;
        private JsonWebKey _jsonWebKey;
        private OpenIdConnectConfiguration _configuration;

        [SetUp]
        public void SetUp()
        {
            _rsa = RSA.Create(2048);
            _signingKey = new RsaSecurityKey(_rsa) { KeyId = "test-kid" };
            _jsonWebKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(_signingKey);
            _jsonWebKey.Kid = "test-kid";

            _configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
            _configuration.SigningKeys.Add(_signingKey);
            _configuration.JsonWebKeySet = new JsonWebKeySet();
            _configuration.JsonWebKeySet.Keys.Add(_jsonWebKey);
        }

        private IConfigurationManager<OpenIdConnectConfiguration> CreateManager(OpenIdConnectConfiguration configuration)
        {
            var mock = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
            mock.Setup(manager => manager.GetConfigurationAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(configuration);

            return mock.Object;
        }

        private string CreateToken(
            string subject = "user-123",
            string username = "alice",
            IEnumerable<string> groups = null,
            string issuer = Issuer,
            string audience = "seekarr-app",
            int notBeforeMinutes = -1,
            int expiresMinutes = 5,
            RsaSecurityKey signingKey = null)
        {
            signingKey = signingKey ?? _signingKey;

            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

            var claims = new List<Claim>();
            if (subject != null)
            {
                claims.Add(new Claim("sub", subject));
            }

            if (username != null)
            {
                claims.Add(new Claim("preferred_username", username));
            }

            if (groups != null)
            {
                foreach (var group in groups)
                {
                    claims.Add(new Claim("groups", group));
                }
            }

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.UtcNow.AddMinutes(notBeforeMinutes),
                expires: DateTime.UtcNow.AddMinutes(expiresMinutes),
                signingCredentials: credentials);

            return handler.WriteToken(token);
        }

        [Test]
        public async Task valid_token_passes_with_subject_username_and_groups()
        {
            var token = CreateToken(groups: new[] { "homies", "family" });

            var service = new AuthentikTokenValidationService(CreateManager(_configuration));

            var result = await service.ValidateAsync(token);

            Assert.That(result.Success, Is.True);
            Assert.That(result.FailureReason, Is.Null);
            Assert.That(result.Subject, Is.EqualTo("user-123"));
            Assert.That(result.Username, Is.EqualTo("alice"));
            Assert.That(result.Groups, Is.EquivalentTo(new[] { "homies", "family" }));
        }

        [Test]
        public async Task expired_token_fails()
        {
            var token = CreateToken(notBeforeMinutes: -20, expiresMinutes: -10);

            var service = new AuthentikTokenValidationService(CreateManager(_configuration));

            var result = await service.ValidateAsync(token);

            Assert.That(result.Success, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_token"));
        }

        [Test]
        public async Task wrong_issuer_fails()
        {
            var token = CreateToken(issuer: "https://evil.example/");

            var service = new AuthentikTokenValidationService(CreateManager(_configuration));

            var result = await service.ValidateAsync(token);

            Assert.That(result.Success, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_token"));
        }

        [Test]
        public async Task audience_without_seekarr_fails()
        {
            var token = CreateToken(audience: "other-app");

            var service = new AuthentikTokenValidationService(CreateManager(_configuration));

            var result = await service.ValidateAsync(token);

            Assert.That(result.Success, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_token"));
        }

        [Test]
        public async Task missing_subject_fails()
        {
            var token = CreateToken(subject: null);

            var service = new AuthentikTokenValidationService(CreateManager(_configuration));

            var result = await service.ValidateAsync(token);

            Assert.That(result.Success, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("missing_subject"));
        }

        [Test]
        public async Task unknown_kid_triggers_refresh_and_retries()
        {
            var newRsa = RSA.Create(2048);
            var refreshedKey = new RsaSecurityKey(newRsa) { KeyId = "refreshed-kid" };
            var refreshedJwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(refreshedKey);
            refreshedJwk.Kid = "refreshed-kid";

            var refreshedConfiguration = new OpenIdConnectConfiguration { Issuer = Issuer };
            refreshedConfiguration.SigningKeys.Add(refreshedKey);
            refreshedConfiguration.JsonWebKeySet = new JsonWebKeySet();
            refreshedConfiguration.JsonWebKeySet.Keys.Add(refreshedJwk);

            var mock = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
            mock.SetupSequence(manager => manager.GetConfigurationAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(_configuration)
                .ReturnsAsync(refreshedConfiguration);

            var token = CreateToken(signingKey: refreshedKey);

            var service = new AuthentikTokenValidationService(mock.Object);

            var result = await service.ValidateAsync(token);

            Assert.That(result.Success, Is.True);
            Assert.That(result.FailureReason, Is.Null);
            mock.Verify(manager => manager.RequestRefresh(), Times.Once);
            mock.Verify(manager => manager.GetConfigurationAsync(It.IsAny<CancellationToken>()), Times.Exactly(2));
        }
    }
}
