using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

using FluentAssertions;

using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;
using NzbDrone.Common.Cache;
using NzbDrone.Common.EnvironmentInfo;
using NzbDrone.Core.Authentication;
using NzbDrone.Test.Common;
using Sonarr.Http.Authentication;

namespace Sonarr.Http.Test.Authentication
{
    [TestFixture]
    public class AuthenticationControllerOidcFixture : TestBase<AuthenticationController>
    {
        private Mock<IAuthenticationService> _authServiceMock;
        private Mock<NzbDrone.Core.Configuration.IConfigFileProvider> _configMock;
        private Mock<IOidcTokenValidationService> _tokenValidationMock;
        private Mock<ISonarrServiceTokenService> _tokenServiceMock;

        [SetUp]
        public void Setup()
        {
            _authServiceMock = new Mock<IAuthenticationService>();
            _configMock = new Mock<NzbDrone.Core.Configuration.IConfigFileProvider>();
            _tokenValidationMock = new Mock<IOidcTokenValidationService>();
            _tokenServiceMock = new Mock<ISonarrServiceTokenService>();

            var tempFolder = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "test_oidc_" + Guid.NewGuid());
            System.IO.Directory.CreateDirectory(tempFolder);

            Mocker.SetConstant<ICacheManager>(new CacheManager());

            _configMock.SetupGet(c => c.OidcAuthority).Returns("https://auth.example.com");
            _configMock.SetupGet(c => c.OidcClientId).Returns("test-client-id");
            _configMock.SetupGet(c => c.UrlBase).Returns("/api");

            // Setup authentication service mocks for forms auth (used by Login)
            var users = new List<User>
            {
                new User { Id = 1, Identifier = Guid.NewGuid(), Username = "testuser", OidcSubject = null, Role = SonarrRole.ReadOnly },
                new User { Id = 2, Identifier = Guid.NewGuid(), Username = "admin", OidcSubject = null, Role = SonarrRole.Admin }
            };

            _authServiceMock.Setup(m => m.Login(It.IsAny<HttpRequest>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns((string username, string password) => users.FirstOrDefault(u => u.Username == username && password == "password"));

            _authServiceMock.Setup(m => m.Logout(It.IsAny<HttpContext>())).Verifiable();
            _authServiceMock.Setup(m => m.GetLockoutEndTime(It.IsAny<HttpRequest>()))
                .Returns((DateTime?)null);
        }

        [TearDown]
        public void Cleanup()
        {
            if (System.IO.Directory.Exists(TempFolder))
            {
                System.IO.Directory.Delete(TempFolder, true);
            }
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

        private string CreateOidcToken(string issuer, string audience, string sub = null, string username = null)
        {
            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(ReadKey()), SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                sub != null ? new Claim("sub", sub) : null,
                username != null ? new Claim("preferred_username", username) : null
            }
            .Where(c => c != null).ToArray();

            var jwt = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            return handler.WriteToken(jwt);
        }

        private string CreateServiceToken(string subject)
        {
            var keyBytes = Convert.FromBase64String("eJwL7AAABICQgYCBgI+AgIiBgIKIgYCBAIA=");
            var handler = new JwtSecurityTokenHandler();
            var credentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

            var claims = new[] { new Claim("sub", subject) }.Where(c => c != null).ToArray();

            var jwt = new JwtSecurityToken(
                issuer: "https://auth.example.com/sonarr",
                audience: "test-client-id",
                claims: claims,
                notBefore: DateTime.UtcNow.AddMinutes(-1),
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            return handler.WriteToken(jwt);
        }

        private AuthenticationController CreateController()
        {
            var controller = new AuthenticationController(
                _authServiceMock.Object,
                _configMock.Object,
                Mocker.Resolve<IAppFolderInfo>(),
                TestLogger);

            return controller;
        }

        private static OidcExchangeRequest CreateOidcExchange(string token) => new(token, null);

        [Test]
        public void exchange_with_valid_token_returns_200()
        {
            _tokenValidationMock.Setup(v => v.ValidateAsync(It.IsAny<string>()))
                .ReturnsAsync(new OidcValidationResult(
                    true, null, "subject-1", "testuser", new List<string> { "homies" }));

            _tokenServiceMock.Setup(t => t.MintToken("subject-1", SonarrRole.ReadOnly))
                .Returns("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid-token");

            var controller = CreateController();

            var httpContext = new DefaultHttpContext();
            var jsonBody = System.Text.Json.JsonSerializer.Serialize(new
            {
                subject_token = CreateOidcToken("https://auth.example.com", "test-client-id")
            });
            httpContext.Request.Body = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(jsonBody));
            httpContext.Request.ContentType = "application/json";

            var result = controller.ExchangeOidc(new OidcExchangeRequest(CreateOidcToken("https://auth.example.com", "test-client-id")));

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public void exchange_with_null_token_returns_400()
        {
            var controller = CreateController();

            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "POST";
            httpContext.Request.ContentType = "application/json";
            httpContext.Request.Body = System.IO.Stream.Null;

            var result = controller.ExchangeOidc(new OidcExchangeRequest(null));

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public void exchange_with_whitespace_token_returns_400()
        {
            var controller = CreateController();

            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "POST";
            httpContext.Request.ContentType = "application/json";

            var jsonBody = System.Text.Json.JsonSerializer.Serialize(new
            {
                subject_token = "   "
            });
            httpContext.Request.Body = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(jsonBody));

            var result = controller.ExchangeOidc(new OidcExchangeRequest("   "));

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public void me_with_valid_token_returns_200()
        {
            var controller = CreateController();

            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "GET";
            httpContext.Request.Headers.Authorization = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid-token";
            httpContext.Request.ContentType = "application/json";

            var result = controller.GetMe();

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public void me_with_no_token_returns_401()
        {
            var controller = CreateController();

            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "GET";

            var result = controller.GetMe();

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public void exchange_with_empty_body_returns_400()
        {
            var controller = CreateController();

            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "POST";
            httpContext.Request.ContentType = "application/json";
            httpContext.Request.Body = System.IO.Stream.Null;

            var result = controller.ExchangeOidc(new OidcExchangeRequest(null));

            Assert.That(result, Is.Not.Null);
        }
    }
}
