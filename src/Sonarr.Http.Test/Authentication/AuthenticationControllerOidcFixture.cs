using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using NUnit.Framework;
using NzbDrone.Core.Authentication;
using NzbDrone.Test.Common;
using Sonarr.Http.Authentication;

namespace Sonarr.Http.Test.Authentication
{
    [TestFixture]
    public class AuthenticationControllerOidcFixture : TestBase<AuthenticationController>
    {
        private DefaultHttpContext _httpContext;

        [SetUp]
        public void Setup()
        {
            _httpContext = new DefaultHttpContext();
            _httpContext.Connection.RemoteIpAddress = IPAddress.Parse("10.0.0.1");
            Subject.ControllerContext = new ControllerContext { HttpContext = _httpContext };

            var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
            services.AddLogging();
            services.AddSingleton(Mocker.GetMock<IAuthentikTokenValidationService>().Object);
            services.AddSingleton(Mocker.GetMock<ISonarrServiceTokenService>().Object);
            services.AddSingleton(Mocker.GetMock<IUserService>().Object);
            services.AddSingleton(Mocker.GetMock<IUserRepository>().Object);
            _httpContext.RequestServices = services.BuildServiceProvider();

            Mocker.GetMock<ISonarrServiceTokenService>()
                .Setup(s => s.MintToken(It.IsAny<string>(), It.IsAny<SonarrRole>()))
                .Returns("sonarr-token");
            Mocker.GetMock<ISonarrServiceTokenService>()
                .Setup(s => s.ValidateToken(It.IsAny<string>()))
                .Returns((string t) => t == "valid-token" ? new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(new[] { new System.Security.Claims.Claim("sub", "subject-1") }, "test")) : null);
        }

        private void SetSubjectToken(string token)
        {
            _httpContext.Request.Body = new System.IO.MemoryStream();
            if (!string.IsNullOrEmpty(token))
            {
                var json = "{\"subject_token\":\"" + token + "\"}";
                var bytes = System.Text.Encoding.UTF8.GetBytes(json);
                _httpContext.Request.Body.Write(bytes, 0, bytes.Length);
                _httpContext.Request.Body.Position = 0;
            }

            _httpContext.Request.ContentType = "application/json";
            _httpContext.Request.ContentLength = _httpContext.Request.Body.Length;
        }

        [Test]
        public async Task exchange_missing_token_returns_400()
        {
            SetSubjectToken(null);
            var result = await Subject.ExchangeOidc(new OidcExchangeRequest(null));
            var status = (result as Microsoft.AspNetCore.Http.IStatusCodeHttpResult)?.StatusCode;
            status.Should().Be(400);
        }

        [Test]
        public async Task exchange_invalid_authentik_returns_401()
        {
            Mocker.GetMock<IAuthentikTokenValidationService>()
                .Setup(s => s.ValidateAsync("bad"))
                .ReturnsAsync(new AuthentikValidationResult(false, "invalid_token", null, null, new System.Collections.Generic.List<string>()));

            SetSubjectToken("bad");
            var result = await Subject.ExchangeOidc(new OidcExchangeRequest("bad"));
            ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)result).StatusCode.Should().Be(401);
        }

        [Test]
        public async Task exchange_insufficient_group_returns_403()
        {
            Mocker.GetMock<IAuthentikTokenValidationService>()
                .Setup(s => s.ValidateAsync("tok"))
                .ReturnsAsync(new AuthentikValidationResult(true, null, "subject-1", "alice", new System.Collections.Generic.List<string> { "pirates" }));

            SetSubjectToken("tok");
            var result = await Subject.ExchangeOidc(new OidcExchangeRequest("tok"));
            ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)result).StatusCode.Should().Be(403);
        }

        [Test]
        public async Task exchange_success_returns_200()
        {
            Mocker.GetMock<IAuthentikTokenValidationService>()
                .Setup(s => s.ValidateAsync("good"))
                .ReturnsAsync(new AuthentikValidationResult(true, null, "subject-1", "alice", new System.Collections.Generic.List<string> { "homies" }));

            Mocker.GetMock<IUserService>()
                .Setup(s => s.UpsertOidcUser(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<SonarrRole>()))
                .Returns(new User { Username = "alice" });

            SetSubjectToken("good");
            var result = await Subject.ExchangeOidc(new OidcExchangeRequest("good"));
            ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)result).StatusCode.Should().Be(200);
        }

        [Test]
        public async Task exchange_upsert_failure_returns_500_with_fixed_message()
        {
            Mocker.GetMock<IAuthentikTokenValidationService>()
                .Setup(s => s.ValidateAsync("boom"))
                .ReturnsAsync(new AuthentikValidationResult(true, null, "subject-1", "alice", new System.Collections.Generic.List<string> { "homies" }));

            Mocker.GetMock<IUserService>()
                .Setup(s => s.UpsertOidcUser(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<SonarrRole>()))
                .Throws(new System.Exception("secret db error"));

            SetSubjectToken("boom");
            var result = await Subject.ExchangeOidc(new OidcExchangeRequest("boom"));
            NzbDrone.Test.Common.ExceptionVerification.ExpectedErrors(1);
            ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)result).StatusCode.Should().Be(500);

            var ms = new System.IO.MemoryStream();
            var originalBody = _httpContext.Response.Body;
            _httpContext.Response.Body = ms;
            await result.ExecuteAsync(_httpContext);
            ms.Position = 0;
            using var reader = new System.IO.StreamReader(ms);
            var body = await reader.ReadToEndAsync();
            _httpContext.Response.Body = originalBody;
            body.Should().Contain("User provisioning failed");
            body.Should().NotContain("secret db error");
        }

        [Test]
        public void me_invalid_token_returns_401()
        {
            _httpContext.Request.Headers.Authorization = "Bearer bad-token";
            var result = Subject.GetMe();
            ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)result).StatusCode.Should().Be(401);
        }

        [Test]
        public void me_missing_user_returns_404()
        {
            _httpContext.Request.Headers.Authorization = "Bearer valid-token";
            Mocker.GetMock<IUserRepository>()
                .Setup(r => r.FindBySubject("subject-1"))
                .Returns((User)null);

            var result = Subject.GetMe();
            ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)result).StatusCode.Should().Be(404);
        }

        [Test]
        public void me_success_returns_200()
        {
            _httpContext.Request.Headers.Authorization = "Bearer valid-token";
            Mocker.GetMock<IUserRepository>()
                .Setup(r => r.FindBySubject("subject-1"))
                .Returns(new User { Username = "alice", OidcGroups = "homies", Role = SonarrRole.ReadOnly });

            var result = Subject.GetMe();
            ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)result).StatusCode.Should().Be(200);
        }

        [Test]
        public void rate_limit_trips_at_11th()
        {
            var ip = "10.0.0.99";
            _httpContext.Connection.RemoteIpAddress = IPAddress.Parse(ip);
            Mocker.GetMock<IAuthentikTokenValidationService>()
                .Setup(s => s.ValidateAsync(It.IsAny<string>()))
                .ReturnsAsync(new AuthentikValidationResult(true, null, "subject-1", "alice", new System.Collections.Generic.List<string> { "homies" }));
            Mocker.GetMock<IUserService>()
                .Setup(s => s.UpsertOidcUser(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<SonarrRole>()))
                .Returns(new User { Username = "alice" });

            for (var i = 0; i < 10; i++)
            {
                var r = Subject.ExchangeOidc(new OidcExchangeRequest("good" + i)).GetAwaiter().GetResult();
                ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)r).StatusCode.Should().NotBe(429);
            }

            var last = Subject.ExchangeOidc(new OidcExchangeRequest("good")).GetAwaiter().GetResult();
            ((Microsoft.AspNetCore.Http.IStatusCodeHttpResult)last).StatusCode.Should().Be(429);
        }
    }
}
