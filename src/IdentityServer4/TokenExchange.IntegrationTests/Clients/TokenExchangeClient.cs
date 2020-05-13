using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using TokenExchange.IntegrationTests.Clients.Setup;
using TokenExchange.IntegrationTests.Common;
using TokenExchange.IntegrationTests.Temp;
using Xunit;
using Xunit.Abstractions;

namespace TokenExchange.IntegrationTests.Clients
{
    public class TokenExchangeClient
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;
        private readonly ISigningCredentialStore _testServerCredentialStore;

        public TokenExchangeClient(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            var builder = new WebHostBuilder()
                .UseStartup<StartupWithTokenExchange>();
            var server = new TestServer(builder);

            _client = server.CreateClient();
            _testServerCredentialStore = (ISigningCredentialStore)server.Services.GetService(typeof(ISigningCredentialStore));
        }

        [Fact]
        public async Task Should_Restrict_TokenExchange_Token_Lifetime_To_SubjectToken_Lifetime()
        {
            var testServerSigningCredentials = await _testServerCredentialStore.GetSigningCredentialsAsync();
            const string clientId = "tokenexchange";
            const string clientSecret = "secret";
            const string sourceScope = "api";
            const string targetScope = "other_api";
            const string aliceSub = "818727";
            const string issuer = Constants.Issuer;
            // Bootstrap token simulated to have been issued 15 minutes ago
            var currentTime = DateTime.UtcNow;
            var subjectTokenIssueTime = currentTime.AddMinutes(-15);
            var subjectTokenExpireTime = subjectTokenIssueTime.AddHours(1);

            var subjectToken = JwtTokenGenerator.CreateToken(
                issuer: issuer,
                audience: sourceScope,
                credential: testServerSigningCredentials,
                claims: new[] {
                    new Claim("client_id", clientId),
                    new Claim("scope", sourceScope),
                    new Claim("sub", aliceSub),
                    new Claim("amr", "pwd"),
                },
                issuedAt: subjectTokenIssueTime,
                notBefore: subjectTokenIssueTime,
                expires: subjectTokenExpireTime
                );

            var request = new TokenExchangeTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = clientId,
                ClientSecret = clientSecret,
                RequestedTokenType = "urn:ietf:params:oauth:token-type:jwt",
                SubjectToken = subjectToken.Jwt,
                Scope = targetScope,
                SubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
            };
            _testOutputHelper.WriteLine("Request:");
            _testOutputHelper.WriteLine(JsonConvert.SerializeObject(new
            {
                request.GrantType,
                request.ClientId,
                request.ClientSecret,
                request.Audience,
                request.Resource,
                request.ActorTokenType,
                request.ActorToken,
                request.SubjectTokenType,
                request.SubjectToken,
                SubjectClaims = subjectToken.Token.Claims.ToDictionary(c => c.Type, c => c.Value)

            }, Formatting.Indented));

            var response = await _client.RequestTokenExchangeTokenAsync(request);
            _testOutputHelper.WriteLine("Response:");
            _testOutputHelper.WriteLine(JsonConvert.SerializeObject(
                new
                {
                    response.Error,
                    response.ErrorDescription,
                    response.TokenType,
                    response.AccessToken,
                    response.ExpiresIn,
                    SubjectClaims = response.IsError ? new Dictionary<string, object>() : GetPayload(response)
                }, Formatting.Indented));

            response.IsError.Should().Be(false);
            ((double)response.ExpiresIn)
                .Should()
                .BeInRange(
                    TimeSpan.FromMinutes(44).TotalSeconds, 
                    TimeSpan.FromMinutes(45).TotalSeconds, 
                    "because processing time will have passed since calculating it");
            response.TokenType.Should().Be("Bearer");
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();

            var payload = GetPayload(response);
            payload.Should().Contain(JwtClaimTypes.Issuer, issuer);
            payload.Should().Contain(JwtClaimTypes.ClientId, clientId);

            payload.Should().Contain(JwtClaimTypes.Audience, targetScope);

            var scopes = ((JArray)payload[JwtClaimTypes.Scope]).Select(x => x.ToString());
            scopes.Count().Should().Be(1);
            scopes.Should().Contain(targetScope);
        }


        private Dictionary<string, object> GetPayload(TokenResponse response)
        {
            var token = response.AccessToken.Split('.').Skip(1).Take(1).First();
            var dictionary = JsonConvert.DeserializeObject<Dictionary<string, object>>(
                Encoding.UTF8.GetString(Base64Url.Decode(token)));

            return dictionary;
        }
    }
}