// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using IdentityModel;
using IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients.Setup;
using IdentityServer.IntegrationTests.Common;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;
using Xunit.Abstractions;

namespace IdentityServer.IntegrationTests.Clients
{
    public class MacTokenExchangeClient
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;
        private SigningCredentials _testServerSigningCredentials;
        private ISigningCredentialStore _testServerCredentialStore;

        public MacTokenExchangeClient(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
            var builder = new WebHostBuilder()
                .UseStartup<Startup>();
            var server = new TestServer(builder);

            _client = server.CreateClient();
            _testServerCredentialStore = (ISigningCredentialStore)server.Services.GetService(typeof(ISigningCredentialStore));
        }

        (JwtSecurityToken Token, string Jwt) CreateToken(string issuer, string audience, SigningCredentials credential, Claim[] claims, DateTime? issuedAt = null, DateTime? notBefore = null, DateTime? expires = null)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.OutboundClaimTypeMap.Clear();
            
            var token = handler.CreateJwtSecurityToken(
                issuer: issuer,
                audience: audience,
                signingCredentials: credential,
                subject: Identity.Create("pwd", claims),
                notBefore: notBefore,
                expires: expires,
                issuedAt: issuedAt);

            token.Header[JwtHeaderParameterNames.Typ] = "at+jwt";
            return (token, handler.WriteToken(token));
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
            const string issuer = "https://idsvr4";
            // Bootstrap token simulated to have been issued 15 minutes ago
            var currentTime = DateTime.UtcNow;
            var subjectTokenIssueTime = currentTime.AddMinutes(-15);
            var subjectTokenExpireTime = subjectTokenIssueTime.AddHours(1);

            var subjectToken = CreateToken(
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

    /// <summary>
    /// HttpClient extensions for OAuth token requests
    /// </summary>
    public static class HttpClientTokenRequestExtensions
    {
        /// <summary>
        /// Sends a token request using the RFC 8693 Token Exchange grant type.
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenResponse> RequestTokenExchangeTokenAsync(this HttpMessageInvoker client,
            TokenExchangeTokenRequest request, CancellationToken cancellationToken = default)
        {
            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.GrantType))
            {
                request.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, request.GrantType);
            }

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.SubjectToken))
            {
                request.Parameters.AddRequired(OidcConstants.TokenRequest.SubjectToken, request.SubjectToken);
            }

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.SubjectTokenType))
            {
                request.Parameters.AddRequired(OidcConstants.TokenRequest.SubjectTokenType, request.SubjectTokenType);
            }

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.ActorToken))
            {
                request.Parameters.AddOptional(OidcConstants.TokenRequest.ActorToken, request.ActorToken);
            }

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.ActorToken))
            {
                request.Parameters.AddOptional(OidcConstants.TokenRequest.ActorToken, request.ActorToken);
            }

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.RequestedTokenType))
            {
                request.Parameters.AddOptional(OidcConstants.TokenRequest.RequestedTokenType, request.RequestedTokenType);
            }

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.Scope))
            {
                request.Parameters.AddOptional(OidcConstants.TokenRequest.Scope, request.Scope);
            }

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.Resource))
            {
                request.Parameters.AddOptional(OidcConstants.TokenRequest.Resource, request.Resource);
            }

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.Audience))
            {
                request.Parameters.AddOptional(OidcConstants.TokenRequest.Audience, request.Audience);
            }

            return await client.RequestTokenAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    public class TokenExchangeTokenRequest : TokenRequest
    {
        public TokenExchangeTokenRequest()
        {
            GrantType = OidcConstants.GrantTypes.TokenExchange;
        }

        public string Resource { get; set; }
        public string Audience { get; set; }
        public string RequestedTokenType { get; set; }
        public string SubjectToken { get; set; }
        public string SubjectTokenType { get; set; }
        public string ActorToken { get; set; }
        public string ActorTokenType { get; set; }
        public string Scope { get; set; }
    }

    internal static class DictionaryExtensions
    {
        public static void AddOptional(this IDictionary<string, string> parameters, string key, string value)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            if (value.IsPresent())
            {
                if (parameters.ContainsKey(key))
                {
                    throw new InvalidOperationException($"Duplicate parameter: {key}");
                }
                else
                {
                    parameters.Add(key, value);
                }
            }
        }

        public static void AddRequired(this IDictionary<string, string> parameters, string key, string value, bool allowEmpty = false)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            if (value.IsPresent())
            {
                if (parameters.ContainsKey(key))
                {
                    throw new InvalidOperationException($"Duplicate parameter: {key}");
                }
                else
                {
                    parameters.Add(key, value);
                }
            }
            else
            {
                if (allowEmpty)
                {
                    parameters.Add(key, "");
                }
                else
                {
                    throw new ArgumentException("Parameter is required", key);
                }
            }
        }
    }

    internal static class InternalStringExtensions
    {
        [DebuggerStepThrough]
        public static bool IsMissing(this string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        [DebuggerStepThrough]
        public static bool IsPresent(this string value)
        {
            return !(value.IsMissing());
        }

        [DebuggerStepThrough]
        public static string EnsureTrailingSlash(this string url)
        {
            if (!url.EndsWith("/"))
            {
                return url + "/";
            }

            return url;
        }

        [DebuggerStepThrough]
        public static string RemoveTrailingSlash(this string url)
        {
            if (url != null && url.EndsWith("/"))
            {
                url = url.Substring(0, url.Length - 1);
            }

            return url;
        }
    }
}