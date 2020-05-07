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

        string CreateRequestJwt(string issuer, string audience, SigningCredentials credential, Claim[] claims)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.OutboundClaimTypeMap.Clear();
            
            var token = handler.CreateJwtSecurityToken(
                issuer: issuer,
                audience: audience,
                signingCredentials: credential,
                subject: Identity.Create("pwd", claims));

            token.Header[JwtHeaderParameterNames.Typ] = "at+jwt";

            return handler.WriteToken(token);
        }




        [Fact]
        public async Task Request_with_no_explicit_scopes_should_return_expected_payload()
        {
            var testServerSigningCredentials = await _testServerCredentialStore.GetSigningCredentialsAsync();


            var clientId = "tokenexchange";
            var clientSecret = "secret";
            var sourceScope = "api1";
            var targetScope = "api2";
            var aliceSub = "818727";
            var requestJwt = CreateRequestJwt(
                issuer: "https://idsvr4",
                audience: sourceScope,
                credential: testServerSigningCredentials,
                claims: new[] {
                    new Claim("client_id", clientId),
                    new Claim("scope", sourceScope),
                    new Claim("sub", aliceSub), 
                    new Claim("amr", "pwd"),
                });




            var request = new TokenExchangeTokenRequest
            {
                Address = TokenEndpoint, 
                ClientId = clientId, 
                ClientSecret = clientSecret,
                RequestedTokenType = "urn:ietf:params:oauth:token-type:jwt"
            };
            request.SubjectToken = requestJwt;
            request.SubjectTokenType = "urn:ietf:params:oauth:token-type:jwt";
            var response = await _client.RequestTokenExchangeTokenAsync(request);
            //var response = await _client.RequestClientCredentialsTokenAsync();

            _testOutputHelper.WriteLine("Raw output:");
            _testOutputHelper.WriteLine(response.AccessToken ?? "");
            _testOutputHelper.WriteLine(response.RefreshToken ?? "");
            _testOutputHelper.WriteLine(response.IdentityToken ?? "");
            _testOutputHelper.WriteLine(response.TokenType ?? "");
            _testOutputHelper.WriteLine(response.ErrorDescription ?? "");
            _testOutputHelper.WriteLine(response.Error ?? "");
            //_testOutputHelper.WriteLine(response.HttpErrorReason ?? "");
            _testOutputHelper.WriteLine(response.Raw ?? "");

            response.IsError.Should().Be(false);
            response.ExpiresIn.Should().Be(3600);
            response.TokenType.Should().Be("Bearer");
            response.IdentityToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();

            var payload = GetPayload(response);
            _testOutputHelper.WriteLine("Decoded token payload:");
            foreach (var entry in payload)
            {
                _testOutputHelper.WriteLine("-->{0} = {1}", entry.Key, entry.Value);
            }
            payload.Count().Should().Be(6);
            payload.Should().Contain("iss", "https://idsvr4");
            payload.Should().Contain("client_id", "client");

            var audiences = ((JArray)payload["aud"]).Select(x => x.ToString());
            audiences.Count().Should().Be(2);
            audiences.Should().Contain("api");
            audiences.Should().Contain("other_api");

            var scopes = ((JArray)payload["scope"]).Select(x => x.ToString());
            scopes.Count().Should().Be(3);
            scopes.Should().Contain("api1");
            scopes.Should().Contain("api2");
            scopes.Should().Contain("other_api");
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

            if (!request.Parameters.ContainsKey(OidcConstants.TokenRequest.RequestedTokenType))
            {
                request.Parameters.AddRequired(OidcConstants.TokenRequest.RequestedTokenType, request.RequestedTokenType);
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