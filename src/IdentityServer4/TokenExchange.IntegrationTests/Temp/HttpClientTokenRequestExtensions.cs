using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel;
using IdentityModel.Client;
using TokenExchange.IntegrationTests.Clients;

namespace TokenExchange.IntegrationTests.Temp
{
    /// <summary>
    /// HttpClient extensions for OAuth token requests
    /// </summary>
    internal static class HttpClientTokenRequestExtensions
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
}