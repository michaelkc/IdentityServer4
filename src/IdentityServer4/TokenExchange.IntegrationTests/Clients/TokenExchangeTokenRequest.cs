using IdentityModel;
using IdentityModel.Client;

namespace TokenExchange.IntegrationTests.Clients
{
    internal class TokenExchangeTokenRequest : TokenRequest
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
}