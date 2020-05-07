using System.Linq;

namespace Seges.IdentityServer4.TokenExchange
{
    public class TokenTypes
    {

        public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";
        public const string RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";
        public const string IdToken = "urn:ietf:params:oauth:token-type:id_token";
        public const string Saml1 = "urn:ietf:params:oauth:token-type:saml1";
        public const string Saml2 = "urn:ietf:params:oauth:token-type:saml2";
        public const string Jwt = "urn:ietf:params:oauth:token-type:jwt";

        public static bool SupportsInputType(string tokenType) => new[] {Jwt}.Contains(tokenType);
        public static bool SupportsOutputType(string tokenType) => new[] { Jwt }.Contains(tokenType);
    }
}