using System;
using System.Threading.Tasks;
using IdentityServer4.Validation;

namespace Seges.IdentityServer4.TokenExchange
{
    public class TypedTokenValidator
    {
        private readonly ITokenValidator _tokenValidator;
        private readonly SamlTokenValidator _samlTokenValidator;

        public TypedTokenValidator(ITokenValidator tokenValidator, SamlTokenValidator samlTokenValidator)
        {
            _tokenValidator = tokenValidator;
            _samlTokenValidator = samlTokenValidator;
        }

        public async Task<TokenValidationResult> ValidateAsync(string tokenType, string token) =>
            tokenType switch
            {
                TokenTypes.Jwt => await _tokenValidator.ValidateAccessTokenAsync(token),
                TokenTypes.RefreshToken => await _tokenValidator.ValidateRefreshTokenAsync(token),
                TokenTypes.IdToken => await _tokenValidator.ValidateIdentityTokenAsync(token),
                TokenTypes.Saml1 => await _samlTokenValidator.ValidateSaml1TokenAsync(token),
                TokenTypes.Saml2 => await _samlTokenValidator.ValidateSaml2TokenAsync(token),
                _ => new TokenValidationResult {IsError = true, ErrorDescription = "unsupported token type"}
            };
    }
}