using System.Collections.Generic;
using IdentityServer4.Models;
using IdentityServer4.Validation;

namespace Seges.IdentityServer4.TokenExchange
{
    
    public class TokenExchangeRequestValidationResult : TokenRequestValidationResult
    {
        public TokenRequestErrors TokenRequestError { get; }

        public TokenExchangeRequestValidationResult(ValidateTokenExchangeRequest validatedRequest, Dictionary<string, object> customResponse = null) : base(validatedRequest, customResponse)
        {
        }

        public TokenExchangeRequestValidationResult(ValidateTokenExchangeRequest validatedRequest, TokenRequestErrors tokenRequestError, string error, string errorDescription = null, Dictionary<string, object> customResponse = null) : base(validatedRequest, error, errorDescription, customResponse)
        {
            TokenRequestError = tokenRequestError;
        }

        public ValidateTokenExchangeRequest ValidatedTokenExchangeRequest
        {
            get => (ValidateTokenExchangeRequest)ValidatedRequest;
        }
    }
}