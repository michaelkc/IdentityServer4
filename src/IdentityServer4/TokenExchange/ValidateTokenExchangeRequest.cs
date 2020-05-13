using System;
using System.Security.Claims;
using IdentityServer4.Validation;

namespace TokenExchange
{
    internal class ValidateTokenExchangeRequest : ValidatedTokenRequest
    {
        public Claim[] SubjectClaims { get; set; } = new Claim[0];
        public bool IsImpersonation { get; set; }
        public bool IsDelegation { get; set; }
        public ValidatedTokenRequest ValidatedTokenRequest { get; set; }
        public string RequestedTokenType { get; set; }
        public string Audience { get; set; }
        public string Resource { get; set; }
        public Claim[] ActorClaims { get; set; } = new Claim[0];
        public string Sub { get; set; }
        public string Amr { get; set; }
        public TimeSpan SubjectTokenRemainingLifetime { get; set; }
    }
}