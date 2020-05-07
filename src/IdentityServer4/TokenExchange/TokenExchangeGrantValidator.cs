using System;
using System.Collections.Specialized;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;

namespace Seges.IdentityServer4.TokenExchange
{
    /*
     * Additional constraints:
     * - we only allow authenticated clients (no token exchange in the front end)
     * - we never extend token lifetime, the lifetime of the resulting token is set to the shortest lifetime of (subject_token, actor_token)
     * - as IdSrv does not currently support resource indicators, we do not use them (or audience), we use scopes
     */

    public class TokenRequestErrorDescriptions
    {
        public const string InvalidActorToken = "InvalidActorToken";
        public const string UnsupportedSubjectTokenType = "Unsupported subject token type";
        public const string UnsupportedActorTokenType = "Unsupported actor token type";
        public const string InvalidSubjectToken = "InvalidSubjectToken";
    }

    public class TokenExchangeGrantValidator : IExtensionGrantValidator
    {
        private readonly TypedTokenValidator _typedTokenValidator;
        private readonly ScopeValidator _scopeValidator;
        private readonly ISystemClock _clock;
        private readonly ITokenValidator _validator;
        private readonly ILogger<TokenExchangeGrantValidator> _logger;

        public TokenExchangeGrantValidator(TypedTokenValidator typedTokenValidator, ScopeValidator scopeValidator, ISystemClock clock, ILogger<TokenExchangeGrantValidator> logger)
        {
            _typedTokenValidator = typedTokenValidator;
            _scopeValidator = scopeValidator;
            _clock = clock;
            _logger = logger;
        }


        public async Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            var validationResult = await ValidateTokenExchangeRequestAsync(context);
            if (validationResult.IsError)
            {
                context.Result = new GrantValidationResult(
                    validationResult.Error, 
                    validationResult.ErrorDescription);
            }
            await AuthorizeRequestAsync(validationResult);
            if (validationResult.IsError)
            {
                context.Result = new GrantValidationResult(
                    validationResult.Error,
                    validationResult.ErrorDescription);
            }
            var response = await GenerateResponseAsync(validationResult, context.Request);
            context.Result = response;
        }

        private async Task<TokenExchangeRequestValidationResult> ValidateTokenExchangeRequestAsync(ExtensionGrantValidationContext context)
        {
            var request = context.Request;

            // https://tools.ietf.org/html/rfc8693#section-2.1
            var grantType = request.GrantType;
            var resource = request.Raw.Get("resource");
            var audience = request.Raw.Get("audience");
            var scope = request.Scopes;
            var requestedTokenType = request.Raw.Get("requested_token_type");
            var subjectToken = request.Raw.Get("subject_token");
            var subjectTokenType = request.Raw.Get("subject_token_type");
            var actorToken = request.Raw.Get("actor_token");
            var actorTokenType = request.Raw.Get("actor_token_type");

            // GrantType and Scopes have previously been validated (TODO: Test this)

            // Only subject token passed in = impersonation, results in single-level token with new client/audience/resource/scopes
            // Subject token and actor token passed in = delegation , results in multi-level token with new client/audience/resource/scopes
            var delegationRequested = !string.IsNullOrWhiteSpace(actorTokenType);


            // 2.2.2
            // Any errors related to subject_token and actor_token => invalid_request
            // Any errors related to resource and audience => invalid_target



            //TODO: Look up valid resources and validate

            var validatedRequest = new ValidateTokenExchangeRequest
            {
                IsDelegation = delegationRequested, 
                IsImpersonation = !delegationRequested,
                Resource = resource,
                Audience = audience,
                RequestedTokenType = requestedTokenType,
                // TODO: Figure out if not copying properties causes problems down the line
                ValidatedTokenRequest = context.Request
            };


            TokenValidationResult subjectTokenResult =
                await _typedTokenValidator.ValidateAsync(subjectTokenType, subjectToken);
            TokenValidationResult actorTokenResult = delegationRequested
                ? await _typedTokenValidator.ValidateAsync(actorTokenType, actorToken)
                : null;

            if (subjectTokenResult.IsError)
            {
                return new TokenExchangeRequestValidationResult(
                    validatedRequest, 
                    TokenRequestErrors.InvalidRequest,
                    "figure-out-use-of-error-here",
                    TokenRequestErrorDescriptions.UnsupportedSubjectTokenType);
            }

            var subjectClaims = subjectTokenResult.Claims.ToArray();

            validatedRequest.Sub = subjectClaims.SingleOrDefault(c => c.Type == JwtClaimTypes.Subject)?.Value;

            if (string.IsNullOrWhiteSpace(validatedRequest.Sub))
            {
                return new TokenExchangeRequestValidationResult(
                    validatedRequest,
                    TokenRequestErrors.InvalidRequest,
                    "error",
                    "Subject has missing/empty sub claim");
            }

            var amrs = subjectClaims.Where(c => c.Type == JwtClaimTypes.AuthenticationMethod).Select(c => c.Value).ToArray();
            // IdentityServers GrantValidationResult support at most a single amr claim
            if (amrs.Length != 1)
            {
                return new TokenExchangeRequestValidationResult(
                    validatedRequest,
                    TokenRequestErrors.InvalidRequest,
                    "error",
                    "Subject token has no or more than one (unsupported) amr claim");
            }
            validatedRequest.Amr = amrs.Single();

            
            var exp = subjectClaims
                    .Where(c => c.Type == JwtClaimTypes.Expiration)
                    .Select(c => DateTimeOffset.FromUnixTimeSeconds(long.Parse(c.Value)))
                    .Single();

            // TODO: Consider capping "too long" lifetimes, e.g. more than 1 hour
            // We cannot set expires explicitly (otherwise just set new exp claim to subject token exp), only lifetime
            validatedRequest.SubjectTokenRemainingLifetime = exp - _clock.UtcNow;

            // TODO Additional ClaimSet validation 
            validatedRequest.SubjectClaims = subjectClaims;

            if (delegationRequested)
            {
                if (actorTokenResult.IsError)
                {
                    return new TokenExchangeRequestValidationResult(
                        validatedRequest,
                        TokenRequestErrors.InvalidRequest,
                        "figure-out-use-of-error-here",
                        TokenRequestErrorDescriptions.UnsupportedActorTokenType);
                }
                // TODO Additional ClaimSet validation 
                validatedRequest.ActorClaims = actorTokenResult.Claims.ToArray();
            }

            


            return new TokenExchangeRequestValidationResult(validatedRequest);

        }

        private async Task AuthorizeRequestAsync(TokenExchangeRequestValidationResult tokenExchangeRequestValidationResult)
        {
            var validatedRequest = tokenExchangeRequestValidationResult.ValidatedTokenExchangeRequest;
            //var requestedScopes = validatedRequest.Scopes
            //    .ToArray();
            //var subjectScopes = validatedRequest.SubjectClaims
            //    .Where(c => c.Type == JwtClaimTypes.Scope)
            //    .Select(c => c.Value)
            //    .ToArray();
            //var policyScopes = new[] { "other_api" };
            //_scopeValidator.SetConsentedScopes(subjectScopes.Union(policyScopes));

            var validatedScopes = validatedRequest.ValidatedScopes;
            //_scopeValidator.SetConsentedScopes();
            //var allowedScopes = subjectScopes.Union(policyScopes).ToArray();
            
            //if (allowedScopes)
            //TODO: Authorize that current (client,subjecttoken,actortoken,resource) combo is authorized
            
            //TODO: Implement authorization
            // TODO: Determine which identity scopes, if any, should be included in the response via incoming token, scope and stored policy

            return;
        }

        private async Task<GrantValidationResult> GenerateResponseAsync(
            TokenExchangeRequestValidationResult tokenExchangeRequestValidationResult,
            ValidatedTokenRequest validateTokenRequest)
        {
            var validatedTokenExchangeRequest = tokenExchangeRequestValidationResult.ValidatedTokenExchangeRequest;

            if (!TokenTypes.SupportsOutputType(validatedTokenExchangeRequest.RequestedTokenType))
            {
                return new GrantValidationResult(TokenRequestErrors.InvalidRequest, "requested_token_type is unsupported");
            }

            
            var subjectClaims = validatedTokenExchangeRequest.SubjectClaims;

            // Construct a fresh claimsprincipal
            var userAuthenticationType = "maybepasswordfindvalueinclaimset";
            var userIdentity = new ClaimsIdentity(subjectClaims, userAuthenticationType);

            // Poke contexts ValidateRequest to control various output parameters
            validateTokenRequest.AccessTokenLifetime =
                Convert.ToInt32(validatedTokenExchangeRequest.SubjectTokenRemainingLifetime.TotalSeconds);

            return new GrantValidationResult(validatedTokenExchangeRequest.Sub, validatedTokenExchangeRequest.Amr);
        }

        public string GrantType => OidcConstants.GrantTypes.TokenExchange;
    }
}
