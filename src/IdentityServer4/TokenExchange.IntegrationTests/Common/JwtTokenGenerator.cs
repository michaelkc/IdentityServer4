using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Stores;
using Microsoft.IdentityModel.Tokens;

namespace TokenExchange.IntegrationTests.Common
{
    internal class TestToken
    {
        public TestToken(JwtSecurityToken typed, string jwt)
        {
            Typed = typed;
            Jwt = jwt;
        }

        public JwtSecurityToken Typed { get; }
        public string Jwt { get; }
    }

    internal class JwtTokenGenerator
    {
        private readonly ISigningCredentialStore _credentialStore;
        private readonly JwtSecurityTokenHandler _handler;

        public JwtTokenGenerator(ISigningCredentialStore credentialStore)
        {
            _credentialStore = credentialStore;
            _handler = new JwtSecurityTokenHandler();
            _handler.InboundClaimTypeMap.Clear();
            _handler.OutboundClaimTypeMap.Clear();
        }

        public async Task<TestToken> Create(params ClaimSet[] orderedClaimSets)
        {
            var credential = await _credentialStore.GetSigningCredentialsAsync();
            var primaryClaimSet =
                orderedClaimSets.FirstOrDefault() ?? 
                throw new Exception("No primary claimset");
            var secondaryClaimSets = orderedClaimSets.Skip(1);

            // Lift of "special" claims needed by handler
            var issuer = GetRequiredString(JwtClaimTypes.Issuer, primaryClaimSet);
            var audience = GetRequiredString(JwtClaimTypes.Audience, primaryClaimSet);
            var issuedAt = GetRequiredDateTime(JwtClaimTypes.IssuedAt, primaryClaimSet);
            var notBefore = GetRequiredDateTime(JwtClaimTypes.NotBefore, primaryClaimSet);
            var expires  = GetRequiredDateTime(JwtClaimTypes.Expiration, primaryClaimSet);
            var tokenType = GetRequiredString(JwtHeaderParameterNames.Typ, primaryClaimSet);

            var subject = CreateNestedIdentity(primaryClaimSet, secondaryClaimSets);

            var typedToken = _handler.CreateJwtSecurityToken(
                issuer: issuer,
                audience: audience,
                signingCredentials: credential,
                subject: subject,
                notBefore: notBefore,
                expires: expires,
                issuedAt: issuedAt);

            typedToken.Header[JwtHeaderParameterNames.Typ] = tokenType;
            var jwt = _handler.WriteToken(typedToken);
            return new TestToken(typedToken, jwt);
        }

        private ClaimsIdentity CreateNestedIdentity(
            ClaimSet primaryClaimSet,
            IEnumerable<ClaimSet> secondaryClaimSets)
        {
            var primaryIdentity =  ConvertToIdentity(primaryClaimSet);
            var currentIdentity = primaryIdentity;

            foreach (var currentClaimset in secondaryClaimSets)
            {
                currentIdentity.Actor = ConvertToIdentity(currentClaimset);
            }

            return primaryIdentity;
        }

        private static ClaimsIdentity ConvertToIdentity(ClaimSet primaryClaimSet)
        {
            return Identity.Create(
                GetRequiredString(JwtClaimTypes.AuthenticationMethod, primaryClaimSet),
                primaryClaimSet
                    .Select(c => new Claim(c.Key, c.Value))
                    .ToArray());
        }

        private static string GetRequiredString(string claimType, ClaimSet primaryClaimSet)
        {
            return primaryClaimSet
                       .Where(c => c.Key == claimType)
                       .Select(c => c.Value)
                       .FirstOrDefault() ??
                   throw new Exception($"Primary claim set missing '{claimType}' claim");
        }

        private static DateTime GetRequiredDateTime(string claimType, ClaimSet primaryClaimSet)
        {
            return EpochTime.DateTime(
                long.Parse(
                    primaryClaimSet
                        .Where(c => c.Key == claimType && long.TryParse(c.Value, out _))
                        .Select(c => c.Value)
                        .FirstOrDefault() ??
                    throw new Exception($"Primary claim set missing '{claimType}' claim or not a long value")
                ));
        }
    }
}