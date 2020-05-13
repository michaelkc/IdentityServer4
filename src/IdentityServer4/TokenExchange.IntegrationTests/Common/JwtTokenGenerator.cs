using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;

namespace TokenExchange.IntegrationTests.Common
{
    internal static class JwtTokenGenerator
    {
        public static (JwtSecurityToken Token, string Jwt) CreateToken(string issuer, string audience, SigningCredentials credential, Claim[] claims, DateTime? issuedAt = null, DateTime? notBefore = null, DateTime? expires = null)
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
    }
}