using System.Threading.Tasks;
using IdentityServer4.Validation;

namespace TokenExchange.Validators
{
    public class SamlTokenValidator
    {
        public async Task<TokenValidationResult> ValidateSaml1TokenAsync(string token)
        {
            throw new System.NotImplementedException();
        }

        public async Task<TokenValidationResult> ValidateSaml2TokenAsync(string token)
        {
            throw new System.NotImplementedException();
        }
    }
}