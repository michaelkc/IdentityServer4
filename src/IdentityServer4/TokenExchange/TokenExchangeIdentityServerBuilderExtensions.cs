using Microsoft.Extensions.DependencyInjection;
using TokenExchange;
using TokenExchange.Validators;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class TokenExchangeIdentityServerBuilderExtensions
    {
        /// <summary>
        /// Adds the RFC 8693 Token Exchange grant validator.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddTokenExchange(this IIdentityServerBuilder builder)
        {
            builder.AddExtensionGrantValidator<TokenExchangeGrantValidator>();
            builder.Services.AddTransient<TypedTokenValidator>();
            builder.Services.AddTransient<SamlTokenValidator>();

            return builder;
        }

    }
}
