using IdentityServer4.Configuration;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace TokenExchange.IntegrationTests.Clients.Setup
{
    internal class StartupWithTokenExchange
    {
        public static ICustomTokenRequestValidator CustomTokenRequestValidator { get; set; } 

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();

            var builder = services.AddIdentityServer(options =>
            {
                options.IssuerUri = Constants.Issuer;
                options.Events = new EventsOptions
                {
                    RaiseErrorEvents = true,
                    RaiseFailureEvents = true,
                    RaiseInformationEvents = true,
                    RaiseSuccessEvents = true
                };
            });

            builder.AddInMemoryClients(Clients.Get());
            builder.AddInMemoryIdentityResources(Scopes.GetIdentityScopes());
            builder.AddInMemoryApiResources(Scopes.GetApiScopes());
            builder.AddTestUsers(Users.Get());

            builder.AddDeveloperSigningCredential(persistKey: false);

            builder.AddSecretParser<JwtBearerClientAssertionSecretParser>();
            builder.AddSecretValidator<PrivateKeyJwtSecretValidator>();

            builder.AddTokenExchange();

            // add a custom token request validator if set
            if (CustomTokenRequestValidator != null)
            {
                builder.Services.AddTransient(r => CustomTokenRequestValidator);
            }
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseIdentityServer();
        }
    }
}