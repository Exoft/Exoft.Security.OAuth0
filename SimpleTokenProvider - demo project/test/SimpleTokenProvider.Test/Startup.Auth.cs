using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Builder.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using SimpleTokenProvider.Test.Models;

namespace SimpleTokenProvider.Test
{
    public partial class Startup
    {
        // The secret key every token will be signed with.
        // Keep this safe on the server!
        private static readonly string secretKey = "9565DF9A29045887BBA658ED322D8735C28F239A76041C20C0C851ED90D28B71";
        private static readonly string secretKey2 = "d8e60aa3-1c45-4b54-8b4e-108571918149";

        private void ConfigureAuth(IApplicationBuilder app, DemoDb db)
        {
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));
            var signingKey2 = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey2));


            var tokenValidationParameters = new TokenValidationParameters
            {
                // The signing key must match!
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,

                // Validate the JWT Issuer (iss) claim
                ValidateIssuer = true,
                ValidIssuer = "ExampleIssuer",

                // Validate the JWT Audience (aud) claim
                ValidateAudience = true,
                ValidAudience = "ExampleAudience",

                // Validate the token expiry
                ValidateLifetime = true,
                
                // If you want to allow a certain amount of clock drift, set that here:
                ClockSkew = TimeSpan.Zero
            };

            app.UseSimpleTokenProvider(new TokenProviderOptions
            {
                Path = "/token",
                Audience = "ExampleAudience",
                Issuer = "ExampleIssuer",
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
                SigningRTokenCredentials = new SigningCredentials(signingKey2, SecurityAlgorithms.HmacSha256),
                IdentityResolver = GetIdentity,
                ExpirationAccessToken = TimeSpan.FromMinutes(0.5),
                ExpirationRefreshToken = TimeSpan.FromMinutes(1),
                GetRefreshTokenResolver = (options) => GetRefreshToken(options, db),
                AddRefreshTokenResolver = (options) => AddRefreshToken(options, db),
                ValidateClientResolver = (clientId, clientSecret) => ValidateClient(clientId, clientSecret, db)
            }, tokenValidationParameters);

            app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = false,
                TokenValidationParameters = tokenValidationParameters,
            });

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = false,
                AuthenticationScheme = "Cookie",
                CookieName = "access_token",
                TicketDataFormat = new CustomJwtDataFormat(SecurityAlgorithms.HmacSha256, tokenValidationParameters)
            });
        }

        private Task<ClaimsIdentity> GetIdentity(string username, string password)
        {
            // Don't do this in production, obviously!
            if (username == "demo@demo.com" && password == "demodemo")
            {
                // get user from db
                return Task.FromResult(new ClaimsIdentity(new GenericIdentity(username, "Token"), new Claim[]{ new Claim(ClaimTypes.Role, "ExoftAdmin") }));
            }

            // Credentials are invalid, or account doesn't exist
            return Task.FromResult<ClaimsIdentity>(null);
        }

        private bool ValidateClient(string clientId, string clientSecret, DemoDb dbContext)
        {
            /* Validated client_id/client_secret
             * 
             * var isValidated = dbContext.Users.Any(x => x.ClientId && x.ClientSecret == clientSecret);
             *
             * return isValidated;
             */
            return true;
        }

        private bool AddRefreshToken(RefreshTokenDto options, DemoDb dbContext)
        {
            dbContext.Add(new RefreshToken()
            {
                ExpirationRefreshToken = options.ExpirationRefreshToken,
                Token = options.RefreshToken,
                ClientId = options.ClientId
            });

            return dbContext.SaveChanges() > 0;
        }

        private RefreshTokenDto GetRefreshToken(RefreshTokenDto options, DemoDb dbContext)
        {
            RefreshToken token;
            if (!string.IsNullOrEmpty(options.ClientId))
            {
                 token = dbContext.RefreshTokens.FirstOrDefault(x => x.Token == options.RefreshToken && x.ClientId == options.ClientId);
            }
            else
            {
                 token = dbContext.RefreshTokens.FirstOrDefault(x => x.Token == options.RefreshToken);
            }

            if (token != null)
            {
                return options;
            }
            return null;
        }
    }
}
