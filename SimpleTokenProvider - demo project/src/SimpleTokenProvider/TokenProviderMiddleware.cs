// Copyright (c) Nate Barbettini. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace SimpleTokenProvider
{
    /// <summary>
    /// Token generator middleware component which is added to an HTTP pipeline.
    /// This class is not created by application code directly,
    /// instead it is added by calling the <see cref="TokenProviderAppBuilderExtensions.UseSimpleTokenProvider(Microsoft.AspNetCore.Builder.IApplicationBuilder, TokenProviderOptions)"/>
    /// extension method.
    /// </summary>
    public class TokenProviderMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly TokenProviderOptions _options;
        private readonly ILogger _logger;
        private readonly JsonSerializerSettings _serializerSettings;
        private readonly TokenValidationParameters _tokenValidationParameters;

        public TokenProviderMiddleware(
            RequestDelegate next,
            IOptions<TokenProviderOptions> options,
            ILoggerFactory loggerFactory, TokenValidationParameters tokenValidationParameters)
        {
            _next = next;
            _logger = loggerFactory.CreateLogger<TokenProviderMiddleware>();
            _tokenValidationParameters = tokenValidationParameters;
            _options = options.Value;

            if (tokenValidationParameters == null)
            {
                throw new ArgumentNullException(nameof(tokenValidationParameters));
            }
            ThrowIfInvalidOptions(_options);

            _serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };
        }

        public async Task Invoke(HttpContext context)
        {
            // If the request path doesn't match, skip
            if (!context.Request.Path.Equals(_options.Path, StringComparison.Ordinal))
            {
                await _next(context);
                return;
            }


            // Request must be POST with Content-Type: application/x-www-form-urlencoded
            if (!context.Request.Method.Equals("POST")
               || !context.Request.HasFormContentType)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Bad request.");
                return;
            }

            _logger.LogInformation("Handling request: " + context.Request.Path);

            if (context.Request.Form["grant_type"] == "password")
            {
                await GenerateToken(context);
                return;
            }
            else if (context.Request.Form["grant_type"] == "refresh_token")
            {
                await IssueRefreshedToken(context); 
                return;
            }

            //return GenerateToken(context);
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Bad request.");
        }

        //scenario 1 ： get the access-token by username and password
        private async Task GenerateToken(HttpContext context)
        {
            var username = context.Request.Form["username"];
            var password = context.Request.Form["password"];
            var clientId = context.Request.Form["client_id"];
            var clientSecret = context.Request.Form["client_secret"];

            var identity = await _options.IdentityResolver(username, password);
            if (identity == null)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid username or password.");
                return;
            }

            //validate the client_id/client_secret                                  
            var isClientValidated = _options.ValidateClientResolver(clientId, clientSecret);
            if (!isClientValidated)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid client infomation.");
                return;
            }

            var now = DateTime.UtcNow;

            // Specifically add the jti (nonce), iat (issued timestamp), and sub (subject/user) claims.
            // You can add other claims here, if you want:
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, await _options.NonceGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(now).ToString(), ClaimValueTypes.Integer64)
            };

            claims.AddRange(identity.Claims);

            // Create the access token 
            var jwt = new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(_options.ExpirationAccessToken),
                signingCredentials: _options.SigningCredentials);

            // Create the refresh token 
            var jwtRefreshToken = new JwtSecurityToken(
                claims: claims,
                notBefore: now,
                expires: now.Add(_options.ExpirationRefreshToken),
                signingCredentials: _options.SigningRTokenCredentials);


            await WriteTokenResponse(context, jwt, jwtRefreshToken);
        }

        //scenario 2 ： get the access_token by refresh_token
        private async Task IssueRefreshedToken(HttpContext context)
        {
            try
            {
                var rToken = context.Request.Form["refresh_token"].ToString();
                var clientId = context.Request.Form["client_id"].ToString();

                var token = _options.GetRefreshTokenResolver(new RefreshTokenDto() {RefreshToken = rToken, ClientId = clientId });

                if (token == null)
                {
                    var response = new {error = "Can not refresh token"};
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
                    return;
                }



                // validate token using validation parameters

                var now = DateTime.UtcNow;

                var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

                var refreshToken = jwtSecurityTokenHandler.ReadToken(rToken);

                if (now > refreshToken.ValidTo)
                {
                    var response = new { error = "Refresh token has been expired." };
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
                    return;
                }


                // create a new token based on original one 
                // apply new expiration
                var jwt = new JwtSecurityToken(
                    issuer: _options.Issuer,
                    audience: _options.Audience,
                    claims: ((JwtSecurityToken)refreshToken).Claims,
                    notBefore: now,
                    expires: now.Add(_options.ExpirationAccessToken),
                    signingCredentials: _options.SigningCredentials);


                // Create the refresh token 
                var jwtRefreshToken = new JwtSecurityToken(
                    claims: ((JwtSecurityToken)refreshToken).Claims,
                    notBefore: now,
                    expires: now.Add(_options.ExpirationRefreshToken),
                    signingCredentials: _options.SigningRTokenCredentials);


                await WriteTokenResponse(context, jwt, jwtRefreshToken);
                return;
            }
            catch (Exception ex)
            {
                var response = new {error = "Bad request or invalid token."};
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
                return;
            }
        }


        private static void ThrowIfInvalidOptions(TokenProviderOptions options)
        {
            if (string.IsNullOrEmpty(options.Path))
            {
                throw new ArgumentNullException(nameof(TokenProviderOptions.Path));
            }

            if (string.IsNullOrEmpty(options.Issuer))
            {
                throw new ArgumentNullException(nameof(TokenProviderOptions.Issuer));
            }

            if (string.IsNullOrEmpty(options.Audience))
            {
                throw new ArgumentNullException(nameof(TokenProviderOptions.Audience));
            }

            if (options.ExpirationAccessToken == TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(TokenProviderOptions.ExpirationAccessToken));
            }

            if (options.ExpirationRefreshToken == TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(TokenProviderOptions.ExpirationRefreshToken));
            }

            if (options.IdentityResolver == null)
            {
                throw new ArgumentNullException(nameof(TokenProviderOptions.IdentityResolver));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(TokenProviderOptions.SigningCredentials));
            }

            if (options.NonceGenerator == null)
            {
                throw new ArgumentNullException(nameof(TokenProviderOptions.NonceGenerator));
            }
        }

        /// <summary>
        /// Get this datetime as a Unix epoch timestamp (seconds since Jan 1, 1970, midnight UTC).
        /// </summary>
        /// <param name="date">The date to convert.</param>
        /// <returns>Seconds since Unix epoch.</returns>
        public static long ToUnixEpochDate(DateTime date) => new DateTimeOffset(date).ToUniversalTime().ToUnixTimeSeconds();

        private async Task WriteTokenResponse(HttpContext context, JwtSecurityToken jwt, JwtSecurityToken jwtRefreshToken)
        {
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
            var encodedRefreshJwt = new JwtSecurityTokenHandler().WriteToken(jwtRefreshToken);
            var clientId = context.Request.Form["client_id"];


            _options.AddRefreshTokenResolver(new RefreshTokenDto
            {
                RefreshToken = encodedRefreshJwt,
                ExpirationRefreshToken = jwtRefreshToken.ValidTo,
                ClientId = clientId
            });

            var response = new
            {
                access_token = encodedJwt,
                token_type = "bearer",
                expires_in = (int) _options.ExpirationAccessToken.TotalSeconds,
                refresh_token = encodedRefreshJwt
               // refresh_token_expires_in = (int)_options.ExpirationRefreshToken.TotalSeconds,
            };

            // Serialize and return the response
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
        }
    }
}
