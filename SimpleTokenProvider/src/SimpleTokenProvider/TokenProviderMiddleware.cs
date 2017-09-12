// Copyright (c) Nate Barbettini. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
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

        public TokenProviderMiddleware(
            RequestDelegate next,
            IOptions<TokenProviderOptions> options,
            ILoggerFactory loggerFactory)
        {
            _next = next;
            _logger = loggerFactory.CreateLogger<TokenProviderMiddleware>();
            _options = options.Value;


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
            else if (context.Request.Form["grant_type"] == "client_credentials")
            {
                await GeClientCredentialsGrant(context);
                return;
            }

            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Bad request.");
        }

        /// <summary>
        /// Get the access-token by username and password (Scenario 1)
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
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
                await context.Response.WriteAsync("Invalid client information.");
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

            var tokens = GetJwtTokens(claims);

            await WriteTokenResponse(context, tokens[0], tokens[1]);
        }

        /// <summary>
        /// Get the access_token by refresh_token (Scenario 2)
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private async Task IssueRefreshedToken(HttpContext context)
        {
            try
            {
                var rToken = context.Request.Form["refresh_token"].ToString();
                var clientId = context.Request.Form["client_id"].ToString();
                var token = _options.GetRefreshTokenResolver(new RefreshTokenDto() { RefreshToken = rToken, ClientId = clientId });

                if (token == null)
                {
                    var response = new { error = "Can not refresh token" };
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
                    return;
                }

                var now = DateTime.UtcNow;
                var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                var refreshToken = jwtSecurityTokenHandler.ReadToken(rToken);

                // validate token
                if (now > refreshToken.ValidTo)
                {
                    var response = new { error = "Refresh token has been expired." };
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
                    return;
                }

                var claims = ((JwtSecurityToken)refreshToken).Claims;
                var tokens = GetJwtTokens(claims);

                await WriteTokenResponse(context, tokens[0], tokens[1]);
                return;
            }
            catch (Exception ex)
            {
                var response = new { error = "Bad request or invalid token." };
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
                return;
            }
        }

        /// <summary>
        /// This grant is suitable for machine-to-machine authentication where a specific user’s permission to access data is not required.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private async Task GeClientCredentialsGrant(HttpContext context)
        {
            var clientId = context.Request.Form["client_id"];
            var clientSecret = context.Request.Form["client_secret"];

            //validate the client_id/client_secret                                  
            var isClientValidated = _options.ValidateClientResolver(clientId, clientSecret);
            if (!isClientValidated)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid client information.");
                return;
            }

            var now = DateTime.UtcNow;

            // Specifically add the jti (nonce), iat (issued timestamp), and sub (subject/user) claims.
            // You can add other claims here, if you want:
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, clientId),
                new Claim(JwtRegisteredClaimNames.Jti, await _options.NonceGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(now).ToString(), ClaimValueTypes.Integer64)
            };


            var jwt = new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(_options.ExpirationAccessToken),
                signingCredentials: _options.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                token_type = "bearer",
                expires_in = (int)_options.ExpirationAccessToken.TotalSeconds,
                access_token = encodedJwt,
            };

            //Serialize and return the response
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
        }


        /// <summary>
        /// Returns access_token data and store refresh token using delegate
        /// </summary>
        /// <param name="context"></param>
        /// <param name="jwt"></param>
        /// <param name="jwtRefreshToken"></param>
        /// <returns></returns>
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
                expires_in = (int)_options.ExpirationAccessToken.TotalSeconds,
                refresh_token = encodedRefreshJwt
                // refresh_token_expires_in = (int)_options.ExpirationRefreshToken.TotalSeconds,
            };

            // Serialize and return the response
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, _serializerSettings));
        }

        /// <summary>
        /// Generate access_token and refresh_token
        /// </summary>
        /// <param name="claims"></param>
        /// <returns>Array with access_token and refresh_token</returns>
        private JwtSecurityToken[] GetJwtTokens(IEnumerable<Claim> claims)
        {
            if (claims != null && !claims.Any()) return null;

            var now = DateTime.UtcNow;

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

            return new[] { jwt, jwtRefreshToken };

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

            if (options.SigningRTokenCredentials == null)
            {
                throw new ArgumentNullException(nameof(TokenProviderOptions.SigningRTokenCredentials));
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
    }
}
