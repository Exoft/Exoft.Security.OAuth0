// Copyright (c) Nate Barbettini. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace SimpleTokenProvider
{
    /// <summary>
    /// Provides options for <see cref="TokenProviderMiddleware"/>.
    /// </summary>
    public class TokenProviderOptions
    {
        /// <summary>
        /// The relative request path to listen on.
        /// </summary>
        /// <remarks>The default path is <c>/token</c>.</remarks>
        public string Path { get; set; } = "/token";

        /// <summary>
        ///  The Issuer (iss) claim for generated tokens.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// The Audience (aud) claim for the generated tokens.
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// The expiration time for the generated access token.
        /// </summary>
        /// <remarks>The default is five minutes (300 seconds).</remarks>
        public TimeSpan ExpirationAccessToken { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// The expiration time for the generated refresh token.
        /// </summary>
        /// <remarks>The default is five minutes (300 seconds).</remarks>
        public TimeSpan ExpirationRefreshToken { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>
        /// The signing key to use when generating tokens.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// The signing key to use when generating refresh tokens.
        /// </summary>
        public SigningCredentials SigningRTokenCredentials { get; set; }

        /// <summary>
        /// Resolves a user identity given a username and password.
        /// </summary>
        public Func<string, string, Task<ClaimsIdentity>> IdentityResolver { get; set; }

        /// <summary>
        /// The relative path for refresh token.
        /// </summary>
        /// <remarks>The default path is <c>/refresh-token</c></remarks>
        public string RefreshPath { get; set; } = "/refresh-token";

        /// <summary>
        /// Generates a random value (nonce) for each generated token.
        /// </summary>
        /// <remarks>The default nonce is a random GUID.</remarks>
        public Func<Task<string>> NonceGenerator { get; set; }
            = new Func<Task<string>>(() => Task.FromResult(Guid.NewGuid().ToString()));

        /// <summary>
        /// Get refresh token from database
        /// </summary>
        public Func<RefreshTokenDto, RefreshTokenDto> GetRefreshTokenResolver { get; set; }

        /// <summary>
        /// Store refresh token in database
        /// </summary>
        public Func<RefreshTokenDto, bool> AddRefreshTokenResolver { get; set; }

        /// <summary>
        /// Validate the client_id/client_secret
        /// </summary>
        public Func<string, string, bool> ValidateClientResolver { get; set; }

    }
}