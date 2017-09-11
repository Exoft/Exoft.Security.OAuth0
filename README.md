## Exoft.Security.OAuth0 - Start

To start using Exoft.Security.OAuth0 please install nuget package:

```
PM>Install-Package ExoftSecurityOAuth0
```

To see last version please [click here]( https://www.nuget.org/packages/ExoftSecurityOAuth0)


Then you need to initialize UseSimpleTokenProvider in your Startup.cs as following:

```
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));
            var signingKey2 = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey2));
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
                GetRefreshTokenResolver = (options) => GetRefreshToken(options),
                AddRefreshTokenResolver = (options) => AddRefreshToken(options),
                ValidateClientResolver = (clientId, clientSecret) => ValidateClient(clientId, clientSecret)
            });
            
```

- GetRefreshToken, AddRefreshTokenResolver - these methods should implemented on the application side to store and manage RefreshToken.


- ValidateClientResolver - this method need to validate client_id and client_secret.

Also you need to create TokenValidationParameters object and initialize JwtBearerAuthentication like that:

```
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
            
             app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = false,
                TokenValidationParameters = tokenValidationParameters,
            });

```





## Exoft.Security.OAuth0 - Demo


#### Get access token:

 Request method: POST
 
 Url: app_url/token

 Parameters:
- grant_type:password
- username:demo@demo.com
- password:demodemo

Response:

{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 30,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}




#### Refresh access token:

 Request method: POST
 
 Url: app_url/token

Parameters:

- grant_type: refresh_token
- refresh_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...


Response:

{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "expires_in": 30,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}


#### To access to your app you need specify Authorization key in the header of request:

Authorization: bearer your_access_token
