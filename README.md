## Exoft.Security.OAuth0 - Start

To start using Exoft.Security.OAuth0 please install nuget package:

```
 PM>Install-Package ExoftSecurityOAuth0
```

To see last version please [click here]( https://www.nuget.org/packages/ExoftSecurityOAuth0)


Then you need to invoke the ```AddJwtBearer``` method in the ```ConfigureServices``` method with following parameters:

```
  var tokenValidationParameters = new TokenValidationParameters
  {
      // The signing key must match!
      ValidateIssuerSigningKey = true,
      IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)),

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

      services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options => {
      options.TokenValidationParameters = tokenValidationParameters;
  });
            
```

The next step what you need to do that is configuration ```SimpleTokenProvider``` in the ```Configure``` method and invoke ```UseAuthentication``` method:



```
  app.UseSimpleTokenProvider(new TokenProviderOptions
  {
    Path = "/token",
    Audience = "ExampleAudience",
    Issuer = "ExampleIssuer",
    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)),SecurityAlgorithms.HmacSha256),
    SigningRTokenCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey2)), SecurityAlgorithms.HmacSha256),
    IdentityResolver = GetIdentity,
    ExpirationAccessToken = TimeSpan.FromMinutes(5),
    ExpirationRefreshToken = TimeSpan.FromMinutes(10),
    GetRefreshTokenResolver = (options) => GetRefreshToken(options),
    AddRefreshTokenResolver = (options) => AddRefreshToken(options),
    ValidateClientResolver = (clientId, clientSecret) => ValidateClient(clientId, clientSecret)
  });

  app.UseAuthentication();	

```

- ```GetRefreshTokenResolver```, ```AddRefreshTokenResolver``` - these methods should implemented on the application side to store and manage RefreshToken.


- ```ValidateClientResolver``` - this method need to be implemented to validate client_id and client_secret.





## Exoft.Security.OAuth0 - Demo


#### Get access token

> Request method: POST
>
> Url: app_url/token
>
> Parameters:
> - grant_type:password
> - username:demo@demo.com
> - password:demodemo
>
>Response:
>
>```
>{
>    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
>    "token_type": "bearer",
>    "expires_in": 30,
>    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
>}
>```




#### Refresh access token

 >Request method: POST
 >
> Url: app_url/token
>
>Parameters:
>
>- grant_type: refresh_token
>- refresh_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
>
>
>Response:
>
>```
>{
>    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
>    "token_type": "bearer",
>    "expires_in": 300,
>    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
>}
>```


#### To access to your app you need specify Authorization key in the header of request:

>Authorization: bearer your_access_token


#### Client credentials grant

> Request method: POST
>
> Url: app_url/token
>
>Parameters:
>
>- client_id: sample_client_id
>- client_secret: sample_client_secret
>
>
>Response:
>
>```
>{
>  "token_type": "bearer",
>  "expires_in": 300
>  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",  
>}
>```



