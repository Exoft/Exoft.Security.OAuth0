# Exoft.Security.OAuth0 - Demo


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
