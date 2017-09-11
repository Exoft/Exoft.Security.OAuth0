using System;
using System.Collections.Generic;
using System.Text;

namespace SimpleTokenProvider
{
    public class RefreshTokenDto
    {
        public string ClientId { get; set; }

        public string RefreshToken { get; set; }

        public DateTime ExpirationRefreshToken { get; set; }
    }
}