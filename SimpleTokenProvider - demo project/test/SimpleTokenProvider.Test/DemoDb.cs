using Microsoft.EntityFrameworkCore;
using SimpleTokenProvider.Test.Models;

namespace SimpleTokenProvider.Test
{
    public class DemoDb : DbContext
    {
        public DemoDb(DbContextOptions<DemoDb> options) : base(options)
        {
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
