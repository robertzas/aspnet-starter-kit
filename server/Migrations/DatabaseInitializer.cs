using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Server.Models;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace server.Migrations
{
    public class DatabaseInitializer : IDatabaseInitializer
    {
        private string[] roles = new[] { "User", "Manager", "Administrator" };
        private UserManager<ApplicationUser> _userManager;
        private RoleManager<IdentityRole> _roleManager;
        private ApplicationDbContext _context;
        private readonly ILogger _logger;

        public DatabaseInitializer(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, ILoggerFactory loggerFactory, ApplicationDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = loggerFactory.CreateLogger<ApplicationDbContext>();
            _context = context;
        }

        public async Task Seed()
        {
            await _context.Database.MigrateAsync();

            // Creates Roles.
            foreach (var role in new List<string> { "administrator", "user" })
            {
                if (!await _roleManager.RoleExistsAsync(role))
                {
                    await _roleManager.CreateAsync(new IdentityRole(role));
                    await _roleManager.AddClaimAsync(await _roleManager.FindByNameAsync(role), new Claim(JwtClaimTypes.Role, role));
                }
            };

            var user = new ApplicationUser
            {
                GivenName = "Admin",
                FamilyName = "Admin",
                AccessFailedCount = 0,
                Email = "admin@gmail.com",
                EmailConfirmed = false,
                LockoutEnabled = true,
                NormalizedEmail = "ADMIN@GMAIL.COM",
                NormalizedUserName = "ADMIN@GMAIL.COM",
                TwoFactorEnabled = false,
                UserName = "admin@gmail.com"
            };

            var applicationUser = await _userManager.FindByNameAsync(user.UserName);
            if (applicationUser == null)
            {
                await _userManager.CreateAsync(user, "Password123*");
                var adminUser = await _userManager.FindByNameAsync(user.UserName);
                // Assigns the 'administrator' role.
                await _userManager.AddToRoleAsync(adminUser, "administrator");
                // Assigns claims.
                var claims = new List<Claim> {
                    new Claim(type: JwtClaimTypes.GivenName, value: user.GivenName),
                    new Claim(type: JwtClaimTypes.FamilyName, value: user.FamilyName),
                };
                await _userManager.AddClaimsAsync(adminUser, claims);
            }
        }
    }

    public interface IDatabaseInitializer
    {
        Task Seed();
    }
}