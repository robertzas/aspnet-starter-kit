// Copyright © 2014-present Kriasoft, LLC. All rights reserved.
// This source code is licensed under the MIT license found in the
// LICENSE.txt file in the root directory of this source tree.

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict;

namespace Server.Models
{
    public class ApplicationDBContext : OpenIddictDbContext<ApplicationUser>
    {
        private string[] roles = new[] { "User", "Manager", "Administrator" };

        UserManager<ApplicationUser> _userManager;
        RoleManager<IdentityRole> _roleManager;
        private readonly ILogger _logger;
        public ApplicationDBContext(DbContextOptions options, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, ILoggerFactory loggerFactory) : base(options)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = loggerFactory.CreateLogger<ApplicationDBContext>();
            this.Seed();
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);
        }
        public async void Seed()
        {
            _logger.LogDebug("in seed");
            this.Database.Migrate();

            var user = new ApplicationUser();
            user.Email = "robertzas@gmail.com";
            await _userManager.CreateAsync(user, "Password123*");

        }
    }
}
