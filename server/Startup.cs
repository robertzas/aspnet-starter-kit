using IdentityServer4;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using server.Migrations;
using Server.Models;
using System;
using System.Collections.Generic;
using System.IO;

namespace Server
{
    public class Startup
    {
        private IHostingEnvironment _env;

        // Load application settings from JSON file(s)
        // https://docs.asp.net/en/latest/fundamentals/configuration.html
        public Startup(IHostingEnvironment env)
        {
            Configuration = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile($"appsettings.json", optional: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .Build();
            _env = env;
        }

        public IConfiguration Configuration { get; set; }

        // Configure IoC container
        // https://docs.asp.net/en/latest/fundamentals/dependency-injection.html
        public void ConfigureServices(IServiceCollection services)
        {
            // https://docs.asp.net/en/latest/security/anti-request-forgery.html
            services.AddAntiforgery(options => options.CookieName = options.HeaderName = "X-XSRF-TOKEN");

            // Register Entity Framework database context
            // https://docs.efproject.net/en/latest/platforms/aspnetcore/new-db.html
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseNpgsql(Configuration.GetConnectionString("DefaultConnection"));
            });

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Identity options.
            services.Configure<IdentityOptions>(options =>
            {
                // Password settings.
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = false;
            });

            services.AddMvcCore()
                .AddAuthorization()
                .AddViews()
                .AddRazorViewEngine()
                .AddJsonFormatters();

            // Claims-Based Authorization: role claims.
            services.AddAuthorization(options =>
            {
                // Policy for dashboard: only administrator role.
                options.AddPolicy("Manage Accounts", policy => policy.RequireClaim("role", "administrator"));
                // Policy for resources: user or administrator role.
                options.AddPolicy("Access Resources", policyBuilder => policyBuilder.RequireAssertion(
                        context => context.User.HasClaim(claim => (claim.Type == "role" && claim.Value == "user")
                           || (claim.Type == "role" && claim.Value == "administrator"))
                    )
                );
            });

            // Adds IdentityServer.
            // The AddTemporarySigningCredential extension creates temporary key material for signing tokens on every start.
            // Again this might be useful to get started, but needs to be replaced by some persistent key material for production scenarios.
            // See the cryptography docs for more information: http://docs.identityserver.io/en/release/topics/crypto.html#refcrypto
            services.AddIdentityServer()
                .AddTemporarySigningCredential()
                .AddInMemoryIdentityResources(new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResource("roles", new List<string> { "role" })
            })
                .AddInMemoryApiResources(new List<ApiResource>
            {
                new ApiResource("WebAPI" ) {
                    UserClaims = { "role" }
                }
            })
                .AddInMemoryClients(new List<Client>
            {
                // http://docs.identityserver.io/en/dev/reference/client.html.
                new Client
                {
                    ClientId = "AngularSPA",
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword, // Resource Owner Password Credential grant.
                    AllowAccessTokensViaBrowser = true,
                    RequireClientSecret = false, // This client does not need a secret to request tokens from the token endpoint.

                    AccessTokenLifetime = 900, // Lifetime of access token in seconds.

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId, // For UserInfo endpoint.
                        IdentityServerConstants.StandardScopes.Profile,
                        "roles",
                        "WebAPI"
                    },
                    AllowOfflineAccess = true // For refresh token.
                }
            })
                .AddAspNetIdentity<ApplicationUser>(); // IdentityServer4.AspNetIdentity.

            services.AddTransient<IDatabaseInitializer, DatabaseInitializer>();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory factory, IDatabaseInitializer databaseInitializer)
        {
            // Configure logging
            // https://docs.asp.net/en/latest/fundamentals/logging.html
            factory.AddConsole(Configuration.GetSection("Logging"));
            factory.AddDebug();

            // Serve static files
            // https://docs.asp.net/en/latest/fundamentals/static-files.html
            app.UseStaticFiles(new StaticFileOptions()
            {
                OnPrepareResponse = (context) =>
                {
                    var headers = context.Context.Response.GetTypedHeaders();
                    headers.CacheControl = new CacheControlHeaderValue
                    {
                        MaxAge = TimeSpan.FromDays(364)
                    };
                },
            });

            // IdentityServer4.AccessTokenValidation: authentication middleware for the API.
            app.UseIdentityServerAuthentication(new IdentityServerAuthenticationOptions
            {
                Authority = "http://localhost:5000/",
                //Authority = "http://angularspawebapi.azurewebsites.net",
                AllowedScopes = { "WebAPI" },

                RequireHttpsMetadata = false
            });

            // Enable external authentication provider(s)
            // https://docs.asp.net/en/latest/security/authentication/sociallogins.html
            app.UseIdentity();

            app.UseIdentityServer();

            // Configure ASP.NET MVC
            // https://docs.asp.net/en/latest/mvc/index.html
            app.UseCors("AllowAllOrigins");

            app.UseMvc(routes =>
            {
                routes.MapRoute("default", "{*url}", new { controller = "Home", action = "Index" });
            });

            databaseInitializer.Seed();
        }

        public static void Main()
        {
            var cwd = Directory.GetCurrentDirectory();
            var web = Path.GetFileName(cwd) == "server" ? "../public" : "public";

            var host = new WebHostBuilder()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseWebRoot(web)
                .UseKestrel()
                .UseIISIntegration()
                .UseStartup<Startup>()
                .Build();

            host.Run();
        }
    }
}