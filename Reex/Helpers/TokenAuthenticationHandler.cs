using System;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Reex.Models.v1;
using Reex.Services.FirebaseService;

namespace Reex.Helpers
{
    public class TokenAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        #region fields
        private readonly IFirebaseAuthService firebaseAuthService;
        #endregion

        #region constructors
        public TokenAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IFirebaseAuthService firebaseAuthService) : base(options, logger, encoder, clock)
        {
            this.firebaseAuthService = firebaseAuthService;
        }
        #endregion

        #region methods
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
            {
                return AuthenticateResult.Fail("Missing Authorization Header");
            }

            var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);

            if (!authHeader.Scheme.Equals("token", StringComparison.InvariantCultureIgnoreCase))
            {
                return AuthenticateResult.Fail("Invalid Authorization Scheme");
            }

            try
            {
                var user = await firebaseAuthService.GetUser(authHeader.Parameter);

                if (!string.IsNullOrWhiteSpace(user?.Email) && !string.IsNullOrWhiteSpace(user?.UserId))
                {
                    var claims = new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Email),
                        new Claim(ClaimTypes.Name, user.Email),
                        new Claim(CustomClaims.USER_ID, user.UserId.ToString())
                    };

                    var identity = new ClaimsIdentity(claims, Scheme.Name);
                    var principal = new ClaimsPrincipal(identity);
                    var ticket = new AuthenticationTicket(principal, Scheme.Name);

                    return AuthenticateResult.Success(ticket);
                }
                else
                {
                    return AuthenticateResult.Fail("error - invalid token provided");
                }
            }
            catch(Exception ex)
            {
                return AuthenticateResult.Fail("An error occurred during verification");
            }
        }
        #endregion
    }
}
