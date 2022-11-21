
using Microsoft.AspNetCore.Authentication.JwtBearer;
using MongoDB.Driver;
using System.Security.Claims;

namespace Emperor.WebApi.Services
{
    public class UserValidation : JwtBearerEvents
    {
        private string? Email { get; set; }

        private UserService? _userService { get; set; }

        public UserValidation(UserService userService)
        {
            _userService = userService;
        }

        //public override async Task Forbidden(TokenValidatedContext context)
        //{
        //    try
        //    {

        //    }
        //    catch (Exception ex)
        //    {
        //        context.Fail(new Exception("Forbidden try"));
        //    }
        //}

        public override async Task TokenValidated(TokenValidatedContext context)
        {
            try
            {
                ClaimsPrincipal? userPrincipal = context.Principal;
                if (userPrincipal == null) { context.Fail(new Exception("userPrincipal is null")); }

                if (userPrincipal!.HasClaim(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"))
                {
                    this.Email = userPrincipal.Claims.First(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").Value;
                }

                var user = await _userService!.FindByEmailAsync(this.Email!);

                if (user == null)
                {
                    context.Fail(new Exception("User is null"));
                }
                else
                {
                    if (user.RefreshToken == null)
                    {
                        context.Fail(new Exception(user.RefreshToken));
                    }
                    else
                    {
                        return;
                    }
                }

            }
            catch (Exception)
            {
                context.Fail(new Exception("Invalid principal"));
            }
        }
    }
}
