using Emperor.WebApi.Models;
using Emperor.WebApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using System.Security.Claims;

namespace Emperor.WebApi.Controllers
{
    [Authorize(Roles = "Default")]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserService _userService;

        public UserController(UserService userService)
        {
            _userService = userService;
        }

        [HttpGet]
        public async Task<List<User>> Get() =>
            await _userService.GetAsync();

        [HttpGet("{id:length(24)}")]
        public async Task<ActionResult<User>> Get(string id)
        {
            var user = await _userService.GetAsync(id);

            if (user is null)
            {
                return NotFound();
            }

            return user;
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Post(User user)
        {
            // check user exists
            var existingUser = await _userService.FindByEmailAsync(user.Email);

            if (existingUser != null) { return StatusCode(409); }

            await _userService.CreateAsync(user);

            return CreatedAtAction(nameof(Get), new { id = user.Id }, user);
        }

        [HttpPut("{id:length(24)}")]
        public async Task<IActionResult> Update(string id, User updatedUser)
        {
            var user = await _userService.GetAsync(id);

            if (user is null)
            {
                return NotFound();
            }

            updatedUser.Id = user.Id;

            await _userService.UpdateAsync(id, user);

            return NoContent();
        }

        [HttpDelete("{id:length(24)}")]
        public async Task<IActionResult> Delete(string id)
        {
            var user = await _userService.GetAsync(id);

            if (user is null)
            {
                return NotFound();
            }

            await _userService.RemoveAsync(id);

            return NoContent();
        }


        [AllowAnonymous]
        [HttpPost("authenticate")]
        public async Task<IActionResult> Login(User userX)
        {
            (string? token, string? refreshToken, var user) = await _userService.Authenticate(userX.Email, userX.Password);

            //System.Diagnostics.Debug.WriteLine($"UserController: {token}");
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
            await _userService.UpdateAsync(user.Id!, user);

            if (token == null) { return Unauthorized(); }

            return Ok(new TokenApiModel{ AccessToken = token, RefreshToken = refreshToken });
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh( TokenApiModel tokenApiModel)
        {
            var principal = await _userService.GetPrincipalFromExpiredToken(tokenApiModel.AccessToken);
            var email = principal.Claims.ElementAt(0).Value;
            var refreshToken = tokenApiModel.RefreshToken;

            var user = await _userService.FindByEmailAsync(email);

            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest("Invalid client request");

            var newAccessToken = _userService.GenerateAccessToken(principal.Claims);
            var newRefreshToken = _userService.GenerateRefreshToken();
            user.RefreshToken = newRefreshToken;

            await _userService.UpdateAsync(user.Id!, user);

            return Ok(new TokenApiModel{ AccessToken = newAccessToken, RefreshToken = refreshToken });

         }

        [HttpPost("revoke")]
        public async Task<IActionResult> Revoke()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            string? email = null;
            if (identity != null)
            {
                IEnumerable<Claim> claims = identity.Claims;
                email = claims.ElementAt(0).Value;
                // or
                //email = identity!.FindFirst("Email")!.Value!;

            }

            if (email == null)
            {
                return BadRequest("Invalid email");
            }

            var user = await _userService.FindByEmailAsync(email);
            if (user == null) return BadRequest();
            user.RefreshToken = null;
            await _userService.UpdateAsync(user.Id!, user);
            return NoContent();
        }
    }
}
