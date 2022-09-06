using IdentityWebApplication.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IdentityWebApplication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly JwtBearerTokenSettings jwtBearerTokenSettings;
        private IMailService _mailService;

        public AuthenticationController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IOptions<JwtBearerTokenSettings> jwtTokenOptions, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IMailService mailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration;
            this.jwtBearerTokenSettings = jwtTokenOptions.Value;
            _mailService = mailService;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel userModel)
        {

            if (!ModelState.IsValid || userModel == null)
            {
                return new BadRequestObjectResult(new { Message = "User Registration Failed" });
            }

            var userExists = await _userManager.FindByEmailAsync(userModel.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status="Error", Message="User already exists."});
            ApplicationUser user = new ApplicationUser()
            {
                Email = userModel.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                FirstName = userModel.FirstName,
                LastName = userModel.LastName,
                UserName = userModel.FirstName+userModel.LastName,
            };

            //var result = await _userManager.CreateAsync(user, userModel.Password);
            var result = await _userManager.CreateAsync(user, userModel.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation Failed." });
            }
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
            if (await _roleManager.RoleExistsAsync(UserRoles.User))
                await _userManager.AddToRoleAsync(user, UserRoles.User);

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            var encodedEmailToken = Encoding.UTF8.GetBytes(token);
            var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);

            string url = $"{_configuration["AppUrl"]}/api/authentication/confirmemail?userid={user.Id}&token={validEmailToken}";

            await _mailService.SendEmailAsync(user.Email, "Confirm your email", $"<h1>Welcome to Auth Demo</h1>" +
                    $"<p>Please confirm your email by <a href='{url}'>Clicking here</a></p>");

            return Ok(new { Message = "User Reigstration Successful. check your email." });
  
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel userModel)
        {
            var identityUser = await _userManager.FindByEmailAsync(userModel.Email);
            if (identityUser != null)
            {
                var userRoles = await _userManager.GetRolesAsync(identityUser);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Email, userModel.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                foreach(var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var authSignKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtBearerTokenSettings:SecretKey"]));

                var token = new JwtSecurityToken(
                                issuer: _configuration["JwtBearerTokenSettings:Issuer"],
                                audience: _configuration["JwtBearerTokenSettings:Audience"],
                                expires: DateTime.Now.AddHours(1),
                                claims: authClaims,
                                signingCredentials: new SigningCredentials(authSignKey, SecurityAlgorithms.HmacSha256));
                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token),
                                expiration = token.ValidTo,
                                User = userModel.Email});
            }
            return Unauthorized();
        }

        [HttpGet]
        //[Route("ConfirmEmail/{userId}/{token}")]
        [Route("ConfirmEmail")]
        public async Task<ContentResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
                return new ContentResult
                {
                    ContentType = "text/html",
                    Content = "<div>User Name is not valid!</div>"
                };

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return new ContentResult
                {
                    ContentType = "text/html",
                    Content = "<div>User Name is not exists!</div>"
                };

            var decodedToken = WebEncoders.Base64UrlDecode(token);
            string normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ConfirmEmailAsync(user, normalToken);

            if (result.Succeeded)
                return new ContentResult
                {
                    ContentType = "text/html",
                    Content = "<div>email confirmed successfully.</div>"
                };

            return new ContentResult
            {
                ContentType = "text/html",
                Content = "<div>Error.Try Again!</div>"
            };
        }
    }
}
