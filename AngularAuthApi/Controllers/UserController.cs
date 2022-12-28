using AngularAuthApi.Data;
using AngularAuthApi.Helpers;
using AngularAuthApi.Models;
using AngularAuthApi.Models.Dto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly ApplicationDbContext _authContext;

        public UserController(ApplicationDbContext authContext)
        {
            _authContext = authContext;
        }
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User Obj)
        {
            if(Obj == null)
                return BadRequest();
            var user = await _authContext.users
                .FirstOrDefaultAsync(x => x.Username == Obj.Username);
            if(user == null)
                return NotFound(new {Message="User is not found"});

            if(!PasswordHasher.VerifyPassword(Obj.Password, user.Password))
                return BadRequest(new {Message="Password is Incorrect!"});

            user.Token = CreateJWT(user);
            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(1);
            await _authContext.SaveChangesAsync();

            return Ok(new TokenApi()
            {
               AccessToken =newAccessToken,
               RefreshToken = newRefreshToken
            });
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User Obj)
        {
            if(Obj==null)
                return BadRequest();
            //Check Email
            if (await CheckEmailAsync(Obj.Email))
                return BadRequest(new { Message = "Email Already Exit" });

            //Check UserName
            if (await CheckUserNameAsync(Obj.Username))
                return BadRequest(new { Message = "Username Already Exit" });

            //Check Passwords
            var pass = checkPasswordStrength(Obj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass });


            Obj.Password = PasswordHasher.HashPassword(Obj.Password);
            Obj.Role = "User";
            Obj.Token = "";
            await _authContext.users.AddAsync(Obj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User Register" });
        }
        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUser()
        {
            return Ok( await _authContext.users.ToListAsync());
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApi tokenApi)
        {
            if (tokenApi is null)
                return BadRequest("Invalid Client Request");
            string accessToken = tokenApi.AccessToken;
            string refreshToken = tokenApi.RefreshToken;
            var principal = GetPrincipalFromExpireToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _authContext.users.FirstOrDefaultAsync(u => u.Username == username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest("Invalid Request");
            var newAccessToken = CreateJWT(user);
            var newRefreshToken = CreateRefreshToken();
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApi()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }
        
        private Task<bool> CheckUserNameAsync(string username)
            =>_authContext.users.AnyAsync(x=>x.Username==username);
        private Task<bool> CheckEmailAsync(string email)
            =>_authContext.users.AnyAsync(x=>x.Email==email);
        private string checkPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 8)
                sb.Append("Minimum password length should be 8 " + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
                && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be alphanumerics" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,$,%,&,*,~,(,),//[,\\],?,\\,+,=]"))
                sb.Append("Password should contain special chracter" +Environment.NewLine);
            return sb.ToString();
        }
        private string CreateJWT(User u)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverynice.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,u.Role),
                new Claim(ClaimTypes.Name,$"{u.Username}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescripter = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials,
            };

            var token = jwtTokenHandler.CreateToken(tokenDescripter);
            return jwtTokenHandler.WriteToken(token);
        }
        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);
            var tokenInUser = _authContext.users
                .Any(u => u.RefreshToken == refreshToken);
            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }  
        private ClaimsPrincipal GetPrincipalFromExpireToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverynice.....");
            var tokenValidationParameter = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameter, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("This is Invalid token");
            return principal;

        }
    }
}
