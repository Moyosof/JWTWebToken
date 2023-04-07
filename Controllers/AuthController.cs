using BCrypt.Net;
using JwtWebApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        //To create a JSON web token, we first write a register method where we use BCrypt to hash the password of the use, then
        //we write a Login method to verify the user, only if the credentials are correct
        

        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }



        //registration method using BCrypt.Net-Next package

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            string passwordHash
                = BCrypt.Net.BCrypt.HashPassword(request.Password);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }


        [HttpPost("Login")]
        public ActionResult<User> Login(UserDto request)
        {
            //check if the username exist
            if (user.Username != request.Username)
            {
                return BadRequest("User not found");
            }

            //check if the password matches with the password, but the key<Verify> helps to check the hash
            if(!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return BadRequest("Wrong password");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        List

        //write a method to create a claim for the token
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "User"),
            };

            //to create Json web token
            //secure your Token in the appsetting
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value!));

            // a signing credentials
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: cred
                );
                
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
