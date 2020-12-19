using JWT.Authentication_Broker.Model.Contract;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace JWT.Authentication_Broker.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JwtAuthenticationController : ControllerBase
    {
        #region Injectable Member
        private readonly IJwtHandler _jwtHandler;
        #endregion

        #region Constructor
        public JwtAuthenticationController(IJwtHandler jwtHandler)
        {
            _jwtHandler = jwtHandler;
        }
        #endregion

        #region Actions
        [HttpGet]
        [Route("GenerateToken")]
        public IActionResult GenerateToken(string username, string password)
        {
            if (!(username == "Ashutosh" && password == "Jagtap"))//Check in DB
            {
                return BadRequest("Username and Password are not correct!");
            }

            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, "Admin"),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            var result = _jwtHandler.CreateToken(authClaims);

            return Ok(result);
        }

        [HttpPost()]
        [Route("GenerateRefreshToken")]
        public IActionResult GenerateRefreshToken([FromBody] JwtRequest jwtRequest)
        {
            var principal = _jwtHandler.GetPrincipalFromToken(jwtRequest.Token);
            var username = principal.Identity.Name;

            //retrieve the refresh token from a database.
            var savedRefreshToken = _jwtHandler.GetRefreshTokenByUsername(username);
            if (savedRefreshToken != jwtRequest.RefreshToken)
            {
               return BadRequest("Invalid refresh token");
            }

            var newJwtRefreshToken = _jwtHandler.CreateToken(principal.Claims.ToList());
            return Ok(newJwtRefreshToken);
        }
        #endregion
    }
}
