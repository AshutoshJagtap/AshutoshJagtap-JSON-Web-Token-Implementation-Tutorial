using JWT.Authentication_Broker.Model.Contract;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JWT.Authentication_Broker.Model.Service
{
    public class JwtHandler : IJwtHandler
    {
        #region Injectable Member
        private readonly AppsettingConfiguration _settings;
        #endregion

        #region Constructor
        public JwtHandler(IOptions<AppsettingConfiguration> setting)
        {
            _settings = setting.Value;
        }
        #endregion

        #region Public Mothods
        public JwtResponse CreateToken(IList<Claim> claims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SecretKey));
            var username = claims.FirstOrDefault(x => x.Type == ClaimTypes.Name).Value;
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, "Admin"),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            var jwtSecurityToken = new JwtSecurityToken(
                    issuer: _settings.ValidIssuer,
                    audience: _settings.ValidAudience,
                    claims: authClaims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            return new JwtResponse
            {
                Token = token,
                ExpiresAt = DateTime.Now.AddMinutes(30).ToString("dd/MM/yyyy HH:mm:ss"),
            };
        }
        #endregion
    }
}
