using JWT.Authentication_Broker.Model.Contract;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWT.Authentication_Broker.Model.Service
{
    public class JwtHandler : IJwtHandler
    {
        #region private Member
        private readonly AppsettingConfiguration _settings;
        private static Dictionary<string, string> usersRefreshTokens = new Dictionary<string, string>();

        #endregion
        #region Constructor
        public JwtHandler(IOptions<AppsettingConfiguration> setting)
        {
            _settings = setting.Value;
        }
        #endregion

        #region Public Mothods
        public JwtResponse CreateToken(IList<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SecretKey));

            var jwtSecurityToken = new JwtSecurityToken(
                    issuer: _settings.ValidIssuer,
                    audience: _settings.ValidAudience,
                    claims: authClaims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);


            var jwtResponse = new JwtResponse
            {
                Token = token,
                ExpiresAt = DateTime.Now.AddMinutes(30).ToString("dd/MM/yyyy HH:mm:ss"),
                RefreshToken = GenerateRefreshToken()
            };

            //Add jwtResponse.RefreshToken into DB against current user
            //if user already have refreshtoken then update it with new jwtResponse.RefreshToken

            if (usersRefreshTokens.ContainsKey(username))
            {
                usersRefreshTokens[username] = jwtResponse.RefreshToken;
            }
            else
            {
                usersRefreshTokens.Add(username, jwtResponse.RefreshToken);
            }
            return jwtResponse;
        }

        public ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _settings.ValidIssuer,
                ValidateAudience = true,
                ValidAudience = _settings.ValidAudience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SecretKey)),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token.");
            }

            return principal;
        }

        public string GetRefreshTokenByUsername(string username)
        {
            return usersRefreshTokens[username];
        }
        #endregion

        #region Private Mothods
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
        #endregion
    }
}
