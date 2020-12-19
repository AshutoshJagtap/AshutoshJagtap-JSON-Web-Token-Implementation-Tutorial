using JWT.Authentication_Broker.Model.Contract;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

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
        public JwtResponse CreateToken(IList<Claim> authClaims)
        {
            X509Certificate2 x509Certificate2 = GetCertificateFromStore();
            if (x509Certificate2 == null)
            {
                return null;
            }
            X509SecurityKey x509SecurityKey = new X509SecurityKey(x509Certificate2);
            var signingCredentials = new SigningCredentials(x509SecurityKey, SecurityAlgorithms.RsaSha256Signature);


            var jwtSecurityToken = new JwtSecurityToken(
                    issuer: _settings.ValidIssuer,
                    audience: _settings.ValidAudience,
                    claims: authClaims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: signingCredentials
                );
            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            return new JwtResponse
            {
                Token = token,
                ExpiresAt = DateTime.Now.AddMinutes(30).ToString("dd/MM/yyyy HH:mm:ss"),
            };
        }
        #endregion

        #region Private Methods
        private X509Certificate2 GetCertificateFromStore()
        {
            X509Store x509Store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                x509Store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection x509Certificate2Collection = x509Store.Certificates;
                //TODO : SerialNumber read from appsettings. 
                X509Certificate2Collection currentCertificate = x509Certificate2Collection.Find(X509FindType.FindBySerialNumber, "7cbe911e7a918317d3925430d1ebac52d435289d", false);
                return currentCertificate.Count == 0 ? null : currentCertificate[0];
            }
            catch (Exception)
            {
                throw;
            }
        }
        #endregion
    }
}
