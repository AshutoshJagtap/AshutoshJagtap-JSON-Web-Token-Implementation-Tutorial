using System.Collections.Generic;
using System.Security.Claims;

namespace JWT.Authentication_Broker.Model.Contract
{
    public interface IJwtHandler
    {
        JwtResponse CreateToken(IList<Claim> claims);
        ClaimsPrincipal GetPrincipalFromToken(string token);
        string GetRefreshTokenByUsername(string username);
    }
}
