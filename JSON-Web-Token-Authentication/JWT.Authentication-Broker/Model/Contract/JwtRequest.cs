namespace JWT.Authentication_Broker.Model.Contract
{
    public class JwtRequest
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }
}
