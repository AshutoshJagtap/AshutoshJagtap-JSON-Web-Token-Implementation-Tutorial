namespace JWT.Authentication_Broker.Model.Contract
{
    public class JwtResponse
    {
        public string Token { get; set; }
        public string ExpiresAt { get; set; }
    }
}
