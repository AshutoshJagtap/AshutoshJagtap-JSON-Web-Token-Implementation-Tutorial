namespace JWT.Authentication_Broker.Model.Contract
{
    public class AppsettingConfiguration
    {
        public string ValidAudience { get; set; }
        public string ValidIssuer { get; set; }
        public string SecretKey { get; set; }
    }
}
