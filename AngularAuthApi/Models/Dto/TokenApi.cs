namespace AngularAuthApi.Models.Dto
{
    public class TokenApi
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
    }
}
