namespace Emperor.WebApi.Models
{
    public class TokenApiModel
    {
        public string AccessToken { get; set; } = null!;
        public string? RefreshToken { get; set; } = null!;
    }
}
