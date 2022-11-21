namespace Emperor.WebApi.Models
{
    public class AppDatabaseSetting
    {
        public string ConnectionString { get; set; } = null!;

        public string DatabaseName { get; set; } = null!;

        public string ChineseDictionaryCollectionName { get; set; } = null!;

        public string UserCollectionName { get; set; } = null!;

        public string JwtKey { get; set; } = null!;
    }
}
