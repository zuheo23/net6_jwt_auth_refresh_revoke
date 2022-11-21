using MongoDB.Bson.Serialization.Attributes;

namespace Emperor.WebApi.Models
{
    public class User
    {
        [BsonId]
        [BsonRepresentation(MongoDB.Bson.BsonType.ObjectId)]
        public string? Id { get; set; }

        [BsonElement("Email")]
        public string Email { get; set; } = null!;

        [BsonElement("Password")]
        public string Password { get; set; } = null!;

        [BsonElement("Roles")]
        public List<string> Roles { get; set; } = new List<string> { "Default" };

        public string? RefreshToken { get; set; }

        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}