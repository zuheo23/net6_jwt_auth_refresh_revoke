using Emperor.WebApi.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Emperor.WebApi.Services
{
    public class UserService
    {
        private readonly IMongoCollection<User> _userCollection;

        private readonly string _key;

        public UserService(IOptions<AppDatabaseSetting> chineseDictionaryDatabaseSetting)
        {
            var mongoClient = new MongoClient(
                chineseDictionaryDatabaseSetting.Value.ConnectionString);

            var mongoDatabase = mongoClient.GetDatabase(
                chineseDictionaryDatabaseSetting.Value.DatabaseName);

            _userCollection = mongoDatabase.GetCollection<User>(
                chineseDictionaryDatabaseSetting.Value.UserCollectionName);

            _key = chineseDictionaryDatabaseSetting.Value.JwtKey;

            System.Diagnostics.Debug.WriteLine($"UserService:{_key}");
        }

        public async Task<List<User>> GetAsync() =>
            await _userCollection.Find(_ => true).ToListAsync();

        public async Task<User?> GetAsync(string id) =>
            await _userCollection.Find(x => x.Id == id).FirstOrDefaultAsync();

        public async Task CreateAsync(User newUser)
        {
            newUser.Password = SecretHasher.Hash(newUser.Password);

            await _userCollection.InsertOneAsync(newUser);
        }

        public async Task UpdateAsync(string id, User updatedUser) =>
            await _userCollection.ReplaceOneAsync(x => x.Id == id, updatedUser);

        public async Task RemoveAsync(string id) =>
            await _userCollection.DeleteOneAsync(x => x.Id == id);

        public async Task<User?> FindByEmailAsync(string email)
        {
            return await _userCollection.Find(x => x.Email == email).FirstOrDefaultAsync();
        }


        public async Task<(string?, string?, User?)> Authenticate(string email, string password)
        {
            var user = await _userCollection.Find(x => x.Email == email).FirstOrDefaultAsync(); 

            if (user == null) return (null, null, user);

            if (!SecretHasher.Verify(password, user.Password)) return (null, null, user);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, email),
            };

            for (int i = 0; i < user.Roles.Count; i++)
            {
                claims.Add(new Claim(ClaimTypes.Role, user.Roles[i]));
            }

            var token = GenerateAccessToken(claims);

            var refreshToken = GenerateRefreshToken();

            return (token, refreshToken, user);

        }

        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenKey = Encoding.UTF8.GetBytes(_key);

            

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(2),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey),
                    SecurityAlgorithms.HmacSha256Signature)
            };



            var token = tokenHandler.CreateToken(tokenDescriptor);

            System.Diagnostics.Debug.WriteLine($"UserServiceAuthenticate: {token}");
            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        public Task<ClaimsPrincipal> GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_key)),
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
                if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            return Task.FromResult(principal);
            //return principal;
        }

        /**
         * static 
         */

        // https://stackoverflow.com/questions/2138429/hash-and-salt-passwords-in-c-sharp
        public static class SecretHasher
        {
            private const int _saltSize = 16; // 128 bits
            private const int _keySize = 32; // 256 bits
            private const int _iterations = 100000;
            private static readonly HashAlgorithmName _algorithm = HashAlgorithmName.SHA256;

            private const char segmentDelimiter = ':';

            public static string Hash(string secret)
            {
                var salt = RandomNumberGenerator.GetBytes(_saltSize);
                var key = Rfc2898DeriveBytes.Pbkdf2(
                    secret,
                    salt,
                    _iterations,
                    _algorithm,
                    _keySize
                );
                return string.Join(
                    segmentDelimiter,
                    Convert.ToHexString(key),
                    Convert.ToHexString(salt),
                    _iterations,
                    _algorithm
                );
            }

            public static bool Verify(string secret, string hash)
            {
                var segments = hash.Split(segmentDelimiter);
                var key = Convert.FromHexString(segments[0]);
                var salt = Convert.FromHexString(segments[1]);
                var iterations = int.Parse(segments[2]);
                var algorithm = new HashAlgorithmName(segments[3]);
                var inputSecretKey = Rfc2898DeriveBytes.Pbkdf2(
                    secret,
                    salt,
                    iterations,
                    algorithm,
                    key.Length
                );
                return key.SequenceEqual(inputSecretKey);
            }
        }   
    }

}
