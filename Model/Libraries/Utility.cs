using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using BCrypt.Net;
using Microsoft.IdentityModel.Tokens;

namespace SecurityBoxFunctions.Library
{
    public static class Utilities
    {
        /// <summary>
        /// Hash String using BCrypt
        /// </summary>
        /// <param name="inputString">String to hash</param>
        /// <returns>Hashed value</returns>
        public static string HashString(string inputString)
        {
            return BCrypt.Net.BCrypt.HashPassword(inputString);
        }

        /// <summary>
        /// Verify hash value
        /// </summary>
        /// <param name="hashedString">String hashed and stored in DB</param>
        /// <param name="inputString">String to compare</param>
        /// <returns>True if value is valid</returns>
        public static bool IsValidHash(string hashedString, string inputString)
        {
            try
            {
                return BCrypt.Net.BCrypt.Verify(hashedString, inputString);
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static string GenerateJWTToken(string data, string jwt_key, string jwt_issuer, string jwt_audience)
        {
            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, data),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, data)
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt_key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwt_issuer,
                audience: jwt_audience,
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}