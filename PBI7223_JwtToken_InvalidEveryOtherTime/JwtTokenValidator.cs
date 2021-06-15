using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using JWT;
using JWT.Serializers;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PBI7223_JwtToken_InvalidEveryOtherTime
{
    public class JwtTokenValidator
    {
        public static void Validate(string jwtToken)
        {
            string publicKey = File.ReadAllText("keys/devpub.key");
            publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "")
                .Replace("-----END PUBLIC KEY-----", "")
                .Replace("\n", "")
                .Replace("\r", "");

            Validate(jwtToken, publicKey);
        }

        private static void Validate(string token, string key)
        {
            //var serializer = new JsonNetSerializer();
            //var urlEncoder = new JwtBase64UrlEncoder();
            //var decoder = new JwtDecoder(serializer, urlEncoder);
            //JwtHeader header = decoder.DecodeHeader<JwtHeader>(token);

            //var typ = header.Typ; // JWT
            //var alg = header.Alg; // RS256
            //var kid = header.Kid; // CFAEAE2D650A6CA9862575DE54371EA980643849


            var keyBytes = Convert.FromBase64String(key);

            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParameters);

                var validationParameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    IssuerSigningKey = new RsaSecurityKey(rsa),

                };

                var handler = new JwtSecurityTokenHandler();
                IdentityModelEventSource.ShowPII = true; //NOTE: more exception info will be available.
                handler.ValidateToken(token, validationParameters, out var validatedToken);
            }
        }
    }
}
