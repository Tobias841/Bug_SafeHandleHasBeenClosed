using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JWT;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Serializers;
//using JWT;
//using JWT.Algorithms;
//using JWT.Serializers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace PBI7223_JwtToken_InvalidEveryOtherTime
{
    public static class TestJwtTokenGenerator
    {
        public static string GetJwtToken()
        {
            var payload = new Dictionary<string, object>
            {
                {"iss", "SomeUrlHere"},
                {"sn", "TestName1"},
                {"givenName", "TestName2"},
                {"nameid", "190210099297"},
                {"iat", (int) (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds}, //{"iat", "1538137524"},
                {"nbf", "1538137464"},
                {"exp", (int) (DateTime.UtcNow.AddYears(1).Subtract(new DateTime(1970, 1, 1))).TotalSeconds}, //{"exp", "1938241124"},
                {"jti", "3bbbd628"},
            };

            string privateKey = File.ReadAllText("keys/devpriv.key");
            var rsaParams = GetRsaParameters(privateKey);
            var encoder = GetRS256JWTEncoder(rsaParams);

            return encoder.Encode(payload, new byte[0]);
        }

        private static RSAParameters GetRsaParameters(string rsaPrivateKey)
        {
            var byteArray = Encoding.ASCII.GetBytes(rsaPrivateKey);
            using (var ms = new MemoryStream(byteArray))
            {
                using (var sr = new StreamReader(ms))
                {
                    // use Bouncy Castle to convert the private key to RSA parameters
                    var pemReader = new PemReader(sr);
                    var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                    return DotNetUtilities.ToRSAParameters(keyPair.Private as RsaPrivateCrtKeyParameters);
                }
            }
        }

        private static IJwtEncoder GetRS256JWTEncoder(RSAParameters rsaParams)
        {
            var csp = new RSACryptoServiceProvider();
            csp.ImportParameters(rsaParams);

            var algorithm = new RS256Algorithm(csp, csp);
            var serializer = new JsonNetSerializer();
            var urlEncoder = new JwtBase64UrlEncoder();
            var encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

            return encoder;
        }
    }
}
