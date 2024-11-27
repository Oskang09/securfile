using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace invoicehub.util
{
    public static class Securfile
    {
        public static string DecryptString(this string cipherValue, string cipherKey, string authKey)
        {
            var ciphers = cipherValue.Split(',');
            if (ciphers.Length != 2)
            {
                throw new Exception("securfile: invalid encrypted value");
            }
            return Decrypt(ciphers[1], ciphers[0], cipherKey, authKey);
        }

        public static string DecryptFile(this string file, string cipherKey, string authKey)
        {
            using (var bufferedReader = new StreamReader(file))
            {
                return DecryptFileByBufferedReader(bufferedReader, cipherKey, authKey);
            }
        }

        public static string DecryptFile(this Stream file, string cipherKey, string authKey)
        {
            using (var bufferedReader = new StreamReader(file))
            {
                return DecryptFileByBufferedReader(bufferedReader, cipherKey, authKey);
            }
        }

        private static string DecryptFileByBufferedReader(StreamReader bufferedReader, string cipherKey, string authKey)
        {
            var cipherValue = bufferedReader.ReadToEnd();
            return DecryptString(cipherValue, cipherKey, authKey);
        }
        private static string Decrypt(string cipherValue, string nonceKey, string cipherKey, string authKey)
        {
            var combined = Convert.FromBase64String(cipherValue);

            var nonce = Encoding.UTF8.GetBytes(nonceKey);
            var tag = new byte[16];
            var ciphertext = new byte[combined.Length - tag.Length];

            Buffer.BlockCopy(combined, 0, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(combined, 0 + ciphertext.Length, tag, 0, tag.Length);

            using (var aesGcm = new AesGcm(Encoding.UTF8.GetBytes(cipherKey), 16))
            {
                var decryptedBytes = new byte[ciphertext.Length];

                if (!string.IsNullOrEmpty(authKey))
                {
                    var authBytes = Encoding.UTF8.GetBytes(authKey);
                    aesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes, authBytes);
                }
                else
                {
                    aesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes);
                }

                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }
}