using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp;

namespace DSS.Infrastructure.Services
{
    public static class SecureStringHelper
    {
        private static bool _isEncrypted;
        private static bool _useVault;
        private static string _vaultPath = "vault-c";
        private static VaultClient _vaultClient;
        private static readonly byte[] Key = new byte[32]
        {
            0x10, 0x22, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
            0x90, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x01, 0x12,
            0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A,
            0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF1, 0x02, 0x13
        };

        private static readonly byte[] IV = new byte[16]; // use fixed or per-record IV

        public static void Initialize(IConfiguration config)
        {
            _isEncrypted = config.GetValue<bool>("EncryptConnectionStrings", false);
            _useVault = config.GetValue<bool>("UseVault", false);
            if (_useVault)
            {
                var vaultConfig = config.GetSection("Vault");
                var vaultAddress = vaultConfig["Address"];
                var vaultToken = vaultConfig["Token"];
                Console.WriteLine($"Vault Address: {vaultAddress}");
                Console.WriteLine($"Vault token: {vaultToken}");

                var vaultClientSettings = new VaultClientSettings(
                    vaultAddress,
                    new TokenAuthMethodInfo(vaultToken)
                );
                _vaultClient = new VaultClient(vaultClientSettings);

            }
        }

        public static string Encrypt(string plainText)
        {
            using var aes = Aes.Create();
            aes.Key = Key;
            aes.IV = IV;

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static async Task<string> Decrypt(string cipherText)
        {
            string value = "";
            try
            {
                if (_useVault)
                {
                    var secret = await _vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: _vaultPath, mountPoint: "secret");
                  
                    if (secret?.Data?.Data.TryGetValue("sample", out var result) == true)
                    {
                        value = result.ToString();
                    }
                    else
                    {
                        Console.WriteLine("Key not found!");
                        throw new Exception("Key not found in Vault!");
                    }

                    cipherText = value;
                }
                if (_isEncrypted)
                {
                    using var aes = Aes.Create();
                    aes.Key = Key;
                    aes.IV = IV;

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    var cipherBytes = Convert.FromBase64String(cipherText);
                    var decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }

                return cipherText;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Decryption failed: " + ex.Message);
                throw;
            }
        }
    }
}
