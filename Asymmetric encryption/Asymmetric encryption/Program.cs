using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static async Task Main(string[] args) // Using async Main for modern .NET style
    {
        // Original message to encrypt
        string originalMessage = "This is a secret message for .NET 9!";
        Console.WriteLine("Original Message: " + originalMessage);

        try
        {
            // Create an RSA instance and generate a key pair
            using RSA rsa = RSA.Create();
            rsa.KeySize = 2048; // 2048-bit key size for security

            // Export the public and private keys
            RSAParameters publicKey = rsa.ExportParameters(includePrivateParameters: false); // Public key only
            RSAParameters privateKey = rsa.ExportParameters(includePrivateParameters: true); // Private key

            // Encrypt with the public key
            byte[] encryptedBytes;
            using (RSA rsaEncryptor = RSA.Create())
            {
                rsaEncryptor.ImportParameters(publicKey); // Load the public key
                byte[] messageBytes = Encoding.UTF8.GetBytes(originalMessage);
                encryptedBytes = rsaEncryptor.Encrypt(messageBytes, RSAEncryptionPadding.OaepSHA256);
            }
            string encryptedMessage = Convert.ToBase64String(encryptedBytes);
            Console.WriteLine("Encrypted Message: " + encryptedMessage);

            // Decrypt with the private key
            byte[] decryptedBytes;
            using (RSA rsaDecryptor = RSA.Create())
            {
                rsaDecryptor.ImportParameters(privateKey); // Load the private key
                decryptedBytes = rsaDecryptor.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
            }
            string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine("Decrypted Message: " + decryptedMessage);
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine("Cryptographic error: " + ex.Message);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Unexpected error: " + ex.Message);
        }
    }
}