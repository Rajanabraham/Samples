using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            Console.WriteLine("=== SSL/TLS Handshake Simulation ===");
            Console.WriteLine("(Simplified version for educational purposes)\n");

            // Simulated certificate (in real life this would contain server's public key and identity)
            string serverCertificate = "SIMULATED_CERTIFICATE: trust_this_server.com";

            // ----------------------------------
            // Handshake Phase 1: Initial Negotiation
            // ----------------------------------
            Console.WriteLine("[Client] Sending CLIENT HELLO:");
            Console.WriteLine(" - Supported TLS version");
            Console.WriteLine(" - List of cipher suites\n");

            Console.WriteLine("[Server] Responds with SERVER HELLO:");
            Console.WriteLine(" - Choosen TLS version");
            Console.WriteLine(" - Selected cipher suite");
            Console.WriteLine(" - Sending server certificate\n");
            Console.WriteLine($"   Server Certificate: {serverCertificate}\n");

            // ----------------------------------
            // Handshake Phase 2: Key Exchange
            // ----------------------------------
            // Server generates long-term RSA keys (in real life, these would come from the certificate)
            using (RSACryptoServiceProvider serverRSA = new RSACryptoServiceProvider())
            {
                // Server's public key (normally embedded in the certificate)
                string serverPublicKey = serverRSA.ToXmlString(false);

                // Client verifies certificate (simplified)
                Console.WriteLine("[Client] Verifies server certificate...");
                Console.WriteLine(" - Check validity period");
                Console.WriteLine(" - Check issuing authority");
                Console.WriteLine(" - Extract server's public key from certificate\n");

                // Client generates session key (AES)
                using (Aes aes = Aes.Create())
                {
                    aes.GenerateKey();
                    byte[] sessionKey = aes.Key;

                    Console.WriteLine("[Client] Creates SESSION KEY for secure communication:");
                    Console.WriteLine($"   AES Session Key: {Convert.ToBase64String(sessionKey)}\n");

                    // Client encrypts session key with server's public key
                    byte[] encryptedSessionKey = serverRSA.Encrypt(sessionKey, false);
                    Console.WriteLine("[Client] Encrypts session key with server's public key:");
                    Console.WriteLine($"   Encrypted Session Key: {Convert.ToBase64String(encryptedSessionKey)}\n");
                    Console.WriteLine("[Client] Sends encrypted session key to server\n");

                    // ----------------------------------
                    // Handshake Phase 3: Final Setup
                    // ----------------------------------
                    Console.WriteLine("[Server] Decrypts session key with server's private key");
                    byte[] decryptedSessionKey = serverRSA.Decrypt(encryptedSessionKey, false);
                    Console.WriteLine($"   Decrypted Session Key: {Convert.ToBase64String(decryptedSessionKey)}\n");

                    Console.WriteLine("[Server] Sends SERVER FINISHED message:");
                    Console.WriteLine(" - Indicates handshake is complete");
                    Console.WriteLine(" - Verification that keys work properly\n");

                    Console.WriteLine("[Client] Sends CLIENT FINISHED message:");
                    Console.WriteLine(" - Verifies handshake succeeded\n");

                    // ----------------------------------
                    // Secure Communication Phase
                    // ----------------------------------
                    Console.WriteLine("=== Secure Communication Established ===");
                    Console.WriteLine("Both parties now use the same session key for encryption\n");

                    string secretMessage = "This is a super secret message!";
                    Console.WriteLine("[Client] Sending encrypted message:");
                    Console.WriteLine($"   Original: {secretMessage}");

                    // Encrypt and send
                    byte[] encryptedMessage = EncryptWithSessionKey(secretMessage, sessionKey);
                    Console.WriteLine($"   Encrypted: {Convert.ToBase64String(encryptedMessage)}\n");

                    // Receive and decrypt
                    Console.WriteLine("[Server] Received message. Decrypting...");
                    string decryptedMessage = DecryptWithSessionKey(encryptedMessage, sessionKey);
                    Console.WriteLine($"   Decrypted: {decryptedMessage}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    static byte[] EncryptWithSessionKey(string message, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV();

            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(aes.IV, 0, aes.IV.Length);
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (StreamWriter sw = new StreamWriter(cs))
                {
                    sw.Write(message);
                }
                return ms.ToArray();
            }
        }
    }

    static string DecryptWithSessionKey(byte[] encryptedData, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            byte[] iv = new byte[aes.IV.Length];
            Array.Copy(encryptedData, 0, iv, 0, iv.Length);
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream(encryptedData, iv.Length, encryptedData.Length - iv.Length))
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }
}