using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;

namespace Encrpter
{
    public class EncrptHandler
    {
        public AesManaged aesM;
        public EncrptHandler()
        {
            this.aesM = new AesManaged();
            
        }
        public String EncryptData(String plainText)
        {
            
                // Check arguments.
                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (aesM.Key == null || aesM.Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (aesM.IV == null || aesM.IV.Length <= 0)
                    throw new ArgumentNullException("IV");
                byte[] encrypted;

                // Create an AesManaged object
                // with the specified key and IV.
                
     

                    // Create an encryptor to perform the stream transform.
                    ICryptoTransform encryptor = aesM.CreateEncryptor(aesM.Key, aesM.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }

                string enString = Convert.ToBase64String(encrypted);
                // Return the encrypted bytes from the memory stream.
                return enString;
        }
        public string DecryptData(String Data)
        {
            byte[] cipherText = Convert.FromBase64String(Data);

            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (aesM.Key == null || aesM.Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (aesM.IV == null || aesM.IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an AesManaged object
            // with the specified key and IV.
            
                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesM.CreateDecryptor(aesM.Key, aesM.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            

            return plaintext;

        }
        public string DecryptData(String Data,byte[] aesK)
        {
            byte[] cipherText = Convert.FromBase64String(Data);

            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (aesK == null || aesK.Length <= 0)
                throw new ArgumentNullException("Key");
            if (aesM.IV == null || aesM.IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an AesManaged object
            // with the specified key and IV.

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesM.CreateDecryptor(aesK, aesM.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }


            return plaintext;

        }
    }
}
