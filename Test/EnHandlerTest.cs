using Microsoft.VisualStudio.TestTools.UnitTesting;
using Encrpter;
using System;
using Microsoft.Azure.KeyVault.Models;

namespace Test
{
    [TestClass]
    public class EnHandlerTest
    {
        [TestMethod]
        public async System.Threading.Tasks.Task TestMethod1Async()
        {
            KeyVaultHelper helper = new KeyVaultHelper();

            EncrptHandler e = new EncrptHandler();

            string ed=e.EncryptData("gaurav");
            string keyVaulturl= "https://gaurav-1.vault.azure.net/";
            string keyname="gaurav-key1";
            KeyBundle x= await helper.CreateKey(keyVaulturl, keyname);

            byte[] wrapped_key = await helper.WrapKey(e.aesM.Key, keyVaulturl, keyname);
            string secretname = "gaurav-secret";

          string value = Convert.ToBase64String(wrapped_key);
          helper.CreateSecretInKeyvaultTostoreWrappedKey(value, keyVaulturl, secretname);
            string wrapped_Aes_key_which_is_stored_in_keyvault = (await helper.GetSecret(keyVaulturl, secretname)).Value;
            Console.WriteLine(wrapped_Aes_key_which_is_stored_in_keyvault);
            //Console.WriteLine("llalla");
            Console.WriteLine(value);
            byte[] wrapped_aes_key_which_is_stored_in_keyvault= Convert.FromBase64String(wrapped_Aes_key_which_is_stored_in_keyvault);
           
            byte[] aesKey = await helper.UnwrapKey(wrapped_aes_key_which_is_stored_in_keyvault, keyVaulturl, keyname);

            string dd=e.DecryptData(ed,aesKey);
            Assert.AreEqual("gaurav", dd);
            Console.WriteLine(ed);
            Console.WriteLine(dd);

        }
    }
}
