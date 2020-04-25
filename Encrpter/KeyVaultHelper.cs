using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Azure.Services.AppAuthentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Policy;
using System.Threading.Tasks;

namespace Encrpter
{
    public class KeyVaultHelper
    {
        private static readonly AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
        KeyVaultClient keyVaultClient;
        public KeyVaultHelper()
        {
            this.keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
        } 
        public async Task<KeyBundle>CreateKey(string keyVaulturl,string keyname)
        {
            KeyBundle NewKey = await this.keyVaultClient.CreateKeyAsync(keyVaulturl, keyname, "RSA").ConfigureAwait(false);
            return NewKey;
            
        }
        public async Task<KeyBundle>GetKeyfromKeyvault(string keyVaulturl, string keyname)
        {
            KeyBundle keybundle = await this.keyVaultClient.GetKeyAsync(keyVaulturl, keyname).ConfigureAwait(false);
            return keybundle;
            
        }
        public async Task<byte[]> WrapKey(byte[] key_to_be_wrapped,string keyVaulturl, string keyname)
        {
            KeyBundle key_bundle = await GetKeyfromKeyvault(keyVaulturl, keyname);
            string id = key_bundle.KeyIdentifier.Identifier;
            Console.WriteLine(id);
            byte[] wrapped_encryption_key = (await this.keyVaultClient.WrapKeyAsync(id,"RSA-OAEP-256", key_to_be_wrapped).ConfigureAwait(false)).Result;
           // byte[] wrapped_encryption_key = (await this.keyVaultClient.WrapKeyAsync("https://komal-keyvault2.vault.azure.net/keys/keygaurav/ff4c2efae1ba4c5d800e72495e90be66", "RSA-OAEP-256", key_to_be_wrapped).ConfigureAwait(false)).Result;
            return wrapped_encryption_key;
            
        }
        public async Task<byte[]> UnwrapKey(byte[] wrapped_key,string keyVaulturl,string keyname)
        {
            KeyBundle keybundle = await GetKeyfromKeyvault(keyVaulturl, keyname);
            string id = keybundle.KeyIdentifier.Identifier;
            Console.WriteLine(id);
            string unwrap_algo = "RSA-OAEP-256";
            //   byte[] unwrapped_key = (await this.keyVaultClient.UnwrapKeyAsync("https://komal-keyvault2.vault.azure.net/keys/keygaurav/ff4c2efae1ba4c5d800e72495e90be66", unwrap_algo, wrapped_key).ConfigureAwait(false)).Result;
            byte[] unwrapped_key = (await this.keyVaultClient.UnwrapKeyAsync(id, unwrap_algo, wrapped_key).ConfigureAwait(false)).Result;
            return unwrapped_key;
        }
        public async void CreateSecretInKeyvaultTostoreWrappedKey(string  wrapped_key,string keyVaulturl, string secretName)
        {
            await this.keyVaultClient.SetSecretAsync(keyVaulturl, secretName, wrapped_key) ;

        }
        public async Task<SecretBundle> GetSecret(string keyVaulturl, string secretName)
        {
            SecretBundle wrapped_key_stored_as_a_secret = await this.keyVaultClient.GetSecretAsync(keyVaulturl, secretName);
            return wrapped_key_stored_as_a_secret;
        }

    }
}
