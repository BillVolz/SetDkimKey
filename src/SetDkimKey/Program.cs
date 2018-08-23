using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using SetDkimKey.AccountSettings;
using SetDkimKey.UtilsService;

namespace SetDkimKey
{
    class Program
    {
        static void Main(string[] args)
        {
            var settingsKeyForDomain = "customerexample.com" + "~*~" + "dkim";

            var encryptionClient = new UtilsService.PrivateServiceSoapClient("PrivateServiceSoap","http://localhost:8086/sl.asmx");
            
            //Encrypted the Test Key on the server using the machines machine key.
            var encryptedKey =encryptionClient.EncryptDomainKey(TestPrivateKey);

            Console.WriteLine("Encrypted Key: {0}",encryptedKey);

            var accountSettings = new AccountSettings.AccountServiceSoapClient("AccountServiceSoap","http://localhost:8086/AccountSettings.asmx");
                
            var settings = new List<SettingKeyValuePair>();

            settings.Add(new SettingKeyValuePair() {Key = "PrivateKey", Value = encryptedKey});
            settings.Add(new SettingKeyValuePair() {Key = "Enabled", Value = "True"});
            settings.Add(new SettingKeyValuePair() {Key = "Method", Value = "DKIM"});
            settings.Add(new SettingKeyValuePair() {Key = "HeaderCanonicalization", Value = "Relaxed"});
            settings.Add(new SettingKeyValuePair() {Key = "BodyCanonicalization", Value = "Relaxed"});
            settings.Add(new SettingKeyValuePair() {Key = "SignatureExpirationDays", Value = "30"});
            settings.Add(new SettingKeyValuePair() {Key = "Notes", Value = "Added via API"});

            //Set/Add dkim setting and save.
            accountSettings.SetSettings(1000, ConfigFileType.AccountDomainKeys.ToString(),
                settingsKeyForDomain, settings.ToArray());

            
            //No read it back out and decrypt it.
            var backOut = accountSettings.GetSettings(1000, ConfigFileType.AccountDomainKeys.ToString(),
                settingsKeyForDomain);

            //Lets try to verify the key.
            foreach (var item in backOut)
            {
                Console.WriteLine("Key: {0}",item.Key);
                if (item.Key.Equals("PrivateKey"))
                {
                    var decryptedKey = encryptionClient.DecryptDomainKey(item.Value.ToString());
                    Console.WriteLine("Value: {0}", decryptedKey);
                }
                else
                    Console.WriteLine("Value: {0}", item.Value);
            }

            Console.ReadLine();

        }

        /* settings file format 
         * 
         * 
         *  Password = 
            PrivateKey = 
            SignatureExpirationDays = 30
            Notes = 
            Enabled = True
            Method = DKIM
            HeaderCanonicalization = Relaxed
            BodyCanonicalization = Relaxed
         * 
         * */

        public enum ConfigFileType
        {
            General,
            Accounts,
            AccountGeneral,
            AccountDeliveryRules,
            GlobalDeliveryRules,
            SmartDeliveryRules,
            AccountDomainKeys,
            Alerts,
            Plugins,
            Interfaces,
            OptimizedFailureStrings,
            FailureCodeList,
            BounceSignatures,
            SuppressionCodeList,
            ResponseTranslations,
            TextBodyTranslations,
            BillingData,
            CloudAccounts,
        }

        private const string TestPrivateKey = @"-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCwasP20qHGdwWziaacbfWxIVEJcIARVWTsIm7rCCxpClYbqEhz
WJwxEX91ZRJskrR4QW05yMJ7IKCQevOXjJCf2y/9B9Fla3tWGQoxL+vFHDp0++Ux
PpQDxzDL2b3tG+0aV7SKJBqHQ0hhUtFSAIShrFqmcugOnkstZE2tPL9EywIDAQAB
AoGATSCgRAyaRZZLm86WVNWOEL6sGyBgHTPkR4hWTdLo95NZSgYshqE6yAkKXFyv
zV/mHp0cD6NBw2rkR8Y5MQx3PXHEnc7nGY+N7b/W3ZZiJIYNDFN4+j8knSNgFq5k
LpGssoswx5dVApJwKK0hC5skfXcJRnAhay/i7MFyIlfc4oECQQDl7XQaiVRDPaKQ
2rtdkoK8dZzfTksdQHsGtob8erzUtRrmNecE0tE+uuxBYnLR2ZFI7U6I+yL5x9QF
1ZxaYACxAkEAxGv13UMhgIV9XwtHhzotCTrw6PhqeK7hkFyWSrTCXQ/cWTKzxpHs
odopXGYJo4jbLUsguEj0fooGzuD2YjfcOwJAMb69Bty9WUrleBeKwATpuiJsDTgg
MjT4KQymict4PUDtj+8Li1SdJshEQyUsmFBNCY0mF6bV+1qLebOsfzUUEQJBAIcL
/0AAftFBdoBZXfVwnzRAbRCQc4vEGVvK/J4ih5u6YvKE9Kuq+roRJ+zaTvg8CQ2s
ILPznP4/YgztCRlgdK8CQGeJKjAF9zmfM3EVLkFyCB2TZR18LLvl0Kcx5Iyt/k62
ndIC4tIFU8GBYU3lOxCrCC2f661i3dBiZoA3XNmpdjU=
-----END RSA PRIVATE KEY-----";
    }
}
