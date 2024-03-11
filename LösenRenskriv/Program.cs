using System;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static System.Net.Mime.MediaTypeNames;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace LösenRenskriv
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //fixa client och server args, egen metod
            //samma, egen metod för felmeddeande

            Init();
            Create();

            if (args.Length != 0)
            {
                switch (args[0].ToLower())
                {
                    case "init":
                        if (args[1].ToLower() == "client.json" && args[2].ToLower() == "server.json")
                            Init();
                        else
                            Console.WriteLine("Wrong input, try again."); //Felmeddelande
                        break;


                    case "create":
                        if (args[1].ToLower() == "client.json" && args[2].ToLower() == "server.json")
                            Create();
                        else
                            Console.WriteLine("Wrong input, try again."); //Felmeddelande
                        break;


                    case "get":
                        if (args[1].ToLower() == "client.json" && args[2].ToLower() == "server.json")
                        {
                            if (args[3].Length != 0)
                            {
                                string prop = args[3];
                                Get(prop);
                            }
                            else if (args[3].Length == 0)
                            {
                                string noProp = "noProp";
                                Get(noProp);
                            }
                            else Console.WriteLine("Wrong input, try again.");
                        }
                        else
                            Console.WriteLine("Wrong input, try again."); //Felmeddelande
                        break;


                    case "set":
                        if (args[1].ToLower() == "client.json" && args[2].ToLower() == "server.json")
                        {
                            if (args[3].Length != 0)
                            {
                                string prop = args[3];

                                if (args[4].Length != 0)
                                {
                                    if (args[4].ToLower() == "--generate" || args[4].ToLower() == "--g")
                                    {
                                        bool generate = true;
                                        Set(prop, generate);
                                    }
                                    else
                                    {
                                        bool generate = false;
                                        Set(prop, generate);
                                    }
                                }
                            }
                        }
                        else
                            Console.WriteLine("Wrong input, try again."); //Felmeddelande
                        break;


                    case "delete":

                        if (args[1].ToLower() == "client.json" && args[2].ToLower() == "server.json" && args[3].Length != 0)
                        {
                            string prop = args[3];
                            Delete(prop);
                        }
                        else
                            Console.WriteLine("Wrong input, try again."); //Felmeddelande
                        break;


                    case "secret":
                        if (args[1].ToLower() == "client.json")
                            Secret();
                        else
                            Console.WriteLine("Wrong input, try again."); //Felmeddelande
                        break;


                    default:
                        Console.WriteLine("fel input");
                        break;
                }
            }

                

            static void Secret()
            {
                string readJsonClient = File.ReadAllText("client.json");
                Dictionary<string, string> clientJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonClient);

                string sameSecretKey = clientJsonText["SecretKey"];

                Console.WriteLine($"The secret key is: {sameSecretKey}");
            }

            static void Delete(string prop)
            {
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                string result = CheckMasterPassword(masterPassword);

                if (result != null)
                {
                    Dictionary<string, string> decryptedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(result);
                    
                    if (decryptedVault.ContainsKey(prop))
                    {
                        decryptedVault.Remove(prop);
                        Console.WriteLine($"You have now deleted the property {prop} from the vault.");
                    }
                    else Console.WriteLine("The propetry you entered does not exist.");

                }
                else Console.WriteLine("Your entered the wrong password, try again.");
                Environment.Exit(0);
            }

            static void Set(string prop, bool generate)
            {
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                string result = CheckMasterPassword(masterPassword);

                if (result != null)
                {
                    Dictionary<string, string> decryptedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(result);

                    if (generate == true)
                    {
                        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                        var stringChars = new char[20];
                        var random = new Random();

                        for (int i = 0; i < stringChars.Length; i++)
                        {
                            stringChars[i] = chars[random.Next(chars.Length)];
                        }
                        string generatedPassword = stringChars.ToString();

                        Console.WriteLine($"Your generated password for {prop} is: {generatedPassword}");
                        

                    }
                    else if (generate == false)
                    {
                        Console.WriteLine($"Enter your new password for {prop}:");
                        string newPassword = Console.ReadLine();

                        if (newPassword.Length != 0)
                        {
                            decryptedVault["prop"] = newPassword;
                            Console.WriteLine($"Your generated password for {prop} is: {newPassword}");
                        }
                        //else //felmeddelande
                    }

                }
                else Console.WriteLine("Your entered the wrong password, try again.");
                Environment.Exit(0);
            }

            static void Get(string prop)
            {
                //ta in lösen och secret key för att göra vault key för att försöka dekrypera aka kolla om rätt lösen
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                string result = CheckMasterPassword(masterPassword);

                if (result != null)
                {
                    //Console.WriteLine("Enter the property whose password you wish to get. Otherwise press enter to see all current properties.");
                    //string prop = Console.ReadLine();

                    Dictionary<string, string> decryptedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(result);

                    if (prop == "noProp")
                    {
                        Console.WriteLine($"These are all of the properties: ");
                        foreach (string key in decryptedVault.Keys)
                        {
                            Console.WriteLine(key);
                        }
                        //printa hela decrypted vault, alla props aka keys
                    }
                    else if (decryptedVault.ContainsKey(prop))
                    {
                        Console.WriteLine($"This is the password for {prop}:");
                        Console.WriteLine(decryptedVault[prop]);
                        //printa lösenordet till den tillhörande propen
                    }
                }
                else Console.WriteLine("Your entered the wrong password, try again.");
                Environment.Exit(0);
            }

            static void Create()
            {
                //användaren skriver in både masterpassword och secret key
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                Console.WriteLine("Enter your secret key:");
                string secretKey = Console.ReadLine();              //secret key massa siffror

                //konvertera secret key för att generera ny vault key - rätt metod

                byte[] byteSecretKey = Encoding.ASCII.GetBytes(secretKey);

                int iterera = 1000;
                Rfc2898DeriveBytes newVaultKey = new Rfc2898DeriveBytes(masterPassword, byteSecretKey, iterera);
                byte[] byteNewVaultKey = newVaultKey.GetBytes(16);



                //hämta krypterat valv och IV, deserialisera i en dictionary för att kunna hämta värdena
                string readJsonServer = File.ReadAllText("server.json");
                Dictionary<string, string> serverJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonServer);

                string encryptedVault = serverJsonText["EncryptedVault"];
                string IV = serverJsonText["IV"];


                byte[] encryptedVaultbyte = Encoding.ASCII.GetBytes(encryptedVault);
                byte[] IVbyte = Encoding.ASCII.GetBytes(IV);

                //Försöka dekryptera valvet
                string roundtrip = DecryptStringFromBytes_Aes(encryptedVaultbyte, byteNewVaultKey, IVbyte);

                if (roundtrip != null)
                {
                    string readJsonClient = File.ReadAllText("client.json");
                    Dictionary<string, string> clientJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonClient);

                    string sameSecretKey = clientJsonText["SecretKey"];
                    byte[] sameSecretKeyByte = Encoding.ASCII.GetBytes(sameSecretKey);


                    Client newClient = new Client()
                    {
                        SecretKey = sameSecretKeyByte
                    };

                    string secretKeyText = Convert.ToBase64String(newClient.SecretKey);

                    Dictionary<string, string> clientDictionary = new Dictionary<string, string>
                    {
                        { "SecretKey", secretKeyText }
                    };

                    //serialisera och spara dictionaryn som json-fil, sparar över gammal
                    string jsonClient = JsonSerializer.Serialize(clientDictionary);

                    File.WriteAllText("client.json", jsonClient);
                }

                else Console.WriteLine("Your entered the wrong password, try again.");                
            }

            static void Init()
            {
                //användaren skriver in lösenord
                Console.WriteLine("Enter your password:");
                string masterPassword = Console.ReadLine();

                //skapa random iv och secret key
                RandomNumberGenerator rng = RandomNumberGenerator.Create();

                byte[] IV = GenerateRandom(rng);
                byte[] secretKey = GenerateRandom(rng);

                //skapa CLient och set dess secret key, skriv ut så användaren kan spara ?
                Client client = new Client()
                {
                    SecretKey = secretKey
                };


                //gör om till string för att kunna lagra i en dictionary

                string secretKeyText = Convert.ToBase64String(client.SecretKey);


                //secret key printed in plain text - siffror???
                Console.WriteLine($"Remember your secret key, it is: {secretKeyText}");
                //foreach (var b in secretKey)
                //{
                //    Console.Write(b);
                //}

                Dictionary<string, string> clientDictionary = new Dictionary<string, string>
                {
                    { "SecretKey", secretKeyText }
                };


                //serialisera och spara dictionaryn som json-fil
                string jsonClient = JsonSerializer.Serialize(clientDictionary);

                File.WriteAllText("client.json", jsonClient);

                //skapa tomt lösenordsvalv och serialisera
                Dictionary<string, string> Vault = new Dictionary<string, string>();

                string jsonVault = JsonSerializer.Serialize(Vault);

                //generera vault key, gör om till byte[]
                int iterera = 1000;
                Rfc2898DeriveBytes vaultKey = new Rfc2898DeriveBytes(masterPassword, client.SecretKey, iterera);
                byte[] byteVaultKey = vaultKey.GetBytes(16);

                //kryptera valv med vault key och IV
                using (Aes AES = Aes.Create())
                {
                    byte[] encryptedVault = EncryptStringToBytes_Aes(jsonVault, byteVaultKey, IV);

                    //skapa server, tilldela krypterat valv och IV
                    Server server = new Server()
                    {
                        IV = IV,
                        EncryptedVault = encryptedVault
                    };

                    //gör om till string för att kunna lagra i en dictionary
                    string IVtext = Convert.ToBase64String(server.IV);
                    string encryptedVaultText = Convert.ToBase64String(server.EncryptedVault);

                    Dictionary<string, string> serverDictionary = new Dictionary<string, string>
                    {
                        { "IV", IVtext },
                        { "EncryptedVault", encryptedVaultText }
                    };

                    //serialisera och spara servern som json-fil
                    string jsonServer = JsonSerializer.Serialize(serverDictionary);

                    File.WriteAllText("server.json", jsonServer);
                }
            }

            static byte[] GenerateRandom(RandomNumberGenerator rng)
            {
                byte[] random = new byte[16];

                rng.GetBytes(random);

                return random;
            }

            static byte[] EncryptStringToBytes_Aes(string input, byte[] vaultkey, byte[] IV)
            {
                // Felhantera innan det här
                if (input == null || input.Length <= 0)
                    throw new ArgumentNullException("fel med plainText");
                if (vaultkey == null || vaultkey.Length <= 0)
                    throw new ArgumentNullException("fel med Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("fel med IV");
                

                byte[] encryptedVault;

                using (Aes aes = Aes.Create())
                {
                    ICryptoTransform encryptor = aes.CreateEncryptor(vaultkey, IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(input);
                            }
                            encryptedVault = msEncrypt.ToArray();
                        }
                    }
                }
                return encryptedVault;
            }

            static string DecryptStringFromBytes_Aes(byte[] input, byte[] newVaultKey, byte[] IV)
            {
                // Check arguments - gör innan
                if (input == null || input.Length <= 0)
                    throw new ArgumentNullException("cipherText");
                if (newVaultKey == null || newVaultKey.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");

                // Declare the string used to hold
                // the decrypted text.
                string plaintext = null;

                // Create an Aes object
                // with the specified key and IV.
                using (Aes aesAlg = Aes.Create())
                {

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(newVaultKey, IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(input))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                return plaintext;
            }

            static string CheckMasterPassword(string input)
            {
                string readJsonClient = File.ReadAllText("client.json");
                Dictionary<string, string> clientJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonClient);

                string sameSecretKey = clientJsonText["SecretKey"];
                byte[] sameSecretKeyByte = Encoding.ASCII.GetBytes(sameSecretKey);

                int iterera = 1000;
                Rfc2898DeriveBytes newVaultKey = new Rfc2898DeriveBytes(input, sameSecretKeyByte, iterera);
                byte[] byteNewVaultKey = newVaultKey.GetBytes(16);


                string readJsonServer = File.ReadAllText("server.json");
                Dictionary<string, string> serverJsonText = JsonSerializer.Deserialize<Dictionary<string, string>>(readJsonServer);

                string encryptedVault = serverJsonText["EncryptedVault"];
                string IV = serverJsonText["IV"];

                byte[] encryptedVaultbyte = Encoding.ASCII.GetBytes(encryptedVault);                //ändrad metod ascii
                byte[] IVbyte = Convert.FromBase64String(IV);


                string roundtrip = DecryptStringFromBytes_Aes(encryptedVaultbyte, byteNewVaultKey, IVbyte);

                return roundtrip;
            }


        }
    }
}
