// Just a simple showcase. Explore more by yourself!

using PhiSaveManager;
using System.Xml.Linq;

if (args.Length == 0 || args[0] != "decrypt")
{
    Console.WriteLine("Tip: <Song name>.<Composer>.Record.<Difficulty>");
    Console.WriteLine("Tip: {\"s\":<7d>,\"a\":<.12f>,\"c\":<0/1 FC>}");
    
    while (true)
    {
        Console.Write("Action(e/d): ");
        var opt = Console.ReadLine();
        if (opt == "e")
        {
            Console.Write("> ");
            Console.WriteLine("Encrypted: " + SaveManagement.Encrypt(Console.ReadLine() ?? ""));
        }
        else if (opt == "d")
        {
            Console.Write("> ");
            Console.WriteLine("Decrypted: " + SaveManagement.Decrypt(Console.ReadLine() ?? ""));
        }
        else
        {
            Console.WriteLine("Invalid option. Enter 'e' for encrypt or 'd' for decrypt.");
        }
    }
}

var prefs = SaveManagement.LoadPrefs();
var elements = prefs.Select(kvp =>
    {
        string decryptedKey = kvp.Key, decryptedValue = kvp.Value;
        if (!decryptedKey.StartsWith("unity."))
        {
            try
            {
                decryptedKey = SaveManagement.Decrypt(decryptedKey);
                decryptedValue = SaveManagement.Decrypt(decryptedValue);
            }
            catch (Exception ex) {
                Console.WriteLine($"Decryption failed for {kvp.Key} -> {kvp.Value}, treating them as-they-are.");
                Console.WriteLine(ex);
            }
        }
        
        return new XElement("string", decryptedValue, new XAttribute("name", decryptedKey));
    }
);
var root = new XElement("map", elements);
var doc = new XDocument(new XDeclaration("1.0", "utf-8", "yes"), root);
doc.Save("decrypted_prefs.xml");
Console.WriteLine("Decrypted preferences saved to decrypted_prefs.xml");