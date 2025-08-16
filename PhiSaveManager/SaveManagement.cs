using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace PhiSaveManager;

public static class SaveManagement
{
    // Configuration constants
    private static readonly string PrefsFilePath = "com.PigeonGames.Phigros.v2.playerprefs.xml";

#error Keys are REMOVED to prevent abusement.
    private static readonly string DesEncryptKey = "<REMOVED>";
    private static readonly string AesKeyString = "<REMOVED>";
    private static readonly string AesIvString = "<REMOVED>";
    private static readonly string Aes2KeyBase64 = "<REMOVED>";
    private static readonly string Aes2IvBase64 = "<REMOVED>";

    // Crypto instances
    private static readonly Aes MainAes = Aes.Create();
    private static readonly Aes CloudSaveAes = Aes.Create();
    private static readonly DES LegacyDes = DES.Create();

    static SaveManagement()
    {
        MainAes.Key = LoopReverseXor(Encoding.ASCII.GetBytes(AesKeyString));
        MainAes.IV = LoopReverseXor(Encoding.ASCII.GetBytes(AesIvString));

        CloudSaveAes.Key = Convert.FromBase64String(Aes2KeyBase64);
        CloudSaveAes.IV = Convert.FromBase64String(Aes2IvBase64);

        byte[] desKeyBytes = Encoding.Unicode.GetBytes(DesEncryptKey);
        LegacyDes.Key = desKeyBytes;
        LegacyDes.IV = desKeyBytes;
    }

    #region XML File Operations
    /// <summary>
    /// Loads all preferences from XML file into a dictionary.
    /// </summary>
    public static Dictionary<string, string> LoadPrefs()
    {
        if (!File.Exists(PrefsFilePath))
        {
            return [];
        }

        XDocument doc = XDocument.Load(PrefsFilePath);
        return doc.Root?.Elements("string")
            .ToDictionary(
                e => e.Attribute("name")?.Value ?? "",
                e => e.Value
            ) ?? [];
    }

    /// <summary>
    /// Saves all preferences to XML file.
    /// </summary>
    private static void SavePrefs(Dictionary<string, string> prefs)
    {
        var elements = prefs.Select(kvp =>
            new XElement("string", kvp.Value, new XAttribute("name", kvp.Key))
        );
        var root = new XElement("map", elements);
        var doc = new XDocument(new XDeclaration("1.0", "utf-8", "yes"), root);
        doc.Save(PrefsFilePath);
    }

    /// <summary>
    /// Sets a value for the specified key in preferences.
    /// </summary>
    private static void SetString(string key, string value)
    {
        var prefs = LoadPrefs();
        prefs[key] = value;
        SavePrefs(prefs);
    }

    /// <summary>
    /// Gets the value associated with the specified key.
    /// </summary>
    private static string GetString(string key, string defaultValue = "")
    {
        var prefs = LoadPrefs();
        return prefs.TryGetValue(key, out var value) ? value : defaultValue;
    }

    /// <summary>
    /// Deletes the specified key from preferences.
    /// </summary>
    private static void DeleteKeyInternal(string key)
    {
        var prefs = LoadPrefs();
        if (prefs.Remove(key))
        {
            SavePrefs(prefs);
        }
    }

    /// <summary>
    /// Checks if the specified key exists in preferences.
    /// </summary>
    private static bool HasKeyInternal(string key)
    {
        return LoadPrefs().ContainsKey(key);
    }
    #endregion

    #region Public Save API
    public static bool HasKey(string keyName)
    {
        string aesKey = Encrypt(keyName);
        if (HasKeyInternal(aesKey))
        {
            return true;
        }

        string desKey = EncryptDES(keyName);
        return HasKeyInternal(desKey);
    }

    public static void DeleteKey(string keyName)
    {
        DeleteKeyInternal(Encrypt(keyName));
        DeleteKeyInternal(EncryptDES(keyName));
    }

    // Save methods for different data types
    public static void SaveBool(string keyName, bool value) => SaveString(keyName, value.ToString());
    public static void SaveInt(string keyName, int value) => SaveString(keyName, value.ToString());
    public static void SaveFloat(string keyName, float value) => SaveString(keyName, value.ToString("G9"));
    public static void SaveDate(string keyName, DateTime value) => SaveString(keyName, value.ToString("o"));
    public static void SaveString(string keyName, string value)
    {
        string encryptedKey = Encrypt(keyName);
        string encryptedValue = Encrypt(value);
        SetString(encryptedKey, encryptedValue);
    }

    // Load methods for different data types
    public static bool LoadBool(string keyName, bool defaultValue) =>
        bool.TryParse(LoadString(keyName), out bool result) ? result : defaultValue;

    public static int LoadInt(string keyName, int defaultValue) =>
        int.TryParse(LoadString(keyName), out int result) ? result : defaultValue;

    public static float LoadFloat(string keyName, float defaultValue) =>
        float.TryParse(LoadString(keyName), out float result) ? result : defaultValue;

    public static DateTime LoadDate(string keyName, DateTime defaultValue) =>
        DateTime.TryParse(LoadString(keyName), out DateTime result) ? result : defaultValue;

    public static string LoadString(string keyName, string defaultValue = "")
    {
        string aesKey = Encrypt(keyName);
        if (HasKeyInternal(aesKey))
        {
            string encryptedValue = GetString(aesKey);
            return Decrypt(encryptedValue);
        }

        string desKey = EncryptDES(keyName);
        if (HasKeyInternal(desKey))
        {
            string encryptedValue = GetString(desKey);
            string decryptedValue = DecryptDES(encryptedValue);

            // Migrate to new encryption format
            SaveString(keyName, decryptedValue);
            DeleteKeyInternal(desKey);

            return decryptedValue;
        }

        return defaultValue;
    }
    #endregion

    #region Encryption Core
    // Main AES encryption/decryption for local saves
    public static string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return plainText;

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] encryptedBytes = EncryptBytes(plainBytes);
        return WebUtility.UrlEncode(Convert.ToBase64String(encryptedBytes));
    }

    public static string Decrypt(string encryptedText)
    {
        if (string.IsNullOrEmpty(encryptedText))
            return encryptedText;

        string decodedText = WebUtility.UrlDecode(encryptedText);
        byte[] encryptedBytes = Convert.FromBase64String(decodedText);
        byte[] decryptedBytes = DecryptBytes(encryptedBytes);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    public static byte[] EncryptBytes(byte[] data)
    {
        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, MainAes.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(data, 0, data.Length);
        cryptoStream.FlushFinalBlock();
        return memoryStream.ToArray();
    }

    public static byte[] DecryptBytes(byte[] data)
    {
        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, MainAes.CreateDecryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(data, 0, data.Length);
        cryptoStream.FlushFinalBlock();
        return memoryStream.ToArray();
    }

    // Secondary AES for cloud saves
    // For old cloud saves(saveVersion < 2), use the main AES
    public static byte[] CloudSaveEncrypt(byte[] data)
    {
        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, CloudSaveAes.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(data, 0, data.Length);
        cryptoStream.FlushFinalBlock();
        return memoryStream.ToArray();
    }

    public static byte[] CloudSaveDecrypt(byte[] data)
    {
        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, CloudSaveAes.CreateDecryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(data, 0, data.Length);
        cryptoStream.FlushFinalBlock();
        return memoryStream.ToArray();
    }

    // DES encryption (legacy)
    public static string EncryptDES(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return plainText;

        byte[] inputBytes = Encoding.Unicode.GetBytes(plainText);

        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, LegacyDes.CreateEncryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(inputBytes, 0, inputBytes.Length);
        cryptoStream.FlushFinalBlock();
        return Convert.ToBase64String(memoryStream.ToArray());
    }

    public static string DecryptDES(string encryptedText)
    {
        if (string.IsNullOrEmpty(encryptedText))
            return encryptedText;

        byte[] inputBytes = Convert.FromBase64String(encryptedText);

        using var memoryStream = new MemoryStream();
        using var cryptoStream = new CryptoStream(memoryStream, LegacyDes.CreateDecryptor(), CryptoStreamMode.Write);
        cryptoStream.Write(inputBytes, 0, inputBytes.Length);
        cryptoStream.FlushFinalBlock();
        return Encoding.Unicode.GetString(memoryStream.ToArray());
    }

    private static byte[] LoopReverseXor(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return [];
        }

        int len = data.Length;
        byte[] result = new byte[len];

        static byte TransformByte(byte b)
        {
            // v7 = (2 * data->m_Items[v6]) & 0xFFAA | (data->m_Items[v6] >> 1) & 0x55;
            uint v7 = (uint)(((b << 1) & 0xAA) | ((b >> 1) & 0x55));
            // v8 = (4 * v7) & 0xFFFFFFCF | (v7 >> 2) & 0x33;
            uint v8 = (uint)(((v7 << 2) & 0xCF) | ((v7 >> 2) & 0x33));
            // result->m_Items[v6] = data->m_Items[v6 + 1] ^ (((unsigned __int8)v8 >> 4) | (16 * v8)); (Nibble Swap)
            return (byte)((v8 >> 4) | (v8 << 4));
        }

        for (int i = 0; i < len - 1; i++)
        {
            byte transformedByte = TransformByte(data[i]);
            result[i] = (byte)(transformedByte ^ data[i + 1]);
        }

        byte lastTransformedByte = TransformByte(data[len - 1]);
        result[len - 1] = (byte)(lastTransformedByte ^ data[0]);

        return result;
    }
    #endregion
}