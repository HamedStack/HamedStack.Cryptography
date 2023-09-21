// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
// ReSharper disable IdentifierTypo
// ReSharper disable MemberCanBePrivate.Global
// ReSharper disable CommentTypo
// ReSharper disable UnusedType.Global

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HamedStack.Cryptography;

/// <summary>
/// Provides a set of extension methods for AES encryption and decryption, and various hashing operations.
/// </summary>
public static class CryptoExtensions
{
    /// <summary>
    /// Generates a Time-based One-Time Password (TOTP) string based on the provided shared secret string.
    /// </summary>
    /// <param name="sharedSecret">The shared secret used for generating the TOTP.</param>
    /// <param name="timeStepSeconds">The time step in seconds.</param>
    /// <param name="codeLength">The length of the TOTP code.</param>
    /// <exception cref="ArgumentNullException">Thrown when the sharedSecret is null or empty.</exception>
    /// <returns>A string representing the TOTP.</returns>
    public static string GenerateTOTP(this string sharedSecret, int timeStepSeconds = 30, int codeLength = 6)
    {
        if (string.IsNullOrEmpty(sharedSecret))
            throw new ArgumentNullException(nameof(sharedSecret));
        var key = Encoding.Unicode.GetBytes(sharedSecret);
        return GenerateTOTP(key, timeStepSeconds, codeLength);
    }

    /// <summary>
    /// Generates a Time-based One-Time Password (TOTP) string based on the provided shared secret byte array.
    /// </summary>
    /// <param name="sharedSecret">The shared secret used for generating the TOTP.</param>
    /// <param name="timeStepSeconds">The time step in seconds.</param>
    /// <param name="codeLength">The length of the TOTP code.</param>
    /// <exception cref="ArgumentNullException">Thrown when the sharedSecret is null or empty.</exception>
    /// <returns>A string representing the TOTP.</returns>
    public static string GenerateTOTP(this byte[] sharedSecret, int timeStepSeconds = 30, int codeLength = 6)
    {
        if (sharedSecret == null || sharedSecret.Length == 0)
            throw new ArgumentNullException(nameof(sharedSecret));
        var unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var counter = unixTimestamp / timeStepSeconds;
        return GenerateTOTP(sharedSecret, counter, codeLength);
    }

    /// <summary>
    /// Generates a Time-based One-Time Password (TOTP) string using the internal TOTP generation algorithm.
    /// </summary>
    /// <param name="key">The shared secret key.</param>
    /// <param name="counter">The counter value representing the current time step.</param>
    /// <param name="codeLength">The length of the TOTP code.</param>
    /// <returns>A string representing the TOTP.</returns>
    private static string GenerateTOTP(byte[] key, long counter, int codeLength)
    {
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(counterBytes);
        var offset = hash[^1] & 0xf;
        var binaryCode = (hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 |
                         (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff);
        var otp = binaryCode % (int)Math.Pow(10, codeLength);
        return otp.ToString().PadLeft(codeLength, '0');
    }

    /// <summary>
    /// Verifies a Time-based One-Time Password (TOTP) code against the shared secret string.
    /// </summary>
    /// <param name="sharedSecret">The shared secret used for generating the TOTP.</param>
    /// <param name="code">The TOTP code to verify.</param>
    /// <param name="timeStepSeconds">The time step in seconds.</param>
    /// <param name="codeLength">The length of the TOTP code.</param>
    /// <param name="timeTolerance">The number of time steps allowed for variance in token validation.</param>
    /// <returns>A boolean indicating if the TOTP code is valid or not.</returns>
    public static bool VerifyTOTP(this string sharedSecret, string code, int timeStepSeconds = 30, int codeLength = 6, int timeTolerance = 1)
    {
        var key = Encoding.Unicode.GetBytes(sharedSecret);
        return VerifyTOTP(key, code, timeStepSeconds, codeLength, timeTolerance);
    }

    /// <summary>
    /// Verifies a Time-based One-Time Password (TOTP) code against the shared secret byte array.
    /// </summary>
    /// <param name="sharedSecret">The shared secret used for generating the TOTP.</param>
    /// <param name="code">The TOTP code to verify.</param>
    /// <param name="timeStepSeconds">The time step in seconds.</param>
    /// <param name="codeLength">The length of the TOTP code.</param>
    /// <param name="timeTolerance">The number of time steps allowed for variance in token validation.</param>
    /// <returns>A boolean indicating if the TOTP code is valid or not.</returns>
    public static bool VerifyTOTP(this byte[] sharedSecret, string code, int timeStepSeconds = 30, int codeLength = 6, int timeTolerance = 1)
    {
        var unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var counter = unixTimestamp / timeStepSeconds;
        for (var i = counter - timeTolerance; i <= counter + timeTolerance; i++)
        {
            var expectedCode = GenerateTOTP(sharedSecret, i, codeLength);
            if (expectedCode == code)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Generates an HMAC-based One-Time Password (HOTP) based on the provided shared secret string.
    /// </summary>
    /// <param name="sharedSecret">The shared secret used for generating the HOTP.</param>
    /// <param name="counter">The counter value.</param>
    /// <param name="codeLength">The length of the HOTP code.</param>
    /// <exception cref="ArgumentNullException">Thrown when the sharedSecret is null or empty.</exception>
    /// <returns>A string representing the HOTP.</returns>
    public static string GenerateHOTP(this string sharedSecret, long counter, int codeLength = 6)
    {
        if (string.IsNullOrEmpty(sharedSecret))
            throw new ArgumentNullException(nameof(sharedSecret));
        var key = Encoding.Unicode.GetBytes(sharedSecret);
        return GenerateHOTP(key, counter, codeLength);
    }

    /// <summary>
    /// Generates an HMAC-based One-Time Password (HOTP) based on the provided shared secret byte array.
    /// </summary>
    /// <param name="sharedSecret">The shared secret used for generating the HOTP.</param>
    /// <param name="counter">The counter value.</param>
    /// <param name="codeLength">The length of the HOTP code.</param>
    /// <exception cref="ArgumentNullException">Thrown when the sharedSecret is null or empty.</exception>
    /// <returns>A string representing the HOTP.</returns>
    public static string GenerateHOTP(this byte[] sharedSecret, long counter, int codeLength = 6)
    {
        if (sharedSecret == null || sharedSecret.Length == 0)
            throw new ArgumentNullException(nameof(sharedSecret));

        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);
        using var hmac = new HMACSHA256(sharedSecret);
        var hash = hmac.ComputeHash(counterBytes);
        var offset = hash[^1] & 0xf;
        var binaryCode = (hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 |
                         (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff);
        var otp = binaryCode % (int)Math.Pow(10, codeLength);
        return otp.ToString().PadLeft(codeLength, '0');
    }

    /// <summary>
    /// Verifies an HMAC-based One-Time Password (HOTP) code against the shared secret string.
    /// </summary>
    /// <param name="sharedSecret">The shared secret used for generating the HOTP.</param>
    /// <param name="code">The HOTP code to verify.</param>
    /// <param name="counter">The counter value.</param>
    /// <param name="codeLength">The length of the HOTP code.</param>
    /// <returns>A boolean indicating if the HOTP code is valid or not.</returns>
    public static bool VerifyHOTP(this string sharedSecret, string code, long counter, int codeLength = 6)
    {
        var key = Encoding.Unicode.GetBytes(sharedSecret);
        return VerifyHOTP(key, code, counter, codeLength);
    }

    /// <summary>
    /// Verifies an HMAC-based One-Time Password (HOTP) code against the shared secret byte array.
    /// </summary>
    /// <param name="sharedSecret">The shared secret used for generating the HOTP.</param>
    /// <param name="code">The HOTP code to verify.</param>
    /// <param name="counter">The counter value.</param>
    /// <param name="codeLength">The length of the HOTP code.</param>
    /// <returns>A boolean indicating if the HOTP code is valid or not.</returns>
    public static bool VerifyHOTP(this byte[] sharedSecret, string code, long counter, int codeLength = 6)
    {
        var expectedCode = GenerateHOTP(sharedSecret, counter, codeLength);
        return expectedCode == code;
    }

    /// <summary>
    /// Converts a byte array to its Base32 string representation.
    /// </summary>
    /// <param name="data">The byte array to convert.</param>
    /// <returns>A Base32 string representation of the byte array.</returns>
    public static string? ToBase32String(this byte[] data)
    {
        return Base32.ToBase32String(data);
    }

    /// <summary>
    /// Converts a Base32 string to its byte array representation.
    /// </summary>
    /// <param name="base32String">The Base32 string to convert.</param>
    /// <returns>A byte array representation of the Base32 string.</returns>
    public static byte[]? FromBase32String(this string base32String)
    {
        return Base32.FromBase32String(base32String);
    }
    /// <summary>
    /// Converts a string to its Base32 string representation using UTF-8 encoding.
    /// </summary>
    /// <param name="str">The string to convert.</param>
    /// <returns>A Base32 string representation of the input string.</returns>
    public static string? ToBase32String(this string str)
    {
        var data = Encoding.UTF8.GetBytes(str);
        return Base32.ToBase32String(data);
    }

    /// <summary>
    /// Decrypts the specified cipher text using AES algorithm.
    /// </summary>
    /// <param name="cipherText">The cipher text to decrypt.</param>
    /// <param name="key">The secret key used for decryption.</param>
    /// <param name="iv">The initialization vector used for decryption.</param>
    /// <returns>The decrypted text.</returns>
    public static string AesDecrypt(this byte[] cipherText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(cipherText);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs);

        return sr.ReadToEnd();
    }

    /// <summary>
    /// Decrypts the specified cipher text using AES algorithm and provided key and IV strings.
    /// </summary>
    /// <param name="cipherText">The cipher text to decrypt.</param>
    /// <param name="keyText">The secret key as a string used for decryption.</param>
    /// <param name="ivText">The initialization vector as a string used for decryption.</param>
    /// <returns>The decrypted text.</returns>
    public static string AesDecrypt(this string cipherText, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return AesDecryptWithBase64Key(cipherText, key, iv);
    }

    /// <summary>
    /// Decrypts the specified cipher text to a byte array using AES algorithm.
    /// </summary>
    /// <param name="cipherText">The cipher text to decrypt.</param>
    /// <param name="key">The secret key used for decryption.</param>
    /// <param name="iv">The initialization vector used for decryption.</param>
    /// <returns>The decrypted byte array.</returns>
    public static byte[] AesDecryptAsBytes(this byte[] cipherText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(cipherText);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

        var decryptedBytes = new byte[cipherText.Length];
        var bytesRead = cs.Read(decryptedBytes, 0, decryptedBytes.Length);

        return decryptedBytes.Take(bytesRead).ToArray();
    }

    /// <summary>
    /// Decrypts the specified cipher text bytes using the AES algorithm and returns the decrypted content as a byte array.
    /// </summary>
    /// <param name="cipherText">The byte array containing the encrypted content.</param>
    /// <param name="keyText">The encryption key as a string.</param>
    /// <param name="ivText">The initialization vector (IV) as a string.</param>
    /// <returns>The decrypted content as a byte array.</returns>
    public static byte[] AesDecryptAsBytes(this byte[] cipherText, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return AesDecryptAsBytesWithBase64Key(cipherText, key, iv);
    }

    /// <summary>
    /// Decrypts the given cipher text using AES algorithm with a base64-encoded key and IV,
    /// and returns the result as a byte array.
    /// </summary>
    /// <param name="cipherText">The cipher text to decrypt.</param>
    /// <param name="base64Key">The base64-encoded AES encryption key.</param>
    /// <param name="base64Iv">The base64-encoded AES initialization vector.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static byte[] AesDecryptAsBytesWithBase64Key(this byte[] cipherText, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        return AesDecryptAsBytes(cipherText, key, iv);
    }

    /// <summary>
    /// Decrypts the given cipher text using AES algorithm and returns the result as a Stream.
    /// </summary>
    /// <param name="cipherText">The cipher text to decrypt.</param>
    /// <param name="key">The AES encryption key.</param>
    /// <param name="iv">The AES initialization vector.</param>
    /// <returns>The decrypted data as a Stream.</returns>
    public static Stream AesDecryptAsStream(this byte[] cipherText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        var ms = new MemoryStream(cipherText);
        var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

        var resultStream = new MemoryStream();
        cs.CopyTo(resultStream);
        resultStream.Position = 0;

        return resultStream;
    }

    /// <summary>
    /// Decrypts the given cipher text stream using AES algorithm and returns the result as a Stream.
    /// </summary>
    /// <param name="cipherTextStream">The cipher text stream to decrypt.</param>
    /// <param name="keyText">The AES encryption key as a string.</param>
    /// <param name="ivText">The AES initialization vector as a string.</param>
    /// <returns>The decrypted data as a Stream.</returns>
    public static Stream AesDecryptAsStream(this Stream cipherTextStream, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return AesDecryptAsStreamWithBase64Key(cipherTextStream, key, iv);
    }

    /// <summary>
    /// Decrypts the given cipher text stream using AES algorithm and returns the result as a Stream.
    /// </summary>
    /// <param name="cipherTextStream">The cipher text stream to decrypt.</param>
    /// <param name="base64Key">The AES encryption key as a base64-encoded string.</param>
    /// <param name="base64Iv">The AES initialization vector as a base64-encoded string.</param>
    /// <returns>The decrypted data as a Stream.</returns>
    public static Stream AesDecryptAsStreamWithBase64Key(this Stream cipherTextStream, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        var cipherText = new byte[cipherTextStream.Length];
        _ = cipherTextStream.Read(cipherText, 0, cipherText.Length);
        return AesDecryptAsStream(cipherText, key, iv);
    }

    /// <summary>
    /// Decrypts the given base64-encoded cipher text using AES algorithm and returns the result as a string.
    /// </summary>
    /// <param name="cipherText">The base64-encoded cipher text to decrypt.</param>
    /// <param name="base64Key">The AES encryption key as a base64-encoded string.</param>
    /// <param name="base64Iv">The AES initialization vector as a base64-encoded string.</param>
    /// <returns>The decrypted data as a string.</returns>
    public static string AesDecryptWithBase64Key(this string cipherText, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        var cipherBytes = Convert.FromBase64String(cipherText);
        return AesDecrypt(cipherBytes, key, iv);
    }

    /// <summary>
    /// Encrypts the given plaintext using AES algorithm and returns the result as a byte array.
    /// </summary>
    /// <param name="plaintext">The plaintext to encrypt.</param>
    /// <param name="key">The AES encryption key.</param>
    /// <param name="iv">The AES initialization vector.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static byte[] AesEncrypt(this string plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cs))
        {
            sw.Write(plaintext);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Encrypts the given byte array using AES algorithm and returns the result as a byte array.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="key">The AES encryption key.</param>
    /// <param name="iv">The AES initialization vector.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    public static byte[] AesEncrypt(this byte[] data, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Encrypts the data from the given stream using AES algorithm and returns the result as a Stream.
    /// </summary>
    /// <param name="stream">The data stream to encrypt.</param>
    /// <param name="key">The AES encryption key.</param>
    /// <param name="iv">The AES initialization vector.</param>
    /// <returns>The encrypted data as a Stream.</returns>
    public static Stream AesEncrypt(this Stream stream, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            stream.CopyTo(cs);
        }

        ms.Position = 0;
        return ms;
    }

    /// <summary>
    /// Encrypts the specified plain text using AES algorithm.
    /// </summary>
    /// <param name="plaintext">The plain text to encrypt.</param>
    /// <param name="keyText">The secret key used for encryption.</param>
    /// <param name="ivText">The initialization vector used for encryption.</param>
    /// <returns>The encrypted data as byte array.</returns>
    public static byte[] AesEncrypt(this string plaintext, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return AesEncryptWithBase64Key(plaintext, key, iv);
    }

    /// <summary>
    /// Encrypts the specified data using AES algorithm.
    /// </summary>
    /// <param name="data">The data to encrypt.</param>
    /// <param name="keyText">The secret key used for encryption.</param>
    /// <param name="ivText">The initialization vector used for encryption.</param>
    /// <returns>The encrypted data as byte array.</returns>
    public static byte[] AesEncrypt(this byte[] data, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return AesEncryptWithBase64Key(data, key, iv);
    }

    /// <summary>
    /// Encrypts the content of the provided stream using the AES algorithm with the given key and initialization vector (IV) text.
    /// </summary>
    /// <param name="stream">The stream containing the data to encrypt.</param>
    /// <param name="keyText">The encryption key as a string.</param>
    /// <param name="ivText">The initialization vector (IV) as a string.</param>
    /// <returns>An encrypted stream.</returns>
    public static Stream AesEncrypt(this Stream stream, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return AesEncryptWithBase64Key(stream, key, iv);
    }

    /// <summary>
    /// Encrypts the provided plaintext string using the AES algorithm with the given base64 encoded key and initialization vector (IV).
    /// </summary>
    /// <param name="plaintext">The plaintext string to encrypt.</param>
    /// <param name="base64Key">The encryption key as a base64 encoded string.</param>
    /// <param name="base64Iv">The initialization vector (IV) as a base64 encoded string.</param>
    /// <returns>An encrypted byte array.</returns>
    public static byte[] AesEncryptWithBase64Key(this string plaintext, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        return AesEncrypt(plaintext, key, iv);
    }

    /// <summary>
    /// Encrypts the provided byte array data using the AES algorithm with the given base64 encoded key and initialization vector (IV).
    /// </summary>
    /// <param name="data">The byte array to encrypt.</param>
    /// <param name="base64Key">The encryption key as a base64 encoded string.</param>
    /// <param name="base64Iv">The initialization vector (IV) as a base64 encoded string.</param>
    /// <returns>An encrypted byte array.</returns>
    public static byte[] AesEncryptWithBase64Key(this byte[] data, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        return AesEncrypt(data, key, iv);
    }

    /// <summary>
    /// Encrypts the content of the provided stream using the AES algorithm with the given base64 encoded key and initialization vector (IV).
    /// </summary>
    /// <param name="stream">The stream containing the data to encrypt.</param>
    /// <param name="base64Key">The encryption key as a base64 encoded string.</param>
    /// <param name="base64Iv">The initialization vector (IV) as a base64 encoded string.</param>
    /// <returns>An encrypted stream.</returns>
    public static Stream AesEncryptWithBase64Key(this Stream stream, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        return AesEncrypt(stream, key, iv);
    }

    /// <summary>
    /// Calculates the CRC32 hash of the specified input string.
    /// </summary>
    /// <param name="input">The input string to compute the hash for.</param>
    /// <returns>The computed CRC32 hash.</returns>
    public static uint CalculateCRC32Hash(this string input)
    {
        return Crc32.Compute(Encoding.UTF8.GetBytes(input));
    }

    /// <summary>
    /// Calculates the CRC32 hash of the specified input byte array.
    /// </summary>
    /// <param name="input">The input byte array to compute the hash for.</param>
    /// <returns>The computed CRC32 hash.</returns>
    public static uint CalculateCRC32Hash(this byte[] input)
    {
        return Crc32.Compute(input);
    }

    /// <summary>
    /// Calculates the CRC32 hash of the specified input stream.
    /// </summary>
    /// <param name="stream">The input stream to compute the hash for.</param>
    /// <returns>The computed CRC32 hash.</returns>
    public static uint CalculateCRC32Hash(this Stream stream)
    {
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return Crc32.Compute(ms.ToArray());
    }

    /// <summary>
    /// Calculates the CRC64 hash of the provided string input.
    /// </summary>
    /// <param name="input">The string input to compute the hash for.</param>
    /// <returns>The computed CRC64 hash as an unsigned 64-bit integer.</returns>
    public static ulong CalculateCRC64Hash(this string input)
    {
        return Crc64.Compute(Encoding.UTF8.GetBytes(input));
    }

    /// <summary>
    /// Calculates the CRC64 hash of the provided byte array.
    /// </summary>
    /// <param name="input">The byte array to compute the hash for.</param>
    /// <returns>The computed CRC64 hash as an unsigned 64-bit integer.</returns>
    public static ulong CalculateCRC64Hash(this byte[] input)
    {
        return Crc64.Compute(input);
    }

    /// <summary>
    /// Calculates the CRC64 hash of the data in the provided stream.
    /// </summary>
    /// <param name="stream">The stream containing the data to compute the hash for.</param>
    /// <returns>The computed CRC64 hash as an unsigned 64-bit integer.</returns>
    public static ulong CalculateCRC64Hash(this Stream stream)
    {
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return Crc64.Compute(ms.ToArray());
    }

    /// <summary>
    /// Calculates the MD5 hash of the specified input string.
    /// </summary>
    /// <param name="input">The input string to compute the hash for.</param>
    /// <returns>The computed MD5 hash as a string.</returns>
    public static string CalculateMD5Hash(this string input)
    {
        using var md5 = MD5.Create();
        return GetHash(md5, input);
    }

    /// <summary>
    /// Calculates the MD5 hash of the specified input byte array.
    /// </summary>
    /// <param name="input">The input byte array to compute the hash for.</param>
    /// <returns>The computed MD5 hash as a string.</returns>
    public static string CalculateMD5Hash(this byte[] input)
    {
        using var md5 = MD5.Create();
        return GetHash(md5, input);
    }

    /// <summary>
    /// Calculates the MD5 hash of the provided stream.
    /// </summary>
    /// <param name="stream">The stream containing data to hash.</param>
    /// <returns>The calculated MD5 hash in string format.</returns>
    public static string CalculateMD5Hash(this Stream stream)
    {
        using var md5 = MD5.Create();
        return GetHash(md5, stream);
    }

    /// <summary>
    /// Calculates the PBKDF2 (Password-Based Key Derivation Function 2) hash of the provided stream using the specified parameters.
    /// </summary>
    /// <param name="stream">The stream containing data to hash.</param>
    /// <param name="salt">Optional salt for the hash. If not provided, a random salt will be generated.</param>
    /// <param name="iterations">The number of iterations for the PBKDF2 function.</param>
    /// <param name="hashByteSize">The size of the hash to generate.</param>
    /// <returns>An array of bytes representing the PBKDF2 hash.</returns>
    public static byte[] CalculatePBKDF2Hash(this Stream stream, byte[]? salt = null, int iterations = 1000, int hashByteSize = 20)
    {
        salt ??= GenerateRandomSalt();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        var data = ms.ToArray();
        var dataAsString = Convert.ToBase64String(data);
        using var pbkdf2 = new Rfc2898DeriveBytes(dataAsString, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(hashByteSize);
    }

    /// <summary>
    /// Calculates the PBKDF2 (Password-Based Key Derivation Function 2) hash of the provided byte array using the specified parameters.
    /// </summary>
    /// <param name="data">The byte array containing data to hash.</param>
    /// <param name="salt">Optional salt for the hash. If not provided, a random salt will be generated.</param>
    /// <param name="iterations">The number of iterations for the PBKDF2 function.</param>
    /// <param name="hashByteSize">The size of the hash to generate.</param>
    /// <returns>An array of bytes representing the PBKDF2 hash.</returns>
    public static byte[] CalculatePBKDF2Hash(this byte[] data, byte[]? salt = null, int iterations = 1000, int hashByteSize = 20)
    {
        salt ??= GenerateRandomSalt();
        var dataAsString = Convert.ToBase64String(data);
        using var pbkdf2 = new Rfc2898DeriveBytes(dataAsString, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(hashByteSize);
    }

    /// <summary>
    /// Calculates the PBKDF2 (Password-Based Key Derivation Function 2) hash of the provided password string using the specified parameters.
    /// </summary>
    /// <param name="password">The password string to hash.</param>
    /// <param name="salt">Optional salt for the hash. If not provided, a random salt will be generated.</param>
    /// <param name="iterations">The number of iterations for the PBKDF2 function.</param>
    /// <param name="hashByteSize">The size of the hash to generate.</param>
    /// <returns>An array of bytes representing the PBKDF2 hash.</returns>
    public static byte[] CalculatePBKDF2Hash(this string password, byte[]? salt = null, int iterations = 1000, int hashByteSize = 20)
    {
        salt ??= GenerateRandomSalt();
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(hashByteSize);
    }

    /// <summary>
    /// Calculates the SHA1 hash of the specified input string.
    /// </summary>
    /// <param name="input">The input string to compute the hash for.</param>
    /// <returns>The computed SHA1 hash as a string.</returns>
    public static string CalculateSHA1Hash(this string input)
    {
        using var sha1 = SHA1.Create();
        return GetHash(sha1, Encoding.UTF8.GetBytes(input));
    }

    /// <summary>
    /// Calculates the SHA1 hash of the specified input byte array.
    /// </summary>
    /// <param name="input">The input byte array to compute the hash for.</param>
    /// <returns>The computed SHA1 hash as a string.</returns>
    public static string CalculateSHA1Hash(this byte[] input)
    {
        using var sha1 = SHA1.Create();
        return GetHash(sha1, input);
    }

    /// <summary>
    /// Calculates the SHA1 hash of the given stream.
    /// </summary>
    /// <param name="stream">The stream containing data to hash.</param>
    /// <returns>The calculated SHA1 hash in string format.</returns>
    public static string CalculateSHA1Hash(this Stream stream)
    {
        using var sha1 = SHA1.Create();
        return GetHash(sha1, stream);
    }

    /// <summary>
    /// Calculates the SHA256 hash of the given string input.
    /// </summary>
    /// <param name="input">The string to hash.</param>
    /// <returns>The calculated SHA256 hash in string format.</returns>
    public static string CalculateSHA256Hash(this string input)
    {
        using var sha256 = SHA256.Create();
        return GetHash(sha256, Encoding.UTF8.GetBytes(input));
    }

    /// <summary>
    /// Calculates the SHA256 hash of the given byte array.
    /// </summary>
    /// <param name="input">The byte array to hash.</param>
    /// <returns>The calculated SHA256 hash in string format.</returns>
    public static string CalculateSHA256Hash(this byte[] input)
    {
        using var sha256 = SHA256.Create();
        return GetHash(sha256, input);
    }

    /// <summary>
    /// Calculates the SHA256 hash of the given stream.
    /// </summary>
    /// <param name="stream">The stream containing data to hash.</param>
    /// <returns>The calculated SHA256 hash in string format.</returns>
    public static string CalculateSHA256Hash(this Stream stream)
    {
        using var sha256 = SHA256.Create();
        return GetHash(sha256, stream);
    }

    /// <summary>
    /// Calculates the SHA384 hash of the given string input.
    /// </summary>
    /// <param name="input">The string to hash.</param>
    /// <returns>The calculated SHA384 hash in string format.</returns>
    public static string CalculateSHA384Hash(this string input)
    {
        using var sha384 = SHA384.Create();
        return GetHash(sha384, Encoding.UTF8.GetBytes(input));
    }

    /// <summary>
    /// Calculates the SHA384 hash of the given byte array.
    /// </summary>
    /// <param name="input">The byte array to hash.</param>
    /// <returns>The calculated SHA384 hash in string format.</returns>
    public static string CalculateSHA384Hash(this byte[] input)
    {
        using var sha384 = SHA384.Create();
        return GetHash(sha384, input);
    }

    /// <summary>
    /// Calculates the SHA384 hash of the given stream.
    /// </summary>
    /// <param name="stream">The stream containing data to hash.</param>
    /// <returns>The calculated SHA384 hash in string format.</returns>
    public static string CalculateSHA384Hash(this Stream stream)
    {
        using var sha384 = SHA384.Create();
        return GetHash(sha384, stream);
    }

    /// <summary>
    /// Calculates the SHA512 hash of the given string input.
    /// </summary>
    /// <param name="input">The string to hash.</param>
    /// <returns>The calculated SHA512 hash in string format.</returns>
    public static string CalculateSHA512Hash(this string input)
    {
        using var sha512 = SHA512.Create();
        return GetHash(sha512, Encoding.UTF8.GetBytes(input));
    }

    /// <summary>
    /// Calculates the SHA512 hash of the given byte array.
    /// </summary>
    /// <param name="input">The byte array to hash.</param>
    /// <returns>The calculated SHA512 hash in string format.</returns>
    public static string CalculateSHA512Hash(this byte[] input)
    {
        using var sha512 = SHA512.Create();
        return GetHash(sha512, input);
    }

    /// <summary>
    /// Calculates the SHA512 hash of the given stream.
    /// </summary>
    /// <param name="stream">The stream containing data to hash.</param>
    /// <returns>The calculated SHA512 hash in string format.</returns>
    public static string CalculateSHA512Hash(this Stream stream)
    {
        using var sha512 = SHA512.Create();
        return GetHash(sha512, stream);
    }

    /// <summary>
    /// Creates a self-signed X509 certificate with the specified subject name.
    /// </summary>
    /// <param name="subjectName">The subject name for the certificate.</param>
    /// <returns>An instance of the X509Certificate2 class representing the self-signed certificate.</returns>
    public static X509Certificate2 CreateSelfSignedX509Certificate(this string subjectName)
    {
        var distinguishedName = new X500DistinguishedName($"CN={subjectName}");

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));
    }

    /// <summary>
    /// Generates a digital signature for the given byte data using the provided RSA private key.
    /// </summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="privateKey">The RSA private key to use for signing.</param>
    /// <returns>An array of bytes representing the digital signature.</returns>
    public static byte[] GenerateDigitalSignature(this byte[] data, RSAParameters privateKey)
    {
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(privateKey);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Decrypts the Base64 encoded cipher text using RSA with the specified RSA parameters or generated ones if not provided.
    /// </summary>
    /// <param name="cipherText">The Base64 encoded cipher text.</param>
    /// <param name="rsaParams">The optional RSA parameters for decryption. If not provided, new ones will be generated.</param>
    /// <returns>The decrypted string.</returns>
    public static string RSADecrypt(this string cipherText, RSAParameters? rsaParams = null)
    {
        var bytesToDecrypt = Convert.FromBase64String(cipherText);

        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(rsaParams ?? GenerateRSAKeyPair());

        var decryptedBytes = rsa.Decrypt(bytesToDecrypt, false);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    /// <summary>
    /// Decrypts the given byte array using RSA with the specified RSA parameters or generated ones if not provided.
    /// </summary>
    /// <param name="bytesToDecrypt">The bytes to decrypt.</param>
    /// <param name="rsaParams">The optional RSA parameters for decryption. If not provided, new ones will be generated.</param>
    /// <returns>An array of bytes representing the decrypted data.</returns>
    public static byte[] RSADecrypt(this byte[] bytesToDecrypt, RSAParameters? rsaParams = null)
    {
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(rsaParams ?? GenerateRSAKeyPair());

        return rsa.Decrypt(bytesToDecrypt, false);
    }

    /// <summary>
    /// Encrypts the provided plaintext string using RSA with the specified RSA parameters or generated ones if not provided.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="rsaParams">The optional RSA parameters for encryption. If not provided, new ones will be generated.</param>
    /// <returns>The Base64 encoded encrypted string.</returns>
    public static string RSAEncrypt(this string plainText, RSAParameters? rsaParams = null)
    {
        var bytesToEncrypt = Encoding.UTF8.GetBytes(plainText);

        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(rsaParams ?? GenerateRSAKeyPair());

        var encryptedBytes = rsa.Encrypt(bytesToEncrypt, false);
        return Convert.ToBase64String(encryptedBytes);
    }

    /// <summary>
    /// Encrypts the provided byte data using RSA with the specified RSA parameters or generated ones if not provided.
    /// </summary>
    /// <param name="bytesToEncrypt">The byte data to encrypt.</param>
    /// <param name="rsaParams">The optional RSA parameters for encryption. If not provided, new ones will be generated.</param>
    /// <returns>An array of bytes representing the encrypted data.</returns>
    public static byte[] RSAEncrypt(this byte[] bytesToEncrypt, RSAParameters? rsaParams = null)
    {
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(rsaParams ?? GenerateRSAKeyPair());

        return rsa.Encrypt(bytesToEncrypt, false);
    }

    /// <summary>
    /// Exports the given X509Certificate2 to bytes with the specified password and content type.
    /// </summary>
    /// <param name="certificate">The X509 certificate to export.</param>
    /// <param name="password">The password for the exported certificate.</param>
    /// <param name="contentType">The content type of the exported certificate. Default is Pfx.</param>
    /// <returns>The exported certificate as a byte array.</returns>
    public static byte[] SaveX509CertificateToBytes(this X509Certificate2 certificate, string password, X509ContentType contentType = X509ContentType.Pfx)
    {
        return certificate.Export(contentType, password);
    }

    /// <summary>
    /// Exports the given X509Certificate2 to a stream with the specified password and content type.
    /// </summary>
    /// <param name="certificate">The X509 certificate to export.</param>
    /// <param name="password">The password for the exported certificate.</param>
    /// <param name="contentType">The content type of the exported certificate. Default is Pfx.</param>
    /// <returns>The exported certificate as a stream.</returns>
    public static Stream SaveX509CertificateToStream(this X509Certificate2 certificate, string password, X509ContentType contentType = X509ContentType.Pfx)
    {
        var bytes = certificate.Export(contentType, password);
        return new MemoryStream(bytes);
    }

    /// <summary>
    /// Decrypts the given byte array using TripleDES encryption with the provided key and IV and returns it as a string.
    /// </summary>
    /// <param name="cipherText">The encrypted data to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>The decrypted string.</returns>
    public static string TripleDesDecrypt(this byte[] cipherText, byte[] key, byte[] iv)
    {
        using var tripleDES = TripleDES.Create();
        tripleDES.Key = key;
        tripleDES.IV = iv;

        using var decryptor = tripleDES.CreateDecryptor(tripleDES.Key, tripleDES.IV);
        using var ms = new MemoryStream(cipherText);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs);

        return sr.ReadToEnd();
    }

    /// <summary>
    /// Decrypts the Base64 encoded cipher text using TripleDES encryption with the specified key and IV texts and returns the result as a string.
    /// </summary>
    /// <param name="cipherText">The Base64 encoded cipher text.</param>
    /// <param name="keyText">The decryption key text.</param>
    /// <param name="ivText">The initialization vector text.</param>
    /// <returns>The decrypted string.</returns>
    public static string TripleDesDecrypt(this string cipherText, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return TripleDesDecryptWithBase64Key(cipherText, key, iv);
    }

    /// <summary>
    /// Decrypts the given cipher text bytes using TripleDES encryption with the provided key and IV.
    /// </summary>
    /// <param name="cipherText">The encrypted data to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>An array of bytes representing the decrypted data.</returns>
    public static byte[] TripleDesDecryptAsBytes(this byte[] cipherText, byte[] key, byte[] iv)
    {
        using var tripleDES = TripleDES.Create();
        tripleDES.Key = key;
        tripleDES.IV = iv;

        using var decryptor = tripleDES.CreateDecryptor(tripleDES.Key, tripleDES.IV);
        using var ms = new MemoryStream(cipherText);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

        var decryptedBytes = new byte[cipherText.Length];
        var bytesRead = cs.Read(decryptedBytes, 0, decryptedBytes.Length);

        return decryptedBytes.Take(bytesRead).ToArray();
    }

    /// <summary>
    /// Decrypts the given cipher text bytes using TripleDES encryption with the specified key and IV texts.
    /// </summary>
    /// <param name="cipherText">The encrypted data to decrypt.</param>
    /// <param name="keyText">The decryption key text.</param>
    /// <param name="ivText">The initialization vector text.</param>
    /// <returns>An array of bytes representing the decrypted data.</returns>
    public static byte[] TripleDesDecryptAsBytes(this byte[] cipherText, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return TripleDesDecryptAsBytesWithBase64Key(cipherText, key, iv);
    }

    /// <summary>
    /// Decrypts the given cipher text bytes using TripleDES encryption with the provided Base64 encoded key and IV.
    /// </summary>
    /// <param name="cipherText">The encrypted data to decrypt.</param>
    /// <param name="base64Key">The Base64 encoded decryption key.</param>
    /// <param name="base64Iv">The Base64 encoded initialization vector.</param>
    /// <returns>An array of bytes representing the decrypted data.</returns>
    public static byte[] TripleDesDecryptAsBytesWithBase64Key(this byte[] cipherText, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        return TripleDesDecryptAsBytes(cipherText, key, iv);
    }

    /// <summary>
    /// Decrypts the given byte array using TripleDES encryption with the provided key and IV and returns it as a stream.
    /// </summary>
    /// <param name="cipherText">The encrypted data to decrypt.</param>
    /// <param name="key">The decryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>A stream representing the decrypted data.</returns>
    public static Stream TripleDesDecryptAsStream(this byte[] cipherText, byte[] key, byte[] iv)
    {
        using var tripleDES = TripleDES.Create();
        tripleDES.Key = key;
        tripleDES.IV = iv;

        using var decryptor = tripleDES.CreateDecryptor(tripleDES.Key, tripleDES.IV);
        var ms = new MemoryStream(cipherText);
        var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

        var resultStream = new MemoryStream();
        cs.CopyTo(resultStream);
        resultStream.Position = 0;

        return resultStream;
    }

    /// <summary>
    /// Decrypts the provided cipher text stream using TripleDES encryption with the specified key and IV texts and returns the result as a stream.
    /// </summary>
    /// <param name="cipherTextStream">The encrypted stream to decrypt.</param>
    /// <param name="keyText">The decryption key text.</param>
    /// <param name="ivText">The initialization vector text.</param>
    /// <returns>A stream representing the decrypted data.</returns>
    public static Stream TripleDesDecryptAsStream(this Stream cipherTextStream, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return TripleDesDecryptAsStreamWithBase64Key(cipherTextStream, key, iv);
    }

    /// <summary>
    /// Decrypts the provided cipher text stream using TripleDES encryption with the Base64 encoded key and IV and returns the result as a stream.
    /// </summary>
    /// <param name="cipherTextStream">The encrypted stream to decrypt.</param>
    /// <param name="base64Key">The Base64 encoded decryption key.</param>
    /// <param name="base64Iv">The Base64 encoded initialization vector.</param>
    /// <returns>A stream representing the decrypted data.</returns>
    public static Stream TripleDesDecryptAsStreamWithBase64Key(this Stream cipherTextStream, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        var cipherText = new byte[cipherTextStream.Length];
        _ = cipherTextStream.Read(cipherText, 0, cipherText.Length);
        return TripleDesDecryptAsStream(cipherText, key, iv);
    }

    /// <summary>
    /// Decrypts the Base64 encoded cipher text using TripleDES encryption with the Base64 encoded key and IV, returning the decrypted string.
    /// </summary>
    /// <param name="cipherText">The Base64 encoded cipher text.</param>
    /// <param name="base64Key">The Base64 encoded decryption key.</param>
    /// <param name="base64Iv">The Base64 encoded initialization vector.</param>
    /// <returns>The decrypted string.</returns>
    public static string TripleDesDecryptWithBase64Key(this string cipherText, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        var cipherBytes = Convert.FromBase64String(cipherText);
        return TripleDesDecrypt(cipherBytes, key, iv);
    }

    /// <summary>
    /// Encrypts the provided plaintext string using TripleDES with the specified key and IV.
    /// </summary>
    /// <param name="plaintext">The text to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>An array of bytes representing the encrypted data.</returns>
    public static byte[] TripleDesEncrypt(this string plaintext, byte[] key, byte[] iv)
    {
        using var tripleDES = TripleDES.Create();
        tripleDES.Key = key;
        tripleDES.IV = iv;

        using var encryptor = tripleDES.CreateEncryptor(tripleDES.Key, tripleDES.IV);
        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cs))
        {
            sw.Write(plaintext);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Encrypts the provided byte data using TripleDES with the specified key and IV.
    /// </summary>
    /// <param name="data">The byte data to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>An array of bytes representing the encrypted data.</returns>
    public static byte[] TripleDesEncrypt(this byte[] data, byte[] key, byte[] iv)
    {
        using var tripleDES = TripleDES.Create();
        tripleDES.Key = key;
        tripleDES.IV = iv;

        using var encryptor = tripleDES.CreateEncryptor(tripleDES.Key, tripleDES.IV);
        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Encrypts the provided stream using TripleDES with the specified key and IV.
    /// </summary>
    /// <param name="stream">The stream to encrypt.</param>
    /// <param name="key">The encryption key.</param>
    /// <param name="iv">The initialization vector.</param>
    /// <returns>A stream representing the encrypted data.</returns>
    public static Stream TripleDesEncrypt(this Stream stream, byte[] key, byte[] iv)
    {
        using var tripleDES = TripleDES.Create();
        tripleDES.Key = key;
        tripleDES.IV = iv;

        using var encryptor = tripleDES.CreateEncryptor(tripleDES.Key, tripleDES.IV);
        var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            stream.CopyTo(cs);
        }
        ms.Position = 0;
        return ms;
    }

    /// <summary>
    /// Encrypts the given plaintext using TripleDES encryption with the specified key and IV texts.
    /// </summary>
    /// <param name="plaintext">The text to encrypt.</param>
    /// <param name="keyText">The encryption key text.</param>
    /// <param name="ivText">The initialization vector text.</param>
    /// <returns>An array of bytes representing the encrypted data.</returns>
    public static byte[] TripleDesEncrypt(this string plaintext, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return TripleDesEncryptWithBase64Key(plaintext, key, iv);
    }

    /// <summary>
    /// Encrypts the given byte data using TripleDES encryption with the specified key and IV texts.
    /// </summary>
    /// <param name="data">The byte data to encrypt.</param>
    /// <param name="keyText">The encryption key text.</param>
    /// <param name="ivText">The initialization vector text.</param>
    /// <returns>An array of bytes representing the encrypted data.</returns>
    public static byte[] TripleDesEncrypt(this byte[] data, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return TripleDesEncryptWithBase64Key(data, key, iv);
    }

    /// <summary>
    /// Encrypts the given stream using TripleDES encryption with the specified key and IV texts.
    /// </summary>
    /// <param name="stream">The stream to encrypt.</param>
    /// <param name="keyText">The encryption key text.</param>
    /// <param name="ivText">The initialization vector text.</param>
    /// <returns>A stream representing the encrypted data.</returns>
    public static Stream TripleDesEncrypt(this Stream stream, string keyText, string ivText)
    {
        var key = Convert.ToBase64String(Encoding.UTF8.GetBytes(keyText));
        var iv = Convert.ToBase64String(Encoding.UTF8.GetBytes(ivText));
        return TripleDesEncryptWithBase64Key(stream, key, iv);
    }

    /// <summary>
    /// Encrypts the given plaintext using TripleDES encryption with the specified Base64 encoded key and IV.
    /// </summary>
    /// <param name="plaintext">The text to encrypt.</param>
    /// <param name="base64Key">The Base64 encoded encryption key.</param>
    /// <param name="base64Iv">The Base64 encoded initialization vector.</param>
    /// <returns>An array of bytes representing the encrypted data.</returns>
    public static byte[] TripleDesEncryptWithBase64Key(this string plaintext, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        return TripleDesEncrypt(plaintext, key, iv);
    }

    /// <summary>
    /// Encrypts the given byte data using TripleDES encryption with the specified Base64 encoded key and IV.
    /// </summary>
    /// <param name="data">The byte data to encrypt.</param>
    /// <param name="base64Key">The Base64 encoded encryption key.</param>
    /// <param name="base64Iv">The Base64 encoded initialization vector.</param>
    /// <returns>An array of bytes representing the encrypted data.</returns>
    public static byte[] TripleDesEncryptWithBase64Key(this byte[] data, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        return TripleDesEncrypt(data, key, iv);
    }

    /// <summary>
    /// Encrypts the given stream using TripleDES encryption with the specified Base64 encoded key and IV.
    /// </summary>
    /// <param name="stream">The stream to encrypt.</param>
    /// <param name="base64Key">The Base64 encoded encryption key.</param>
    /// <param name="base64Iv">The Base64 encoded initialization vector.</param>
    /// <returns>A stream representing the encrypted data.</returns>
    public static Stream TripleDesEncryptWithBase64Key(this Stream stream, string base64Key, string base64Iv)
    {
        var key = Convert.FromBase64String(base64Key);
        var iv = Convert.FromBase64String(base64Iv);
        return TripleDesEncrypt(stream, key, iv);
    }

    /// <summary>
    /// Verifies the digital signature of the given data using the specified RSA public key.
    /// </summary>
    /// <param name="data">The data to verify.</param>
    /// <param name="signature">The signature of the data.</param>
    /// <param name="publicKey">The RSA public key for verification.</param>
    /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
    public static bool VerifyDigitalSignature(this byte[] data, byte[] signature, RSAParameters publicKey)
    {
        using var rsa = new RSACryptoServiceProvider();
        rsa.ImportParameters(publicKey);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>
    /// Verifies the validity of the provided X509 certificate.
    /// </summary>
    /// <param name="certificate">The X509 certificate to verify.</param>
    /// <returns><c>true</c> if the certificate is valid; otherwise, <c>false</c>.</returns>
    public static bool VerifyX509Certificate(this X509Certificate2 certificate)
    {
        var chain = new X509Chain
        {
            ChainPolicy =
            {
                RevocationMode = X509RevocationMode.Online,
                RevocationFlag = X509RevocationFlag.EntireChain
            }
        };

        return chain.Build(certificate);
    }

    /// <summary>
    /// Generates a random salt of the specified size.
    /// </summary>
    /// <param name="saltSize">Size of the salt to generate. Default is 16 bytes.</param>
    /// <returns>An array of bytes representing the salt.</returns>
    private static byte[] GenerateRandomSalt(int saltSize = 16)
    {
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[saltSize];
        rng.GetBytes(salt);
        return salt;
    }

    /// <summary>
    /// Generates an RSA key pair.
    /// </summary>
    /// <returns>The RSA parameters representing the key pair.</returns>
    private static RSAParameters GenerateRSAKeyPair()
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        return rsa.ExportParameters(true);
    }

    /// <summary>
    /// Computes the hash of the provided input string using the given hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="input">The input string to hash.</param>
    /// <returns>The computed hash in hexadecimal form.</returns>
    private static string GetHash(HashAlgorithm hashAlgorithm, string input)
    {
        var data = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(data).Replace("-", string.Empty);
    }

    /// <summary>
    /// Computes the hash of the provided input bytes using the given hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="input">The input bytes to hash.</param>
    /// <returns>The computed hash in hexadecimal form.</returns>
    private static string GetHash(HashAlgorithm hashAlgorithm, byte[] input)
    {
        var data = hashAlgorithm.ComputeHash(input);
        return BitConverter.ToString(data).Replace("-", string.Empty);
    }

    /// <summary>
    /// Computes the hash of the provided input stream using the given hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="stream">The input stream to hash.</param>
    /// <returns>The computed hash in hexadecimal form.</returns>
    private static string GetHash(HashAlgorithm hashAlgorithm, Stream stream)
    {
        var data = hashAlgorithm.ComputeHash(stream);
        return BitConverter.ToString(data).Replace("-", string.Empty);
    }
}