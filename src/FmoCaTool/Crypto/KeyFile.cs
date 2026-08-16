using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FmoCaTool.Certs;

namespace FmoCaTool.Crypto;

public sealed class KeyFile
{
    public const string FormatName = "fmo-ed25519-private-key";
    public const int CurrentVersion = 1;

    public required byte[] Seed { get; init; }
    public required byte[] PublicKey { get; init; }

    public static KeyFile Generate()
    {
        var material = Ed25519Helper.Generate();
        return new KeyFile { Seed = material.Seed, PublicKey = material.PublicKey };
    }

    public static KeyFile FromSeed(byte[] seed)
    {
        var material = Ed25519Helper.FromSeed(seed);
        return new KeyFile { Seed = material.Seed, PublicKey = material.PublicKey };
    }

    public static KeyFile Load(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));
            var root = document.RootElement;
            var format = root.GetProperty("format").GetString();
            var version = root.GetProperty("version").GetInt32();
            if (!string.Equals(format, FormatName, StringComparison.Ordinal) || version != CurrentVersion)
            {
                throw new CliException($"Unsupported private key format in '{path}'.");
            }

            var publicKey = Base64Url.Decode(root.GetProperty("publicKey").GetString()!, "private key publicKey");
            var seed = Base64Url.Decode(root.GetProperty("privateKey").GetString()!, "private key privateKey");
            if (seed.Length != Ed25519Helper.SeedSize)
            {
                throw new CliException("Private key material must be a 32-byte Ed25519 seed.");
            }

            if (publicKey.Length != Ed25519Helper.PublicKeySize)
            {
                throw new CliException("Private key file publicKey must be exactly 32 bytes.");
            }

            var derived = Ed25519Helper.DerivePublicKey(seed);
            if (!CryptographicOperations.FixedTimeEquals(publicKey, derived))
            {
                throw new CliException("Private key publicKey does not match the stored Ed25519 seed.");
            }

            return new KeyFile { Seed = seed, PublicKey = publicKey };
        }
        catch (CliException)
        {
            throw;
        }
        catch (FileNotFoundException ex)
        {
            throw new CliException($"Private key file not found: {path}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new CliException($"Cannot read private key file: {path}", ex);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or IOException)
        {
            throw new CliException($"Invalid private key file '{path}': {ex.Message}", ex);
        }
    }

    public string ToJson()
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, JsonOutput.WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("format", FormatName);
            writer.WriteNumber("version", CurrentVersion);
            writer.WriteString("publicKey", Base64Url.Encode(PublicKey));
            writer.WriteString("privateKey", Base64Url.Encode(Seed));
            writer.WriteEndObject();
        }

        return JsonOutput.Finish(stream);
    }
}
