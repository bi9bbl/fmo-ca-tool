using System.Text;
using System.Text.Json;
using FmoCaTool.Certs;

namespace FmoCaTool.Crls;

public static class CrlJson
{
    public static CrlBase Load(string path)
    {
        try
        {
            return Parse(File.ReadAllText(path, Encoding.UTF8));
        }
        catch (CliException)
        {
            throw;
        }
        catch (FileNotFoundException ex)
        {
            throw new CliException($"CRL file not found: {path}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new CliException($"Cannot read CRL file: {path}", ex);
        }
        catch (IOException ex)
        {
            throw new CliException($"Cannot read CRL file '{path}': {ex.Message}", ex);
        }
    }

    public static T Load<T>(string path)
        where T : CrlBase
    {
        var crl = Load(path);
        if (crl is not T typed)
        {
            throw new CliException($"CRL '{path}' has type '{crl.Type}', expected '{ExpectedType<T>()}'.");
        }

        return typed;
    }

    public static CrlBase Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new CliException("CRL JSON root must be an object.");
            }

            var type = RequiredString(root, "type");
            return type switch
            {
                "rootCRL" => ParseRoot(root),
                "intermediateCRL" => ParseIntermediate(root),
                _ => throw new CliException($"Unsupported CRL type '{type}'.")
            };
        }
        catch (CliException)
        {
            throw;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new CliException($"Invalid CRL JSON: {ex.Message}", ex);
        }
    }

    public static string Serialize(CrlBase crl)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, JsonOutput.WriterOptions))
        {
            switch (crl)
            {
                case RootCrl root:
                    WriteRoot(writer, root);
                    break;
                case IntermediateCrl intermediate:
                    WriteIntermediate(writer, intermediate);
                    break;
                default:
                    throw new ArgumentException("Unknown CRL type.", nameof(crl));
            }
        }

        return JsonOutput.Finish(stream);
    }

    private static RootCrl ParseRoot(JsonElement root)
    {
        RequireAlgorithm(root);
        var crl = new RootCrl
        {
            IssuerSn = RequiredInt64(root, "issuerSn"),
            CrlNumber = RequiredInt64(root, "crlNumber"),
            ThisUpdate = RequiredInt64(root, "thisUpdate"),
            NextUpdate = RequiredInt64(root, "nextUpdate"),
            Entries = RequiredArray(root, "entries").EnumerateArray().Select((element, index) => new RootCrlEntry
            {
                Sn = RequiredInt64(element, "sn"),
                CertFingerprint = DecodeFingerprint(element, index),
                RevokedAt = RequiredInt64(element, "revokedAt"),
                Reason = RequiredInt64(element, "reason")
            }).ToArray(),
            Signature = Base64Url.Decode(RequiredString(root, "signature"), "signature")
        };
        CrlValidation.Validate(crl, requireCanonicalOrder: false);
        return crl;
    }

    private static IntermediateCrl ParseIntermediate(JsonElement root)
    {
        RequireAlgorithm(root);
        var crl = new IntermediateCrl
        {
            IssuerSn = RequiredInt64(root, "issuerSn"),
            CrlNumber = RequiredInt64(root, "crlNumber"),
            ThisUpdate = RequiredInt64(root, "thisUpdate"),
            NextUpdate = RequiredInt64(root, "nextUpdate"),
            Entries = RequiredArray(root, "entries").EnumerateArray().Select((element, index) => new IntermediateCrlEntry
            {
                Uid = RequiredInt64(element, "uid"),
                CertFingerprint = DecodeFingerprint(element, index),
                RevokedAt = RequiredInt64(element, "revokedAt"),
                Reason = RequiredInt64(element, "reason")
            }).ToArray(),
            Signature = Base64Url.Decode(RequiredString(root, "signature"), "signature")
        };
        CrlValidation.Validate(crl, requireCanonicalOrder: false);
        return crl;
    }

    private static byte[] DecodeFingerprint(JsonElement element, int index)
    {
        var fingerprint = Base64Url.Decode(RequiredString(element, "certFingerprint"), $"entries[{index}].certFingerprint");
        if (fingerprint.Length != 32)
        {
            throw new CliException($"entries[{index}].certFingerprint must decode to exactly 32 bytes.");
        }

        return fingerprint;
    }

    private static void WriteRoot(Utf8JsonWriter writer, RootCrl crl)
    {
        WriteHeader(writer, crl.Type, crl.IssuerSn, crl.CrlNumber, crl.ThisUpdate, crl.NextUpdate);
        writer.WriteStartArray("entries");
        foreach (var entry in crl.Entries)
        {
            writer.WriteStartObject();
            writer.WriteNumber("sn", entry.Sn);
            WriteEntry(writer, entry.CertFingerprint, entry.RevokedAt, entry.Reason);
        }

        WriteFooter(writer, crl.Signature);
    }

    private static void WriteIntermediate(Utf8JsonWriter writer, IntermediateCrl crl)
    {
        WriteHeader(writer, crl.Type, crl.IssuerSn, crl.CrlNumber, crl.ThisUpdate, crl.NextUpdate);
        writer.WriteStartArray("entries");
        foreach (var entry in crl.Entries)
        {
            writer.WriteStartObject();
            writer.WriteNumber("uid", entry.Uid);
            WriteEntry(writer, entry.CertFingerprint, entry.RevokedAt, entry.Reason);
        }

        WriteFooter(writer, crl.Signature);
    }

    private static void WriteHeader(Utf8JsonWriter writer, string type, long issuerSn, long number, long thisUpdate, long nextUpdate)
    {
        writer.WriteStartObject();
        writer.WriteString("type", type);
        writer.WriteNumber("issuerSn", issuerSn);
        writer.WriteNumber("crlNumber", number);
        writer.WriteNumber("thisUpdate", thisUpdate);
        writer.WriteNumber("nextUpdate", nextUpdate);
    }

    private static void WriteEntry(Utf8JsonWriter writer, byte[] fingerprint, long revokedAt, long reason)
    {
        writer.WriteString("certFingerprint", Base64Url.Encode(fingerprint));
        writer.WriteNumber("revokedAt", revokedAt);
        writer.WriteNumber("reason", reason);
        writer.WriteEndObject();
    }

    private static void WriteFooter(Utf8JsonWriter writer, byte[] signature)
    {
        writer.WriteEndArray();
        writer.WriteString("signatureAlgorithm", "Ed25519");
        writer.WriteString("signature", Base64Url.Encode(signature));
        writer.WriteEndObject();
    }

    private static JsonElement RequiredArray(JsonElement parent, string name)
    {
        var property = parent.GetProperty(name);
        if (property.ValueKind != JsonValueKind.Array)
        {
            throw new CliException($"{name} must be an array.");
        }

        return property;
    }

    private static string RequiredString(JsonElement parent, string name)
    {
        var property = parent.GetProperty(name);
        if (property.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw new CliException($"{name} must be a non-empty string.");
        }

        return property.GetString()!;
    }

    private static long RequiredInt64(JsonElement parent, string name)
    {
        var property = parent.GetProperty(name);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt64(out var value))
        {
            throw new CliException($"{name} must be a signed 64-bit integer.");
        }

        return value;
    }

    private static void RequireAlgorithm(JsonElement root)
    {
        if (!string.Equals(RequiredString(root, "signatureAlgorithm"), "Ed25519", StringComparison.Ordinal))
        {
            throw new CliException("signatureAlgorithm must be 'Ed25519'.");
        }
    }

    private static string ExpectedType<T>() where T : CrlBase => typeof(T) == typeof(RootCrl)
        ? "rootCRL"
        : "intermediateCRL";
}
