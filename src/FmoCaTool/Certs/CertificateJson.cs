using System.Text;
using System.Text.Json;

namespace FmoCaTool.Certs;

public static class CertificateJson
{
    public static CertBase Load(string path)
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
            throw new CliException($"Certificate file not found: {path}", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new CliException($"Cannot read certificate file: {path}", ex);
        }
        catch (IOException ex)
        {
            throw new CliException($"Cannot read certificate file '{path}': {ex.Message}", ex);
        }
    }

    public static T Load<T>(string path)
        where T : CertBase
    {
        var certificate = Load(path);
        if (certificate is not T typed)
        {
            throw new CliException($"Certificate '{path}' has type '{certificate.Type}', expected '{ExpectedType<T>()}'.");
        }

        return typed;
    }

    public static CertBase Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new CliException("Certificate JSON root must be an object.");
            }

            var type = RequiredString(root, "type", "certificate type");
            return type switch
            {
                "rootCA" => ParseRoot(root),
                "intermediateCA" => ParseIntermediate(root),
                "userCert" => ParseUser(root),
                _ => throw new CliException($"Unsupported certificate type '{type}'.")
            };
        }
        catch (CliException)
        {
            throw;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new CliException($"Invalid certificate JSON: {ex.Message}", ex);
        }
    }

    public static string Serialize(CertBase certificate)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, JsonOutput.WriterOptions))
        {
            switch (certificate)
            {
                case RootCaCert root:
                    WriteRoot(writer, root);
                    break;
                case IntermediateCaCert intermediate:
                    WriteIntermediate(writer, intermediate);
                    break;
                case UserCert user:
                    WriteUser(writer, user);
                    break;
                default:
                    throw new ArgumentException("Unknown certificate type.", nameof(certificate));
            }
        }

        return JsonOutput.Finish(stream);
    }

    private static RootCaCert ParseRoot(JsonElement root)
    {
        var issuer = RequiredObject(root, "issuer");
        var subject = RequiredObject(root, "subject");
        var extensions = RequiredObject(root, "extensions");
        RequireBoolean(extensions, "isCA", true);
        RequireInt64(extensions, "pathLen", 1);
        RequireAlgorithm(root);

        var certificate = new RootCaCert
        {
            Sn = RequiredInt64(root, "sn"),
            IssuerName = RequiredString(issuer, "name", "issuer.name"),
            IssuerEmail = RequiredString(issuer, "email", "issuer.email"),
            SubjectName = RequiredString(subject, "name", "subject.name"),
            SubjectPublicKey = Base64Url.Decode(RequiredString(subject, "publicKey", "subject.publicKey"), "subject.publicKey"),
            Crl = RequiredStringAllowEmpty(extensions, "crl", "extensions.crl"),
            License = RequiredStringAllowEmpty(extensions, "license", "extensions.license"),
            KeyId = RequiredString(extensions, "keyId", "extensions.keyId"),
            Iat = RequiredInt64(root, "iat"),
            Exp = RequiredInt64(root, "exp"),
            Signature = Base64Url.Decode(RequiredString(root, "signature", "signature"), "signature")
        };
        CertificateValidation.ValidateRoot(certificate);
        return certificate;
    }

    private static IntermediateCaCert ParseIntermediate(JsonElement root)
    {
        var issuer = RequiredObject(root, "issuer");
        var subject = RequiredObject(root, "subject");
        var extensions = RequiredObject(root, "extensions");
        var uidRange = RequiredObject(extensions, "uidRange");
        RequireBoolean(extensions, "isCA", true);
        RequireInt64(extensions, "pathLen", 0);
        RequireAlgorithm(root);

        var countriesElement = extensions.GetProperty("issuingCountries");
        if (countriesElement.ValueKind != JsonValueKind.Array)
        {
            throw new CliException("extensions.issuingCountries must be an array.");
        }

        var countries = countriesElement.EnumerateArray()
            .Select((element, index) => element.ValueKind == JsonValueKind.String
                ? element.GetString() ?? ""
                : throw new CliException($"extensions.issuingCountries[{index}] must be a string."))
            .ToArray();
        foreach (var country in countries)
        {
            CertificateValidation.ValidateNormalizedCountry(country);
        }

        countries = countries.OrderBy(value => value, StringComparer.Ordinal).ToArray();
        var certificate = new IntermediateCaCert
        {
            Sn = RequiredInt64(root, "sn"),
            IssuerSn = RequiredInt64(issuer, "sn"),
            IssuerName = RequiredString(issuer, "name", "issuer.name"),
            IssuerPublicKey = Base64Url.Decode(RequiredString(issuer, "publicKey", "issuer.publicKey"), "issuer.publicKey"),
            SubjectName = RequiredString(subject, "name", "subject.name"),
            SubjectEmail = RequiredString(subject, "email", "subject.email"),
            SubjectPublicKey = Base64Url.Decode(RequiredString(subject, "publicKey", "subject.publicKey"), "subject.publicKey"),
            KeyId = RequiredString(extensions, "keyId", "extensions.keyId"),
            Crl = RequiredStringAllowEmpty(extensions, "crl", "extensions.crl"),
            License = RequiredStringAllowEmpty(extensions, "license", "extensions.license"),
            UidRangeStart = RequiredInt64(uidRange, "start"),
            UidRangeEnd = RequiredInt64(uidRange, "end"),
            IssuingCountries = countries,
            Iat = RequiredInt64(root, "iat"),
            Exp = RequiredInt64(root, "exp"),
            Signature = Base64Url.Decode(RequiredString(root, "signature", "signature"), "signature")
        };
        CertificateValidation.ValidateIntermediate(certificate);
        return certificate;
    }

    private static UserCert ParseUser(JsonElement root)
    {
        var subject = RequiredObject(root, "subject");
        RequireAlgorithm(root);
        var callsign = CertificateValidation.NormalizeCallsign(RequiredString(subject, "callsign", "subject.callsign"));
        var certificate = new UserCert
        {
            IssuerSn = RequiredInt64(root, "issuerSn"),
            Callsign = callsign,
            Uid = RequiredInt64(subject, "uid"),
            PublicKey = Base64Url.Decode(RequiredString(subject, "publicKey", "subject.publicKey"), "subject.publicKey"),
            Iat = RequiredInt64(root, "iat"),
            Exp = RequiredInt64(root, "exp"),
            Signature = Base64Url.Decode(RequiredString(root, "signature", "signature"), "signature")
        };
        CertificateValidation.ValidateUser(certificate);
        return certificate;
    }

    private static void WriteRoot(Utf8JsonWriter writer, RootCaCert certificate)
    {
        writer.WriteStartObject();
        writer.WriteNumber("sn", certificate.Sn);
        writer.WriteString("type", certificate.Type);
        writer.WriteStartObject("issuer");
        writer.WriteString("name", certificate.IssuerName);
        writer.WriteString("email", certificate.IssuerEmail);
        writer.WriteEndObject();
        writer.WriteStartObject("subject");
        writer.WriteString("name", certificate.SubjectName);
        writer.WriteString("publicKey", Base64Url.Encode(certificate.SubjectPublicKey));
        writer.WriteEndObject();
        writer.WriteStartObject("extensions");
        writer.WriteBoolean("isCA", certificate.IsCa);
        writer.WriteNumber("pathLen", certificate.PathLen);
        writer.WriteString("crl", certificate.Crl);
        writer.WriteString("license", certificate.License);
        writer.WriteString("keyId", certificate.KeyId);
        writer.WriteEndObject();
        WriteFooter(writer, certificate.Iat, certificate.Exp, certificate.Signature);
        writer.WriteEndObject();
    }

    private static void WriteIntermediate(Utf8JsonWriter writer, IntermediateCaCert certificate)
    {
        writer.WriteStartObject();
        writer.WriteNumber("sn", certificate.Sn);
        writer.WriteString("type", certificate.Type);
        writer.WriteStartObject("issuer");
        writer.WriteNumber("sn", certificate.IssuerSn);
        writer.WriteString("name", certificate.IssuerName);
        writer.WriteString("publicKey", Base64Url.Encode(certificate.IssuerPublicKey));
        writer.WriteEndObject();
        writer.WriteStartObject("subject");
        writer.WriteString("name", certificate.SubjectName);
        writer.WriteString("email", certificate.SubjectEmail);
        writer.WriteString("publicKey", Base64Url.Encode(certificate.SubjectPublicKey));
        writer.WriteEndObject();
        writer.WriteStartObject("extensions");
        writer.WriteBoolean("isCA", certificate.IsCa);
        writer.WriteNumber("pathLen", certificate.PathLen);
        writer.WriteString("keyId", certificate.KeyId);
        writer.WriteString("crl", certificate.Crl);
        writer.WriteString("license", certificate.License);
        writer.WriteStartObject("uidRange");
        writer.WriteNumber("start", certificate.UidRangeStart);
        writer.WriteNumber("end", certificate.UidRangeEnd);
        writer.WriteEndObject();
        writer.WriteStartArray("issuingCountries");
        foreach (var country in certificate.IssuingCountries)
        {
            writer.WriteStringValue(country);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        WriteFooter(writer, certificate.Iat, certificate.Exp, certificate.Signature);
        writer.WriteEndObject();
    }

    private static void WriteUser(Utf8JsonWriter writer, UserCert certificate)
    {
        writer.WriteStartObject();
        writer.WriteString("type", certificate.Type);
        writer.WriteNumber("issuerSn", certificate.IssuerSn);
        writer.WriteStartObject("subject");
        writer.WriteString("callsign", certificate.Callsign);
        writer.WriteNumber("uid", certificate.Uid);
        writer.WriteString("publicKey", Base64Url.Encode(certificate.PublicKey));
        writer.WriteEndObject();
        WriteFooter(writer, certificate.Iat, certificate.Exp, certificate.Signature);
        writer.WriteEndObject();
    }

    private static void WriteFooter(Utf8JsonWriter writer, long iat, long exp, byte[] signature)
    {
        writer.WriteNumber("iat", iat);
        writer.WriteNumber("exp", exp);
        writer.WriteString("signatureAlgorithm", "Ed25519");
        writer.WriteString("signature", Base64Url.Encode(signature));
    }

    private static JsonElement RequiredObject(JsonElement parent, string propertyName)
    {
        var property = parent.GetProperty(propertyName);
        if (property.ValueKind != JsonValueKind.Object)
        {
            throw new CliException($"{propertyName} must be an object.");
        }

        return property;
    }

    private static string RequiredString(JsonElement parent, string propertyName, string displayName)
    {
        var value = RequiredStringAllowEmpty(parent, propertyName, displayName);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new CliException($"{displayName} must not be empty.");
        }

        return value;
    }

    private static string RequiredStringAllowEmpty(JsonElement parent, string propertyName, string displayName)
    {
        var property = parent.GetProperty(propertyName);
        if (property.ValueKind != JsonValueKind.String)
        {
            throw new CliException($"{displayName} must be a string.");
        }

        return property.GetString() ?? "";
    }

    private static long RequiredInt64(JsonElement parent, string propertyName)
    {
        var property = parent.GetProperty(propertyName);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt64(out var value))
        {
            throw new CliException($"{propertyName} must be a signed 64-bit integer.");
        }

        return value;
    }

    private static void RequireBoolean(JsonElement parent, string propertyName, bool expected)
    {
        var property = parent.GetProperty(propertyName);
        if (property.ValueKind is not (JsonValueKind.True or JsonValueKind.False) || property.GetBoolean() != expected)
        {
            throw new CliException($"extensions.{propertyName} must be {expected.ToString().ToLowerInvariant()}.");
        }
    }

    private static void RequireInt64(JsonElement parent, string propertyName, long expected)
    {
        if (RequiredInt64(parent, propertyName) != expected)
        {
            throw new CliException($"extensions.{propertyName} must be {expected}.");
        }
    }

    private static void RequireAlgorithm(JsonElement root)
    {
        var algorithm = RequiredString(root, "signatureAlgorithm", "signatureAlgorithm");
        if (!string.Equals(algorithm, "Ed25519", StringComparison.Ordinal))
        {
            throw new CliException("signatureAlgorithm must be 'Ed25519'.");
        }
    }

    private static string ExpectedType<T>() where T : CertBase => typeof(T) == typeof(RootCaCert)
        ? "rootCA"
        : typeof(T) == typeof(IntermediateCaCert)
            ? "intermediateCA"
            : "userCert";
}
