using FmoCaTool.Crypto;

namespace FmoCaTool.Certs;

public static class CertificateValidation
{
    public static void ValidateRoot(RootCaCert certificate)
    {
        RequirePositive(certificate.Sn, "Root sn");
        RequireText(certificate.IssuerName, "Root issuer name");
        RequireText(certificate.IssuerEmail, "Root issuer email");
        RequireText(certificate.SubjectName, "Root subject name");
        RequireText(certificate.KeyId, "Root keyId");
        if (!string.Equals(certificate.IssuerName, certificate.SubjectName, StringComparison.Ordinal))
        {
            throw new CliException("Root issuer name must equal its subject name.");
        }

        RequireLength(certificate.SubjectPublicKey, Ed25519Helper.PublicKeySize, "Root public key");
        RequireLength(certificate.Signature, Ed25519Helper.SignatureSize, "Root signature");
        RequireTimeRange(certificate.Iat, certificate.Exp);
    }

    public static void ValidateIntermediate(IntermediateCaCert certificate)
    {
        RequirePositive(certificate.Sn, "Intermediate sn");
        RequirePositive(certificate.IssuerSn, "Intermediate issuerSn");
        RequireText(certificate.IssuerName, "Intermediate issuer name");
        RequireText(certificate.SubjectName, "Intermediate subject name");
        RequireText(certificate.SubjectEmail, "Intermediate subject email");
        RequireText(certificate.KeyId, "Intermediate keyId");
        RequireLength(certificate.IssuerPublicKey, Ed25519Helper.PublicKeySize, "Intermediate issuer public key");
        RequireLength(certificate.SubjectPublicKey, Ed25519Helper.PublicKeySize, "Intermediate public key");
        RequireLength(certificate.Signature, Ed25519Helper.SignatureSize, "Intermediate signature");
        if (certificate.UidRangeStart < 0)
        {
            throw new CliException("Intermediate UID range start must be non-negative.");
        }

        if (certificate.UidRangeEnd < certificate.UidRangeStart)
        {
            throw new CliException("Intermediate UID range start must be less than or equal to end.");
        }

        foreach (var country in certificate.IssuingCountries)
        {
            ValidateNormalizedCountry(country);
        }

        RequireTimeRange(certificate.Iat, certificate.Exp);
    }

    public static void ValidateUser(UserCert certificate)
    {
        RequirePositive(certificate.IssuerSn, "User issuerSn");
        _ = NormalizeCallsign(certificate.Callsign);
        if (certificate.Uid < 0)
        {
            throw new CliException("User UID must be non-negative.");
        }

        RequireLength(certificate.PublicKey, Ed25519Helper.PublicKeySize, "User public key");
        RequireLength(certificate.Signature, Ed25519Helper.SignatureSize, "User signature");
        RequireTimeRange(certificate.Iat, certificate.Exp);
    }

    public static string NormalizeCallsign(string value)
    {
        var callsign = value.Trim().ToUpperInvariant();
        if (callsign.Length == 0)
        {
            throw new CliException("Callsign must not be empty.");
        }

        if (callsign.Any(character => character > 0x7f || char.IsControl(character) || char.IsWhiteSpace(character)))
        {
            throw new CliException("Callsign must contain only non-whitespace ASCII characters.");
        }

        return callsign;
    }

    public static string[] NormalizeCountries(string value)
    {
        var countries = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(country => country.ToUpperInvariant())
            .ToArray();
        if (countries.Length == 0)
        {
            throw new CliException("At least one issuing country is required.");
        }

        foreach (var country in countries)
        {
            ValidateNormalizedCountry(country);
        }

        return countries.Distinct(StringComparer.Ordinal).OrderBy(country => country, StringComparer.Ordinal).ToArray();
    }

    public static void ValidateNormalizedCountry(string country)
    {
        if (country.Length != 2 || country.Any(character => character is < 'A' or > 'Z'))
        {
            throw new CliException($"Invalid country code '{country}'; expected two uppercase ASCII letters.");
        }
    }

    public static void RequireKeyMatches(byte[] certificatePublicKey, KeyFile key, string description)
    {
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(certificatePublicKey, key.PublicKey))
        {
            throw new CliException($"{description} private key does not match the certificate public key.");
        }
    }

    public static void RequireTimeRange(long iat, long exp)
    {
        if (exp <= iat)
        {
            throw new CliException("Certificate exp must be greater than iat.");
        }
    }

    private static void RequirePositive(long value, string displayName)
    {
        if (value <= 0)
        {
            throw new CliException($"{displayName} must be positive.");
        }
    }

    private static void RequireText(string value, string displayName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new CliException($"{displayName} must not be empty.");
        }
    }

    private static void RequireLength(byte[] value, int expectedLength, string displayName)
    {
        if (value.Length != expectedLength)
        {
            throw new CliException($"{displayName} must be exactly {expectedLength} bytes.");
        }
    }
}
