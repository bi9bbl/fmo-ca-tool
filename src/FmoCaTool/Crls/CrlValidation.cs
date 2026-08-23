using FmoCaTool.Crypto;

namespace FmoCaTool.Crls;

public static class CrlValidation
{
    public static void Validate(RootCrl crl, bool requireCanonicalOrder = true)
    {
        ValidateHeader(crl.IssuerSn, crl.CrlNumber, crl.ThisUpdate, crl.NextUpdate);
        if (requireCanonicalOrder && !CrlEntryComparer.IsSorted(crl.Entries))
        {
            throw new CliException("Root CRL entries must be sorted by sn and raw certFingerprint bytes.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in crl.Entries)
        {
            if (entry.Sn <= 0)
            {
                throw new CliException("Root CRL entry sn must be positive.");
            }

            ValidateEntry(entry.CertFingerprint, entry.RevokedAt, entry.Reason, 5, "Root CRL");
            if (!seen.Add($"{entry.Sn}:{Convert.ToHexString(entry.CertFingerprint)}"))
            {
                throw new CliException("Root CRL contains a duplicate sn + certFingerprint entry.");
            }
        }

        RequireSignature(crl.Signature, "Root CRL");
    }

    public static void Validate(IntermediateCrl crl, bool requireCanonicalOrder = true)
    {
        ValidateHeader(crl.IssuerSn, crl.CrlNumber, crl.ThisUpdate, crl.NextUpdate);
        if (requireCanonicalOrder && !CrlEntryComparer.IsSorted(crl.Entries))
        {
            throw new CliException("Intermediate CRL entries must be sorted by uid and raw certFingerprint bytes.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in crl.Entries)
        {
            if (entry.Uid < 0)
            {
                throw new CliException("Intermediate CRL entry uid must be non-negative.");
            }

            ValidateEntry(entry.CertFingerprint, entry.RevokedAt, entry.Reason, 4, "Intermediate CRL");
            if (!seen.Add($"{entry.Uid}:{Convert.ToHexString(entry.CertFingerprint)}"))
            {
                throw new CliException("Intermediate CRL contains a duplicate uid + certFingerprint entry.");
            }
        }

        RequireSignature(crl.Signature, "Intermediate CRL");
    }

    private static void ValidateHeader(long issuerSn, long crlNumber, long thisUpdate, long nextUpdate)
    {
        if (issuerSn <= 0)
        {
            throw new CliException("CRL issuerSn must be positive.");
        }

        if (crlNumber <= 0)
        {
            throw new CliException("CRL crlNumber must be positive.");
        }

        if (thisUpdate < 0 || nextUpdate < 0)
        {
            throw new CliException("CRL update timestamps must be non-negative.");
        }

        if (nextUpdate < thisUpdate)
        {
            throw new CliException("CRL nextUpdate must not be earlier than thisUpdate.");
        }
    }

    private static void ValidateEntry(byte[] fingerprint, long revokedAt, long reason, long maxReason, string kind)
    {
        if (fingerprint.Length != 32)
        {
            throw new CliException($"{kind} certFingerprint must be exactly 32 bytes.");
        }

        if (revokedAt < 0)
        {
            throw new CliException($"{kind} revokedAt must be non-negative.");
        }

        if (reason < 0 || reason > maxReason)
        {
            throw new CliException($"{kind} reason must be between 0 and {maxReason}.");
        }
    }

    private static void RequireSignature(byte[] signature, string kind)
    {
        if (signature.Length != Ed25519Helper.SignatureSize)
        {
            throw new CliException($"{kind} signature must be exactly {Ed25519Helper.SignatureSize} bytes.");
        }
    }
}
