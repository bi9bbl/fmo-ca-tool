using System.Security.Cryptography;
using FmoCaTool.Certs;
using FmoCaTool.Cli;
using FmoCaTool.Crls;

namespace FmoCaTool.Commands;

internal static class VerifyCommand
{
    private static readonly HashSet<string> ValueOptions =
    ["--root", "--intermediate", "--user", "--root-crl", "--intermediate-crl", "--at"];

    private static readonly HashSet<string> FlagOptions = [];

    public static int Run(string[] args, TextWriter output)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteVerify(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions);
        options.RequireNoPositionals();
        var rootPath = options.Optional("--root");
        var intermediatePath = options.Optional("--intermediate");
        var userPath = options.Optional("--user");
        var rootCrlPath = options.Optional("--root-crl");
        var intermediateCrlPath = options.Optional("--intermediate-crl");
        if (rootPath is null && intermediatePath is null && userPath is null && rootCrlPath is null && intermediateCrlPath is null)
        {
            throw new CliException("verify requires at least one certificate or CRL option.");
        }

        if (intermediatePath is not null && rootPath is null)
        {
            throw new CliException("--intermediate requires --root so its issuer signature can be verified.");
        }

        if (userPath is not null && intermediatePath is null)
        {
            throw new CliException("--user requires --intermediate so its issuer signature can be verified.");
        }

        if (rootCrlPath is not null && rootPath is null)
        {
            throw new CliException("--root-crl requires --root.");
        }

        if (intermediateCrlPath is not null && intermediatePath is null)
        {
            throw new CliException("--intermediate-crl requires --intermediate.");
        }

        var at = options.OptionalInt64("--at") ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (at < 0)
        {
            throw new CliException("--at must be non-negative.");
        }

        var errors = new List<string>();
        var warnings = new List<string>();
        var infos = new List<string>();
        var root = rootPath is null ? null : CertificateJson.Load<RootCaCert>(rootPath);
        var intermediate = intermediatePath is null ? null : CertificateJson.Load<IntermediateCaCert>(intermediatePath);
        var user = userPath is null ? null : CertificateJson.Load<UserCert>(userPath);

        if (root is not null)
        {
            if (!root.VerifySelfSignature())
            {
                errors.Add("Root self-signature is invalid.");
            }

            CheckValidity("Root", root.Iat, root.Exp, at, errors);
            infos.Add($"Root fingerprint: {Base64Url.Encode(root.Fingerprint())}");
        }

        if (intermediate is not null && root is not null)
        {
            if (intermediate.IssuerSn != root.Sn ||
                !string.Equals(intermediate.IssuerName, root.SubjectName, StringComparison.Ordinal) ||
                !intermediate.IssuerPublicKey.AsSpan().SequenceEqual(root.SubjectPublicKey))
            {
                errors.Add("Intermediate issuer fields do not bind to the supplied Root.");
            }

            if (!intermediate.VerifyBy(root))
            {
                errors.Add("Intermediate signature is invalid.");
            }

            if (intermediate.Iat < root.Iat || intermediate.Exp > root.Exp)
            {
                errors.Add("Intermediate validity interval is outside the Root validity interval.");
            }

            CheckValidity("Intermediate", intermediate.Iat, intermediate.Exp, at, errors);
            infos.Add($"Intermediate fingerprint: {Base64Url.Encode(intermediate.Fingerprint())}");
        }

        if (user is not null && intermediate is not null)
        {
            if (user.IssuerSn != intermediate.Sn)
            {
                errors.Add("User issuerSn does not match the supplied Intermediate.");
            }

            if (!user.VerifyBy(intermediate))
            {
                errors.Add("User signature is invalid.");
            }

            if (!intermediate.CanIssueFor(user.Uid))
            {
                errors.Add("User UID is outside the Intermediate uidRange.");
            }

            var country = CallsignCountry.Infer(user.Callsign);
            if (country is null)
            {
                warnings.Add("Could not infer a country from the User callsign; issuingCountries was not checked.");
            }
            else if (intermediate.IssuingCountries.Length > 0 &&
                     !intermediate.IssuingCountries.Contains(country, StringComparer.Ordinal))
            {
                errors.Add($"User callsign country {country} is outside the Intermediate issuingCountries scope.");
            }

            if (user.Iat < intermediate.Iat || user.Exp > intermediate.Exp)
            {
                errors.Add("User validity interval is outside the Intermediate validity interval.");
            }

            CheckValidity("User", user.Iat, user.Exp, at, errors);
            infos.Add($"User fingerprint: {Base64Url.Encode(user.Fingerprint())}");
        }

        if (rootCrlPath is not null && root is not null)
        {
            var crl = CrlJson.Load<RootCrl>(rootCrlPath);
            VerifyCrlHeader("Root CRL", crl.IssuerSn, root.Sn, crl.ThisUpdate, crl.NextUpdate, at, errors, warnings);
            if (!crl.VerifyBy(root.SubjectPublicKey))
            {
                errors.Add("Root CRL signature is invalid.");
            }

            if (!CrlEntryComparer.IsSorted(crl.Entries))
            {
                warnings.Add("Root CRL entries are not in canonical raw-fingerprint byte order.");
            }

            infos.Add($"Root CRL number: {crl.CrlNumber}; entries: {crl.Entries.Length}");
            if (intermediate is not null)
            {
                CheckIntermediateRevocation(intermediate, crl, at, errors, infos);
            }
        }

        if (intermediateCrlPath is not null && intermediate is not null)
        {
            var crl = CrlJson.Load<IntermediateCrl>(intermediateCrlPath);
            VerifyCrlHeader("Intermediate CRL", crl.IssuerSn, intermediate.Sn, crl.ThisUpdate, crl.NextUpdate, at, errors, warnings);
            if (!crl.VerifyBy(intermediate.SubjectPublicKey))
            {
                errors.Add("Intermediate CRL signature is invalid.");
            }

            if (!CrlEntryComparer.IsSorted(crl.Entries))
            {
                warnings.Add("Intermediate CRL entries are not in canonical raw-fingerprint byte order.");
            }

            infos.Add($"Intermediate CRL number: {crl.CrlNumber}; entries: {crl.Entries.Length}");
            if (user is not null)
            {
                CheckUserRevocation(user, crl, at, errors, infos);
            }
        }

        output.WriteLine($"Validation time: {at}");
        foreach (var info in infos)
        {
            output.WriteLine($"INFO: {info}");
        }

        foreach (var warning in warnings)
        {
            output.WriteLine($"WARNING: {warning}");
        }

        foreach (var error in errors)
        {
            output.WriteLine($"ERROR: {error}");
        }

        output.WriteLine(errors.Count == 0 ? "VALID" : "INVALID");
        return errors.Count == 0 ? 0 : 3;
    }

    private static void CheckValidity(string kind, long iat, long exp, long at, ICollection<string> errors)
    {
        if (at < iat)
        {
            errors.Add($"{kind} is not valid before Unix timestamp {iat}.");
        }
        else if (at >= exp)
        {
            errors.Add($"{kind} expired at Unix timestamp {exp}.");
        }
    }

    private static void VerifyCrlHeader(
        string kind,
        long issuerSn,
        long expectedIssuerSn,
        long thisUpdate,
        long nextUpdate,
        long at,
        ICollection<string> errors,
        ICollection<string> warnings)
    {
        if (issuerSn != expectedIssuerSn)
        {
            errors.Add($"{kind} issuerSn does not match its issuer certificate.");
        }

        if (at < thisUpdate)
        {
            errors.Add($"{kind} is not applicable before Unix timestamp {thisUpdate}.");
        }
        else if (at > nextUpdate)
        {
            warnings.Add($"{kind} passed nextUpdate at Unix timestamp {nextUpdate}; refresh it before relying on revocation status.");
        }
    }

    private static void CheckIntermediateRevocation(
        IntermediateCaCert certificate,
        RootCrl crl,
        long at,
        ICollection<string> errors,
        ICollection<string> infos)
    {
        var fingerprint = certificate.Fingerprint();
        var serialMatches = crl.Entries.Where(entry => entry.Sn == certificate.Sn).ToArray();
        var exact = serialMatches.FirstOrDefault(entry =>
            CryptographicOperations.FixedTimeEquals(entry.CertFingerprint, fingerprint));
        if (exact is not null && exact.RevokedAt <= at)
        {
            errors.Add($"Intermediate is revoked at Unix timestamp {exact.RevokedAt}; reason={RootReason(exact.Reason)}.");
        }
        else if (exact is not null)
        {
            infos.Add($"Intermediate revocation becomes effective at Unix timestamp {exact.RevokedAt}.");
        }
        else if (serialMatches.Length > 0)
        {
            infos.Add("Root CRL contains the Intermediate SN but no matching certificate fingerprint.");
        }
        else
        {
            infos.Add("Intermediate is not listed in the Root CRL.");
        }
    }

    private static void CheckUserRevocation(
        UserCert certificate,
        IntermediateCrl crl,
        long at,
        ICollection<string> errors,
        ICollection<string> infos)
    {
        var fingerprint = certificate.Fingerprint();
        var uidMatches = crl.Entries.Where(entry => entry.Uid == certificate.Uid).ToArray();
        var exact = uidMatches.FirstOrDefault(entry =>
            CryptographicOperations.FixedTimeEquals(entry.CertFingerprint, fingerprint));
        if (exact is not null && exact.RevokedAt <= at)
        {
            errors.Add($"User Certificate is revoked at Unix timestamp {exact.RevokedAt}; reason={IntermediateReason(exact.Reason)}.");
        }
        else if (exact is not null)
        {
            infos.Add($"User Certificate revocation becomes effective at Unix timestamp {exact.RevokedAt}.");
        }
        else if (uidMatches.Length > 0)
        {
            infos.Add("Intermediate CRL contains the User UID but no matching certificate fingerprint.");
        }
        else
        {
            infos.Add("User Certificate is not listed in the Intermediate CRL.");
        }
    }

    private static string RootReason(long reason) => reason switch
    {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "caCompromise",
        3 => "superseded",
        4 => "privilegeWithdrawn",
        5 => "cessationOfOperation",
        _ => $"unknown({reason})"
    };

    private static string IntermediateReason(long reason) => reason switch
    {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "superseded",
        3 => "privilegeWithdrawn",
        4 => "cessationOfOperation",
        _ => $"unknown({reason})"
    };
}
