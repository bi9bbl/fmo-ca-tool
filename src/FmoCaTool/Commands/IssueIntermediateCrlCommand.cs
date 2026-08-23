using FmoCaTool.Certs;
using FmoCaTool.Cli;
using FmoCaTool.Crls;
using FmoCaTool.Crypto;
using FmoCaTool.IO;

namespace FmoCaTool.Commands;

internal static class IssueIntermediateCrlCommand
{
    private static readonly HashSet<string> ValueOptions =
    [
        "--intermediate-cert", "--intermediate-key", "--crl-number", "--this-update", "--next-update", "--valid-days",
        "--entries", "--revoke", "--revoked-at", "--reason", "--out"
    ];

    private static readonly HashSet<string> FlagOptions = ["--force"];
    private static readonly HashSet<string> RepeatableValueOptions = ["--revoke"];

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteIssueIntermediateCrl(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions, RepeatableValueOptions);
        options.RequireNoPositionals();
        var intermediate = CertificateJson.Load<IntermediateCaCert>(options.RequireNonEmpty("--intermediate-cert"));
        var intermediateKey = KeyFile.Load(options.RequireNonEmpty("--intermediate-key"));
        CertificateValidation.RequireKeyMatches(intermediate.SubjectPublicKey, intermediateKey, "Intermediate");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (intermediate.IsExpired(now))
        {
            throw new CliException($"Intermediate certificate expired at Unix timestamp {intermediate.Exp}.");
        }

        var crlNumber = options.RequireInt64("--crl-number", 1);
        var (thisUpdate, nextUpdate) = CrlCommandSupport.GetUpdateRange(options);
        if (thisUpdate < intermediate.Iat || thisUpdate >= intermediate.Exp || nextUpdate > intermediate.Exp)
        {
            throw new CliException("Intermediate CRL update window must be within the Intermediate certificate validity interval.");
        }

        var specs = CrlCommandSupport.GetEntries(options, thisUpdate, 4);
        var entries = new List<IntermediateCrlEntry>();
        foreach (var spec in specs)
        {
            var certificate = CertificateJson.Load<UserCert>(spec.CertificatePath);
            if (certificate.IssuerSn != intermediate.Sn || !certificate.VerifyBy(intermediate))
            {
                throw new CliException($"User certificate '{spec.CertificatePath}' is not validly issued by the Intermediate CA.");
            }

            if (!intermediate.CanIssueFor(certificate.Uid))
            {
                throw new CliException($"User certificate '{spec.CertificatePath}' has a UID outside the Intermediate range.");
            }

            entries.Add(new IntermediateCrlEntry
            {
                Uid = certificate.Uid,
                CertFingerprint = certificate.Fingerprint(),
                RevokedAt = spec.RevokedAt,
                Reason = spec.Reason
            });
        }

        var crl = new IntermediateCrl
        {
            IssuerSn = intermediate.Sn,
            CrlNumber = crlNumber,
            ThisUpdate = thisUpdate,
            NextUpdate = nextUpdate,
            Entries = CrlEntryComparer.Sort(entries),
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        crl.Signature = Ed25519Helper.Sign(intermediateKey.Seed, crl.ToTbsCbor());
        CrlValidation.Validate(crl);
        if (!crl.VerifyBy(intermediate.SubjectPublicKey))
        {
            throw new CliException("Generated Intermediate CRL failed signature verification.");
        }

        var outputPath = options.RequireNonEmpty("--out");
        var force = options.HasFlag("--force");
        if (force)
        {
            error.WriteLine("WARNING: --force permits replacement of an existing Intermediate CRL file.");
        }

        SafeFileWriter.WriteAtomically([new FileContent(outputPath, CrlJson.Serialize(crl), Secret: false)], force);
        output.WriteLine("Intermediate CRL issued and signature verified.");
        output.WriteLine($"CRL number : {crl.CrlNumber}");
        output.WriteLine($"Entries    : {crl.Entries.Length}");
        output.WriteLine($"CRL file   : {Path.GetFullPath(outputPath)}");
        return 0;
    }
}
