using FmoCaTool.Certs;
using FmoCaTool.Cli;
using FmoCaTool.Crls;
using FmoCaTool.Crypto;
using FmoCaTool.IO;

namespace FmoCaTool.Commands;

internal static class IssueRootCrlCommand
{
    private static readonly HashSet<string> ValueOptions =
    [
        "--root-cert", "--root-key", "--crl-number", "--this-update", "--next-update", "--valid-days",
        "--entries", "--revoke", "--revoked-at", "--reason", "--out"
    ];

    private static readonly HashSet<string> FlagOptions = ["--force"];
    private static readonly HashSet<string> RepeatableValueOptions = ["--revoke"];

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteIssueRootCrl(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions, RepeatableValueOptions);
        options.RequireNoPositionals();
        var root = CertificateJson.Load<RootCaCert>(options.RequireNonEmpty("--root-cert"));
        var rootKey = KeyFile.Load(options.RequireNonEmpty("--root-key"));
        CertificateValidation.RequireKeyMatches(root.SubjectPublicKey, rootKey, "Root");
        if (!root.VerifySelfSignature())
        {
            throw new CliException("Root certificate self-signature is invalid.");
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (root.IsExpired(now))
        {
            throw new CliException($"Root certificate expired at Unix timestamp {root.Exp}.");
        }

        var crlNumber = options.RequireInt64("--crl-number", 1);
        var (thisUpdate, nextUpdate) = CrlCommandSupport.GetUpdateRange(options);
        if (thisUpdate < root.Iat || thisUpdate >= root.Exp || nextUpdate > root.Exp)
        {
            throw new CliException("Root CRL update window must be within the Root certificate validity interval.");
        }

        var specs = CrlCommandSupport.GetEntries(options, thisUpdate, 5);
        var entries = new List<RootCrlEntry>();
        foreach (var spec in specs)
        {
            var certificate = CertificateJson.Load<IntermediateCaCert>(spec.CertificatePath);
            if (!IsIssuedBy(certificate, root) || !certificate.VerifyBy(root))
            {
                throw new CliException($"Intermediate certificate '{spec.CertificatePath}' is not validly issued by the Root.");
            }

            entries.Add(new RootCrlEntry
            {
                Sn = certificate.Sn,
                CertFingerprint = certificate.Fingerprint(),
                RevokedAt = spec.RevokedAt,
                Reason = spec.Reason
            });
        }

        var crl = new RootCrl
        {
            IssuerSn = root.Sn,
            CrlNumber = crlNumber,
            ThisUpdate = thisUpdate,
            NextUpdate = nextUpdate,
            Entries = CrlEntryComparer.Sort(entries),
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        crl.Signature = Ed25519Helper.Sign(rootKey.Seed, crl.ToTbsCbor());
        CrlValidation.Validate(crl);
        if (!crl.VerifyBy(root.SubjectPublicKey))
        {
            throw new CliException("Generated Root CRL failed signature verification.");
        }

        var outputPath = options.RequireNonEmpty("--out");
        var force = options.HasFlag("--force");
        if (force)
        {
            error.WriteLine("WARNING: --force permits replacement of an existing Root CRL file.");
        }

        SafeFileWriter.WriteAtomically([new FileContent(outputPath, CrlJson.Serialize(crl), Secret: false)], force);
        output.WriteLine("Root CRL issued and signature verified.");
        output.WriteLine($"CRL number : {crl.CrlNumber}");
        output.WriteLine($"Entries    : {crl.Entries.Length}");
        output.WriteLine($"CRL file   : {Path.GetFullPath(outputPath)}");
        return 0;
    }

    private static bool IsIssuedBy(IntermediateCaCert intermediate, RootCaCert root) =>
        intermediate.IssuerSn == root.Sn
        && string.Equals(intermediate.IssuerName, root.SubjectName, StringComparison.Ordinal)
        && intermediate.IssuerPublicKey.AsSpan().SequenceEqual(root.SubjectPublicKey);
}
