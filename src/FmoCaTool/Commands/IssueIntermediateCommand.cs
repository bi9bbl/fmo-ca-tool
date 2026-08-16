using FmoCaTool.Certs;
using FmoCaTool.Cli;
using FmoCaTool.Crypto;
using FmoCaTool.IO;

namespace FmoCaTool.Commands;

internal static class IssueIntermediateCommand
{
    private static readonly HashSet<string> ValueOptions =
    [
        "--root-cert", "--root-key", "--name", "--email", "--sn", "--key-id",
        "--uid-start", "--uid-end", "--countries", "--crl", "--license",
        "--valid-days", "--iat", "--exp", "--out"
    ];

    private static readonly HashSet<string> FlagOptions = ["--random-sn", "--force"];

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteIssueIntermediate(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions);
        options.RequireNoPositionals();
        var root = CertificateJson.Load<RootCaCert>(options.RequireNonEmpty("--root-cert"));
        var rootKey = KeyFile.Load(options.RequireNonEmpty("--root-key"));
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (!root.VerifySelfSignature())
        {
            throw new CliException("Root certificate self-signature is invalid.");
        }

        CertificateValidation.RequireKeyMatches(root.SubjectPublicKey, rootKey, "Root");
        if (root.IsExpired(now))
        {
            throw new CliException($"Root certificate expired at Unix timestamp {root.Exp}.");
        }

        var serial = OptionValues.GetSerialNumber(options);
        if (serial == root.Sn)
        {
            throw new CliException("Intermediate SN must differ from Root SN.");
        }

        var uidStart = options.RequireInt64("--uid-start", 0);
        var uidEnd = options.RequireInt64("--uid-end", 0);
        if (uidStart > uidEnd)
        {
            throw new CliException("--uid-start must be less than or equal to --uid-end.");
        }

        var countries = CertificateValidation.NormalizeCountries(options.RequireNonEmpty("--countries"));
        var (iat, exp) = OptionValues.GetValidity(options);
        if (exp > root.Exp)
        {
            throw new CliException($"Intermediate expiration {exp} exceeds Root expiration {root.Exp}.");
        }

        var key = KeyFile.Generate();
        var certificate = new IntermediateCaCert
        {
            Sn = serial,
            IssuerSn = root.Sn,
            IssuerName = root.SubjectName,
            IssuerPublicKey = root.SubjectPublicKey,
            SubjectName = options.RequireNonEmpty("--name"),
            SubjectEmail = options.RequireNonEmpty("--email"),
            SubjectPublicKey = key.PublicKey,
            KeyId = options.RequireNonEmpty("--key-id"),
            Crl = options.Require("--crl"),
            License = options.Require("--license"),
            UidRangeStart = uidStart,
            UidRangeEnd = uidEnd,
            IssuingCountries = countries,
            Iat = iat,
            Exp = exp,
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        certificate.Signature = Ed25519Helper.Sign(rootKey.Seed, certificate.ToTbsCbor());
        CertificateValidation.ValidateIntermediate(certificate);

        var certificateJson = CertificateJson.Serialize(certificate);
        var reparsed = CertificateJson.Parse(certificateJson) as IntermediateCaCert
            ?? throw new CliException("Internal Intermediate certificate roundtrip failed.");
        if (!reparsed.VerifyBy(root))
        {
            throw new CliException("Generated Intermediate certificate failed Root signature verification.");
        }

        var outputDirectory = options.RequireNonEmpty("--out");
        var keyPath = Path.Combine(outputDirectory, "intermediate.key.json");
        var certificatePath = Path.Combine(outputDirectory, "intermediate.cert.json");
        var force = options.HasFlag("--force");
        if (force)
        {
            error.WriteLine("WARNING: --force permits replacement of existing Intermediate key and certificate files.");
        }

        SafeFileWriter.WriteAtomically(
        [
            new FileContent(keyPath, key.ToJson(), Secret: true),
            new FileContent(certificatePath, certificateJson, Secret: false)
        ], force);

        output.WriteLine("Intermediate CA issued and Root signature verified.");
        output.WriteLine($"Serial number : {certificate.Sn}");
        output.WriteLine($"Private key   : {Path.GetFullPath(keyPath)}");
        output.WriteLine($"Certificate   : {Path.GetFullPath(certificatePath)}");
        return 0;
    }
}
