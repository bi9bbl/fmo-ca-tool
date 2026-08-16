using FmoCaTool.Certs;
using FmoCaTool.Cli;
using FmoCaTool.Crypto;
using FmoCaTool.IO;

namespace FmoCaTool.Commands;

internal static class InitRootCommand
{
    private static readonly HashSet<string> ValueOptions =
    [
        "--name", "--email", "--sn", "--key-id", "--crl", "--license",
        "--valid-days", "--iat", "--exp", "--out"
    ];

    private static readonly HashSet<string> FlagOptions = ["--random-sn", "--force"];

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteInitRoot(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions);
        options.RequireNoPositionals();
        var name = options.RequireNonEmpty("--name");
        var email = options.RequireNonEmpty("--email");
        var serial = OptionValues.GetSerialNumber(options);
        var keyId = options.RequireNonEmpty("--key-id");
        var crl = options.Require("--crl");
        var license = options.Require("--license");
        var (iat, exp) = OptionValues.GetValidity(options);
        var outputDirectory = options.RequireNonEmpty("--out");
        var force = options.HasFlag("--force");

        var key = KeyFile.Generate();
        var certificate = new RootCaCert
        {
            Sn = serial,
            IssuerName = name,
            IssuerEmail = email,
            SubjectName = name,
            SubjectPublicKey = key.PublicKey,
            Crl = crl,
            License = license,
            KeyId = keyId,
            Iat = iat,
            Exp = exp,
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        certificate.Signature = Ed25519Helper.Sign(key.Seed, certificate.ToTbsCbor());
        CertificateValidation.ValidateRoot(certificate);

        var certificateJson = CertificateJson.Serialize(certificate);
        var reparsed = CertificateJson.Parse(certificateJson) as RootCaCert
            ?? throw new CliException("Internal Root certificate roundtrip failed.");
        if (!reparsed.VerifySelfSignature())
        {
            throw new CliException("Generated Root certificate failed self-signature verification.");
        }

        var keyPath = Path.Combine(outputDirectory, "root.key.json");
        var certificatePath = Path.Combine(outputDirectory, "root.cert.json");
        if (force)
        {
            error.WriteLine("WARNING: --force permits replacement of existing Root key and certificate files.");
        }

        SafeFileWriter.WriteAtomically(
        [
            new FileContent(keyPath, key.ToJson(), Secret: true),
            new FileContent(certificatePath, certificateJson, Secret: false)
        ], force);

        output.WriteLine("Root CA created and self-signature verified.");
        output.WriteLine($"Serial number : {certificate.Sn}");
        output.WriteLine($"Private key   : {Path.GetFullPath(keyPath)}");
        output.WriteLine($"Certificate   : {Path.GetFullPath(certificatePath)}");
        return 0;
    }
}
