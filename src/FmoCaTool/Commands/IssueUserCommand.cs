using System.Text;
using FmoCaTool.Certs;
using FmoCaTool.Cli;
using FmoCaTool.Crypto;
using FmoCaTool.IO;

namespace FmoCaTool.Commands;

internal static class IssueUserCommand
{
    private static readonly HashSet<string> ValueOptions =
    [
        "--intermediate-cert", "--intermediate-key", "--root-cert", "--callsign", "--uid",
        "--public-key", "--public-key-file", "--valid-days", "--iat", "--exp", "--out"
    ];

    private static readonly HashSet<string> FlagOptions = ["--generate-key", "--force"];

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteIssueUser(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions);
        options.RequireNoPositionals();
        var intermediate = CertificateJson.Load<IntermediateCaCert>(options.RequireNonEmpty("--intermediate-cert"));
        var intermediateKey = KeyFile.Load(options.RequireNonEmpty("--intermediate-key"));
        CertificateValidation.RequireKeyMatches(intermediate.SubjectPublicKey, intermediateKey, "Intermediate");

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (intermediate.IsExpired(now))
        {
            throw new CliException($"Intermediate certificate expired at Unix timestamp {intermediate.Exp}.");
        }

        var rootPath = options.Optional("--root-cert");
        if (rootPath is not null)
        {
            VerifyFullIssuer(intermediate, CertificateJson.Load<RootCaCert>(rootPath), now);
        }

        var callsign = CertificateValidation.NormalizeCallsign(options.RequireNonEmpty("--callsign"));
        var uid = options.RequireInt64("--uid", 0);
        if (!intermediate.CanIssueFor(uid))
        {
            throw new CliException($"UID {uid} is outside Intermediate range [{intermediate.UidRangeStart}, {intermediate.UidRangeEnd}].");
        }

        var (iat, exp) = OptionValues.GetValidity(options);
        if (exp > intermediate.Exp)
        {
            throw new CliException($"User expiration {exp} exceeds Intermediate expiration {intermediate.Exp}.");
        }

        var sourceCount = (options.HasValue("--public-key") ? 1 : 0)
            + (options.HasValue("--public-key-file") ? 1 : 0)
            + (options.HasFlag("--generate-key") ? 1 : 0);
        if (sourceCount != 1)
        {
            throw new CliException("Specify exactly one of --public-key, --public-key-file, or --generate-key.");
        }

        KeyFile? generatedKey = null;
        byte[] publicKey;
        if (options.HasFlag("--generate-key"))
        {
            generatedKey = KeyFile.Generate();
            publicKey = generatedKey.PublicKey;
        }
        else
        {
            var encoded = options.Optional("--public-key") ?? ReadPublicKeyFile(options.RequireNonEmpty("--public-key-file"));
            publicKey = Base64Url.Decode(encoded, "User public key");
            if (publicKey.Length != Ed25519Helper.PublicKeySize)
            {
                throw new CliException("User public key must decode to exactly 32 bytes.");
            }
        }

        var certificate = new UserCert
        {
            IssuerSn = intermediate.Sn,
            Callsign = callsign,
            Uid = uid,
            PublicKey = publicKey,
            Iat = iat,
            Exp = exp,
            Signature = new byte[Ed25519Helper.SignatureSize]
        };
        certificate.Signature = Ed25519Helper.Sign(intermediateKey.Seed, certificate.ToTbsCbor());
        CertificateValidation.ValidateUser(certificate);

        var certificateJson = CertificateJson.Serialize(certificate);
        var reparsed = CertificateJson.Parse(certificateJson) as UserCert
            ?? throw new CliException("Internal User certificate roundtrip failed.");
        if (!reparsed.VerifyBy(intermediate))
        {
            throw new CliException("Generated User certificate failed Intermediate signature verification.");
        }

        var outputValue = options.RequireNonEmpty("--out");
        var safeName = SafeFileName(callsign, uid);
        string certificatePath;
        string? keyPath = null;
        if (generatedKey is not null)
        {
            if (string.Equals(Path.GetExtension(outputValue), ".json", StringComparison.OrdinalIgnoreCase))
            {
                throw new CliException("With --generate-key, --out must be a directory, not a .json file.");
            }

            certificatePath = Path.Combine(outputValue, $"{safeName}.cert.json");
            keyPath = Path.Combine(outputValue, $"{safeName}.key.json");
        }
        else
        {
            certificatePath = string.Equals(Path.GetExtension(outputValue), ".json", StringComparison.OrdinalIgnoreCase)
                ? outputValue
                : Path.Combine(outputValue, $"{safeName}.cert.json");
        }

        var files = new List<FileContent>();
        if (generatedKey is not null)
        {
            files.Add(new FileContent(keyPath!, generatedKey.ToJson(), Secret: true));
        }

        files.Add(new FileContent(certificatePath, certificateJson, Secret: false));
        var force = options.HasFlag("--force");
        if (force)
        {
            error.WriteLine("WARNING: --force permits replacement of existing User certificate and generated key files.");
        }

        SafeFileWriter.WriteAtomically(files, force);

        output.WriteLine("User Certificate issued and Intermediate signature verified.");
        if (keyPath is not null)
        {
            output.WriteLine($"Private key   : {Path.GetFullPath(keyPath)}");
        }

        output.WriteLine($"Certificate   : {Path.GetFullPath(certificatePath)}");
        var fingerprint = Base64Url.Encode(certificate.Fingerprint());
        output.WriteLine("Certificate fingerprint:");
        output.WriteLine(fingerprint);
        output.WriteLine($"SAS_CERT_FINGERPRINT={fingerprint}");
        return 0;
    }

    private static void VerifyFullIssuer(IntermediateCaCert intermediate, RootCaCert root, long now)
    {
        if (!root.VerifySelfSignature())
        {
            throw new CliException("Root certificate self-signature is invalid.");
        }

        if (root.IsExpired(now))
        {
            throw new CliException($"Root certificate expired at Unix timestamp {root.Exp}.");
        }

        var issuerFieldsMatch = intermediate.IssuerSn == root.Sn
            && string.Equals(intermediate.IssuerName, root.SubjectName, StringComparison.Ordinal)
            && intermediate.IssuerPublicKey.AsSpan().SequenceEqual(root.SubjectPublicKey);
        if (!issuerFieldsMatch || !intermediate.VerifyBy(root))
        {
            throw new CliException("Intermediate certificate is not validly issued by the provided Root certificate.");
        }
    }

    private static string ReadPublicKeyFile(string path)
    {
        try
        {
            return File.ReadAllText(path, Encoding.UTF8).Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new CliException($"Cannot read User public key file '{path}': {ex.Message}", ex);
        }
    }

    private static string SafeFileName(string callsign, long uid)
    {
        var safeCallsign = new string(callsign.Select(character =>
            character is >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' ? character : '_').ToArray());
        return $"{safeCallsign}-{uid}";
    }
}
