using FmoCaTool.Certs;
using FmoCaTool.Cli;
using FmoCaTool.Crypto;
using FmoCaTool.IO;

namespace FmoCaTool.Commands;

internal static class GenerateKeyCommand
{
    private static readonly HashSet<string> ValueOptions = ["--name", "--out"];
    private static readonly HashSet<string> FlagOptions = ["--force"];

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteGenerateKey(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions);
        options.RequireNoPositionals();
        var name = options.Optional("--name") ?? "ed25519";
        if (string.IsNullOrWhiteSpace(name) || !string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal) ||
            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new CliException("--name must be a valid file-name stem without directory components.");
        }

        var outputDirectory = options.RequireNonEmpty("--out");
        var keyPath = Path.Combine(outputDirectory, $"{name}.key.json");
        var publicKeyPath = Path.Combine(outputDirectory, $"{name}.public.key");
        var key = KeyFile.Generate();
        var force = options.HasFlag("--force");
        if (force)
        {
            error.WriteLine("WARNING: --force permits replacement of existing key files.");
        }

        SafeFileWriter.WriteAtomically(
        [
            new FileContent(keyPath, key.ToJson(), Secret: true),
            new FileContent(publicKeyPath, Base64Url.Encode(key.PublicKey) + "\n", Secret: false)
        ], force);

        output.WriteLine("Ed25519 key pair generated.");
        output.WriteLine($"Private key : {Path.GetFullPath(keyPath)}");
        output.WriteLine($"Public key  : {Path.GetFullPath(publicKeyPath)}");
        output.WriteLine($"Base64URL   : {Base64Url.Encode(key.PublicKey)}");
        return 0;
    }
}
