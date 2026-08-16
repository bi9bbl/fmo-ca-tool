using System.Globalization;
using FmoCaTool.Certs;
using FmoCaTool.Cli;

namespace FmoCaTool.Commands;

internal static class FingerprintCommand
{
    private static readonly HashSet<string> ValueOptions = ["--format"];
    private static readonly HashSet<string> FlagOptions = ["--quiet"];

    public static int Run(string[] args, TextWriter output)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteFingerprint(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions);
        if (options.Positionals.Count != 1)
        {
            throw new CliException("fingerprint requires exactly one certificate JSON path.");
        }

        var format = options.Optional("--format") ?? "base64url";
        if (format is not ("base64url" or "hex"))
        {
            throw new CliException("--format must be 'base64url' or 'hex'.");
        }

        var certificate = CertificateJson.Load(options.Positionals[0]);
        var fingerprint = certificate.Fingerprint();
        var base64Url = Base64Url.Encode(fingerprint);
        var hex = Convert.ToHexString(fingerprint).ToLower(CultureInfo.InvariantCulture);
        if (options.HasFlag("--quiet"))
        {
            output.WriteLine(format == "hex" ? hex : base64Url);
            return 0;
        }

        output.WriteLine($"Certificate type : {certificate.Type}");
        switch (certificate)
        {
            case RootCaCert root:
                output.WriteLine($"Serial number    : {root.Sn}");
                output.WriteLine($"Subject          : {root.SubjectName}");
                break;
            case IntermediateCaCert intermediate:
                output.WriteLine($"Serial number    : {intermediate.Sn}");
                output.WriteLine($"Subject          : {intermediate.SubjectName}");
                break;
            case UserCert user:
                output.WriteLine($"Callsign         : {user.Callsign}");
                output.WriteLine($"UID              : {user.Uid}");
                break;
        }

        output.WriteLine($"Fingerprint      : {(format == "hex" ? hex : base64Url)}");
        output.WriteLine($"Base64URL        : {base64Url}");
        output.WriteLine($"Hex              : {hex}");
        if (certificate is UserCert)
        {
            output.WriteLine($"SAS_CERT_FINGERPRINT={base64Url}");
        }

        return 0;
    }
}
