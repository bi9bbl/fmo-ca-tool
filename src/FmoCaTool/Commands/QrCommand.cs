using System.Globalization;
using System.Text;
using FmoCaTool.Cli;
using FmoCaTool.IO;
using QRCoder;

namespace FmoCaTool.Commands;

internal static class QrCommand
{
    private static readonly HashSet<string> ValueOptions = ["--text", "--file", "--ecc", "--pixels", "--out"];
    private static readonly HashSet<string> FlagOptions = ["--force"];

    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Contains("--help", StringComparer.Ordinal) || args.Contains("-h", StringComparer.Ordinal))
        {
            HelpText.WriteQr(output);
            return 0;
        }

        var options = CommandOptions.Parse(args, ValueOptions, FlagOptions);
        options.RequireNoPositionals();
        if (options.HasValue("--text") == options.HasValue("--file"))
        {
            throw new CliException("Specify exactly one of --text or --file.");
        }

        var (content, sourceDescription) = options.HasValue("--text")
            ? (options.Require("--text"), "text")
            : ReadFileContent(options.RequireNonEmpty("--file"));
        if (content.Length == 0)
        {
            throw new CliException("QR content must not be empty.");
        }

        var ecc = ParseEcc(options.Optional("--ecc") ?? "Q");
        var pixels = ParsePixels(options.Optional("--pixels") ?? "10");
        byte[] png;
        try
        {
            using var generator = new QRCodeGenerator();
            using var data = generator.CreateQrCode(content, ecc);
            using var qr = new PngByteQRCode(data);
            png = qr.GetGraphic(pixels);
        }
        catch (Exception ex) when (ex is not CliException)
        {
            throw new CliException($"Could not encode QR content: {ex.Message}", ex);
        }

        var outputPath = options.RequireNonEmpty("--out");
        if (!string.Equals(Path.GetExtension(outputPath), ".png", StringComparison.OrdinalIgnoreCase))
        {
            throw new CliException("--out must name a .png file.");
        }

        var force = options.HasFlag("--force");
        if (force)
        {
            error.WriteLine("WARNING: --force permits replacement of an existing QR PNG file.");
        }

        SafeFileWriter.WriteBytesAtomically(outputPath, png, force);
        output.WriteLine("QR code generated.");
        output.WriteLine($"Source : {sourceDescription}");
        output.WriteLine($"PNG    : {Path.GetFullPath(outputPath)}");
        return 0;
    }

    private static (string Content, string Description) ReadFileContent(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            try
            {
                var strictUtf8 = new UTF8Encoding(false, true);
                return (strictUtf8.GetString(bytes), $"UTF-8 file {Path.GetFullPath(path)}");
            }
            catch (DecoderFallbackException)
            {
                return (Convert.ToBase64String(bytes), $"base64-encoded binary file {Path.GetFullPath(path)}");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new CliException($"Cannot read QR source file '{path}': {ex.Message}", ex);
        }
    }

    private static QRCodeGenerator.ECCLevel ParseEcc(string value) => value.ToUpperInvariant() switch
    {
        "L" => QRCodeGenerator.ECCLevel.L,
        "M" => QRCodeGenerator.ECCLevel.M,
        "Q" => QRCodeGenerator.ECCLevel.Q,
        "H" => QRCodeGenerator.ECCLevel.H,
        _ => throw new CliException("--ecc must be L, M, Q, or H.")
    };

    private static int ParsePixels(string value)
    {
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pixels) || pixels is < 1 or > 100)
        {
            throw new CliException("--pixels must be an integer between 1 and 100.");
        }

        return pixels;
    }
}
