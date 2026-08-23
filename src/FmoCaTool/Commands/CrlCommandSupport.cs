using System.Globalization;
using System.Text;
using System.Text.Json;
using FmoCaTool.Cli;

namespace FmoCaTool.Commands;

internal sealed record CrlEntrySpec(string CertificatePath, long RevokedAt, long Reason);

internal static class CrlCommandSupport
{
    public static (long ThisUpdate, long NextUpdate) GetUpdateRange(CommandOptions options)
    {
        var thisUpdate = options.OptionalInt64("--this-update") ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var nextUpdate = options.OptionalInt64("--next-update");
        var validDays = options.OptionalInt64("--valid-days");
        if (nextUpdate.HasValue == validDays.HasValue)
        {
            throw new CliException("Specify exactly one of --next-update or --valid-days.");
        }

        if (thisUpdate < 0)
        {
            throw new CliException("--this-update must be non-negative.");
        }

        if (validDays <= 0)
        {
            throw new CliException("--valid-days must be positive.");
        }

        if (!nextUpdate.HasValue)
        {
            try
            {
                nextUpdate = checked(thisUpdate + checked(validDays!.Value * 86_400L));
            }
            catch (OverflowException ex)
            {
                throw new CliException("The requested CRL validity period is outside the Unix timestamp range.", ex);
            }
        }

        if (nextUpdate.Value < thisUpdate)
        {
            throw new CliException("CRL nextUpdate must not be earlier than thisUpdate.");
        }

        return (thisUpdate, nextUpdate.Value);
    }

    public static IReadOnlyList<CrlEntrySpec> GetEntries(CommandOptions options, long thisUpdate, long maxReason)
    {
        var manifestPath = options.Optional("--entries");
        var certificatePaths = options.Values("--revoke");
        if (manifestPath is not null && certificatePaths.Count > 0)
        {
            throw new CliException("Specify --entries or one or more --revoke options, not both.");
        }

        if (manifestPath is not null)
        {
            return LoadManifest(manifestPath, maxReason);
        }

        if (certificatePaths.Count == 0)
        {
            if (options.HasValue("--reason") || options.HasValue("--revoked-at"))
            {
                throw new CliException("--reason and --revoked-at require at least one --revoke certificate.");
            }

            return [];
        }

        var reason = options.RequireInt64("--reason", 0);
        if (reason > maxReason)
        {
            throw new CliException($"--reason must be between 0 and {maxReason}.");
        }

        var revokedAt = options.OptionalInt64("--revoked-at") ?? thisUpdate;
        if (revokedAt < 0)
        {
            throw new CliException("--revoked-at must be non-negative.");
        }

        return certificatePaths.Select(path => new CrlEntrySpec(path, revokedAt, reason)).ToArray();
    }

    private static IReadOnlyList<CrlEntrySpec> LoadManifest(string path, long maxReason)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            var baseDirectory = Path.GetDirectoryName(fullPath) ?? Directory.GetCurrentDirectory();
            using var document = JsonDocument.Parse(File.ReadAllText(fullPath, Encoding.UTF8));
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                throw new CliException("CRL entries manifest must be a JSON array.");
            }

            var entries = new List<CrlEntrySpec>();
            var index = 0;
            foreach (var element in document.RootElement.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object)
                {
                    throw new CliException($"CRL entries manifest item {index} must be an object.");
                }

                var certificate = RequiredString(element, "certificate", index);
                var revokedAt = RequiredInt64(element, "revokedAt", index);
                var reason = RequiredInt64(element, "reason", index);
                if (revokedAt < 0)
                {
                    throw new CliException($"CRL entries manifest item {index} revokedAt must be non-negative.");
                }

                if (reason < 0 || reason > maxReason)
                {
                    throw new CliException($"CRL entries manifest item {index} reason must be between 0 and {maxReason}.");
                }

                entries.Add(new CrlEntrySpec(
                    Path.IsPathFullyQualified(certificate) ? certificate : Path.Combine(baseDirectory, certificate),
                    revokedAt,
                    reason));
                index++;
            }

            return entries;
        }
        catch (CliException)
        {
            throw;
        }
        catch (FileNotFoundException ex)
        {
            throw new CliException($"CRL entries manifest not found: {path}", ex);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            throw new CliException($"Invalid CRL entries manifest '{path}': {ex.Message}", ex);
        }
    }

    private static string RequiredString(JsonElement element, string name, int index)
    {
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw new CliException($"CRL entries manifest item {index} {name} must be a non-empty string.");
        }

        return property.GetString()!;
    }

    private static long RequiredInt64(JsonElement element, string name, int index)
    {
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.Number ||
            !property.TryGetInt64(out var value))
        {
            throw new CliException($"CRL entries manifest item {index} {name} must be a signed 64-bit integer.");
        }

        return value;
    }
}
