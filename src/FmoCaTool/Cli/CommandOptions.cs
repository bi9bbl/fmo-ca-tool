using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace FmoCaTool.Cli;

public sealed class CommandOptions
{
    private readonly Dictionary<string, string> _values;
    private readonly HashSet<string> _flags;

    private CommandOptions(Dictionary<string, string> values, HashSet<string> flags, List<string> positionals)
    {
        _values = values;
        _flags = flags;
        Positionals = positionals;
    }

    public IReadOnlyList<string> Positionals { get; }

    public static CommandOptions Parse(
        string[] args,
        IReadOnlySet<string> valueOptions,
        IReadOnlySet<string> flagOptions)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var flags = new HashSet<string>(StringComparer.Ordinal);
        var positionals = new List<string>();

        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                positionals.Add(argument);
                continue;
            }

            var equals = argument.IndexOf('=');
            var name = equals < 0 ? argument : argument[..equals];
            if (flagOptions.Contains(name))
            {
                if (equals >= 0)
                {
                    throw new CliException($"Flag {name} does not accept a value.");
                }

                if (!flags.Add(name))
                {
                    throw new CliException($"Option {name} was specified more than once.");
                }

                continue;
            }

            if (!valueOptions.Contains(name))
            {
                throw new CliException($"Unknown option: {name}");
            }

            if (values.ContainsKey(name))
            {
                throw new CliException($"Option {name} was specified more than once.");
            }

            string value;
            if (equals >= 0)
            {
                value = argument[(equals + 1)..];
            }
            else
            {
                if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new CliException($"Option {name} requires a value.");
                }

                value = args[index];
            }

            values.Add(name, value);
        }

        return new CommandOptions(values, flags, positionals);
    }

    public bool HasFlag(string name) => _flags.Contains(name);

    public bool HasValue(string name) => _values.ContainsKey(name);

    public string Require(string name)
    {
        if (!_values.TryGetValue(name, out var value))
        {
            throw new CliException($"Required option is missing: {name}");
        }

        return value;
    }

    public string RequireNonEmpty(string name)
    {
        var value = Require(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new CliException($"Option {name} must not be empty.");
        }

        return value;
    }

    public string? Optional(string name) => _values.GetValueOrDefault(name);

    public long RequireInt64(string name, long? minimum = null)
    {
        var raw = Require(name);
        if (!long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
        {
            throw new CliException($"Option {name} must be a signed 64-bit integer.");
        }

        if (minimum.HasValue && value < minimum.Value)
        {
            throw new CliException($"Option {name} must be at least {minimum.Value}.");
        }

        return value;
    }

    public long? OptionalInt64(string name)
    {
        if (!HasValue(name))
        {
            return null;
        }

        return RequireInt64(name);
    }

    public void RequireNoPositionals()
    {
        if (Positionals.Count != 0)
        {
            throw new CliException($"Unexpected positional argument: {Positionals[0]}");
        }
    }
}

public static class OptionValues
{
    public static (long Iat, long Exp) GetValidity(CommandOptions options)
    {
        var iat = options.OptionalInt64("--iat") ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var exp = options.OptionalInt64("--exp");
        var validDays = options.OptionalInt64("--valid-days");
        if (exp.HasValue == validDays.HasValue)
        {
            throw new CliException("Specify exactly one of --exp or --valid-days.");
        }

        if (validDays <= 0)
        {
            throw new CliException("--valid-days must be positive.");
        }

        if (!exp.HasValue)
        {
            try
            {
                exp = checked(iat + checked(validDays!.Value * 86_400L));
            }
            catch (OverflowException ex)
            {
                throw new CliException("The requested validity period is outside the Unix timestamp range.", ex);
            }
        }

        if (exp.Value <= iat)
        {
            throw new CliException("Certificate exp must be greater than iat.");
        }

        return (iat, exp.Value);
    }

    public static long GetSerialNumber(CommandOptions options)
    {
        var hasSerial = options.HasValue("--sn");
        var hasRandom = options.HasFlag("--random-sn");
        if (hasSerial == hasRandom)
        {
            throw new CliException("Specify exactly one of --sn or --random-sn.");
        }

        if (hasSerial)
        {
            return options.RequireInt64("--sn", 1);
        }

        Span<byte> bytes = stackalloc byte[sizeof(long)];
        long serial;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            serial = BinaryPrimitives.ReadInt64LittleEndian(bytes) & long.MaxValue;
        }
        while (serial == 0);

        return serial;
    }
}
