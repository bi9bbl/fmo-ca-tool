using FmoCaTool.Commands;

namespace FmoCaTool.Cli;

public static class CliApplication
{
    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        try
        {
            if (args.Length == 0 || args[0] is "--help" or "-h")
            {
                HelpText.WriteGeneral(output);
                return 0;
            }

            if (args[0] == "--version")
            {
                output.WriteLine(typeof(CliApplication).Assembly.GetName().Version?.ToString(3) ?? "1.0.0");
                return 0;
            }

            var command = args[0];
            var commandArgs = args[1..];
            return command switch
            {
                "init-root" => InitRootCommand.Run(commandArgs, output, error),
                "issue-intermediate" => IssueIntermediateCommand.Run(commandArgs, output, error),
                "issue-user" => IssueUserCommand.Run(commandArgs, output, error),
                "fingerprint" => FingerprintCommand.Run(commandArgs, output),
                _ => throw new CliException($"Unknown command '{command}'. Run fmo-ca-tool --help for usage.")
            };
        }
        catch (CliException ex)
        {
            error.WriteLine($"Error: {ex.Message}");
            return 2;
        }
        catch (Exception ex)
        {
            error.WriteLine($"Error: operation failed: {ex.Message}");
            return 1;
        }
    }
}
