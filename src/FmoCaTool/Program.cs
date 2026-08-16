using FmoCaTool.Cli;

namespace FmoCaTool;

public static class Program
{
    public static int Main(string[] args) => CliApplication.Run(args, Console.Out, Console.Error);
}
