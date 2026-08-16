using System.Text;

namespace FmoCaTool.IO;

public sealed record FileContent(string Path, string Content, bool Secret);

public static class SafeFileWriter
{
    public static void WriteAtomically(IReadOnlyCollection<FileContent> files, bool force)
    {
        if (files.Count == 0)
        {
            throw new ArgumentException("At least one file is required.", nameof(files));
        }

        var entries = files.Select(file => new Entry(file, Path.GetFullPath(file.Path))).ToArray();
        if (entries.Select(entry => entry.FinalPath).Distinct(PathComparer).Count() != entries.Length)
        {
            throw new CliException("Output paths must be distinct.");
        }

        foreach (var entry in entries)
        {
            var directory = Path.GetDirectoryName(entry.FinalPath) ?? Directory.GetCurrentDirectory();
            Directory.CreateDirectory(directory);
            TryProtectDirectory(directory);
            if (File.Exists(entry.FinalPath) && !force)
            {
                throw new CliException($"Output file already exists: {entry.FinalPath}. Use --force to overwrite it.");
            }

            if (Directory.Exists(entry.FinalPath))
            {
                throw new CliException($"Output path is a directory: {entry.FinalPath}");
            }

            entry.TempPath = Path.Combine(directory, $".{Path.GetFileName(entry.FinalPath)}.{Guid.NewGuid():N}.tmp");
            entry.BackupPath = Path.Combine(directory, $".{Path.GetFileName(entry.FinalPath)}.{Guid.NewGuid():N}.bak");
        }

        var committed = false;
        try
        {
            foreach (var entry in entries)
            {
                WriteTemporary(entry.TempPath!, entry.Source.Content, entry.Source.Secret);
            }

            foreach (var entry in entries.Where(entry => File.Exists(entry.FinalPath)))
            {
                File.Move(entry.FinalPath, entry.BackupPath!);
                entry.HasBackup = true;
            }

            foreach (var entry in entries)
            {
                File.Move(entry.TempPath!, entry.FinalPath);
                entry.WasCommitted = true;
                if (entry.Source.Secret)
                {
                    TryProtectFile(entry.FinalPath);
                }
            }

            committed = true;
        }
        catch (Exception ex)
        {
            RollBack(entries);
            if (ex is CliException)
            {
                throw;
            }

            throw new CliException($"Could not write output files atomically: {ex.Message}", ex);
        }
        finally
        {
            foreach (var entry in entries)
            {
                TryDelete(entry.TempPath);
                if (committed && entry.HasBackup)
                {
                    TryDelete(entry.BackupPath);
                }
            }
        }
    }

    private static void WriteTemporary(string path, string content, bool secret)
    {
        var bytes = new UTF8Encoding(false).GetBytes(content.Replace("\r\n", "\n", StringComparison.Ordinal));
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        if (secret)
        {
            TryProtectFile(path);
        }
    }

    private static void RollBack(IEnumerable<Entry> entries)
    {
        foreach (var entry in entries.Reverse())
        {
            try
            {
                if (entry.WasCommitted && File.Exists(entry.FinalPath))
                {
                    File.Delete(entry.FinalPath);
                }

                if (entry.HasBackup && File.Exists(entry.BackupPath))
                {
                    File.Move(entry.BackupPath!, entry.FinalPath);
                    entry.HasBackup = false;
                }
            }
            catch
            {
                // Preserve the original write error. Any surviving .bak file is intentionally retained.
            }
        }
    }

    private static void TryProtectDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Best effort: filesystem permissions may be controlled externally.
        }
    }

    private static void TryProtectFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Best effort: filesystem permissions may be controlled externally.
        }
    }

    private static void TryDelete(string? path)
    {
        if (path is null)
        {
            return;
        }

        try
        {
            File.Delete(path);
        }
        catch
        {
            // Cleanup is best effort; a rollback backup is never deleted here.
        }
    }

    private static StringComparer PathComparer => OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;

    private sealed class Entry(FileContent source, string finalPath)
    {
        public FileContent Source { get; } = source;
        public string FinalPath { get; } = finalPath;
        public string? TempPath { get; set; }
        public string? BackupPath { get; set; }
        public bool HasBackup { get; set; }
        public bool WasCommitted { get; set; }
    }
}
