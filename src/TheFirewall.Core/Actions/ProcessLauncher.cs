using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace TheFirewall.Core.Actions;

/// <summary>
/// Runs a user-configured program when something happens (ban, unban, successful login).
/// Command format: <c>"C:\scripts\notify.exe" --ip {ip} --user {user}</c> or IPBan style <c>C:\scripts\notify.exe|{ip}</c>.
/// Placeholders: {ip}, {user}, {source}, {country}, {count}, {reason}, {duration}, {log}. IPBan's ###IPADDRESS### style is also accepted.
/// One command per line.
/// </summary>
public sealed class ProcessLauncher(ILogger logger)
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(2);

    public void Run(string commands, IReadOnlyDictionary<string, string?> values)
    {
        if (string.IsNullOrWhiteSpace(commands))
        {
            return;
        }

        foreach (var line in commands.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TryParse(line, out var file, out var arguments))
            {
                logger.LogWarning("Invalid command line: {Command}", line);
                continue;
            }

            var args = ReplacePlaceholders(arguments, values);
            _ = Task.Run(() => Execute(file, args));
        }
    }

    internal static bool TryParse(string line, out string file, out string arguments)
    {
        file = string.Empty;
        arguments = string.Empty;
        line = line.Trim();
        if (line.Length == 0)
        {
            return false;
        }

        int pipe = line.IndexOf('|');
        if (pipe > 0 && !line.StartsWith('"'))
        {
            file = line[..pipe].Trim();
            arguments = line[(pipe + 1)..].Trim();
            return file.Length > 0;
        }

        if (line.StartsWith('"'))
        {
            int close = line.IndexOf('"', 1);
            if (close < 0)
            {
                return false;
            }

            file = line[1..close];
            arguments = line[(close + 1)..].TrimStart('|').Trim();
            return file.Length > 0;
        }

        int space = line.IndexOf(' ');
        file = space < 0 ? line : line[..space];
        arguments = space < 0 ? string.Empty : line[(space + 1)..].Trim();
        return true;
    }

    internal static string ReplacePlaceholders(string template, IReadOnlyDictionary<string, string?> values)
    {
        var result = template;
        foreach (var (key, value) in values)
        {
            // Quotes would let a hostile user name break out of an argument, so they are removed.
            var safe = (value ?? string.Empty).Replace("\"", string.Empty, StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal)
                .Replace("\n", " ", StringComparison.Ordinal);
            result = result.Replace("{" + key + "}", safe, StringComparison.OrdinalIgnoreCase);
            var legacy = key.ToLowerInvariant() switch
            {
                "ip" => "###IPADDRESS###",
                "user" => "###USERNAME###",
                "source" => "###SOURCE###",
                "count" => "###COUNT###",
                "log" => "###LOG###",
                _ => null,
            };
            if (legacy is not null)
            {
                result = result.Replace(legacy, safe, StringComparison.OrdinalIgnoreCase);
            }
        }

        return result;
    }

    private void Execute(string file, string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(file, arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(file) is { Length: > 0 } dir && Directory.Exists(dir) ? dir : AppContext.BaseDirectory,
            });
            if (process is not null && !process.WaitForExit(Timeout))
            {
                process.Kill(entireProcessTree: true);
                logger.LogWarning("Command {File} did not finish within {Timeout} and was stopped", file, Timeout);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to run {File}", file);
        }
    }
}
