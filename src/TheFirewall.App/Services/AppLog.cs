using System.IO;

namespace TheFirewall.App.Services;

/// <summary>The app's own log, %LOCALAPPDATA%\TheFirewall\app.log (errors also go to app-errors.log).</summary>
public static class AppLog
{
    private static readonly Lock Sync = new();

    public static string Directory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TheFirewall");

    public static void Write(string message) => Append("app.log", message);

    public static void Error(Exception exception) => Append("app-errors.log", exception.ToString());

    private static void Append(string file, string message)
    {
        try
        {
            lock (Sync)
            {
                System.IO.Directory.CreateDirectory(Directory);
                var path = Path.Combine(Directory, file);
                if (new FileInfo(path) is { Exists: true, Length: > 2_000_000 })
                {
                    File.Delete(path);
                }

                File.AppendAllText(path, $"{DateTime.Now:O} {message}{Environment.NewLine}");
            }
        }
        catch (Exception)
        {
            // Logging must never break the app.
        }
    }
}
