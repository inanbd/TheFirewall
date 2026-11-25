using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using Microsoft.Win32;

namespace TheFirewall.App.Services;

public enum ServiceInstallState
{
    Unknown,
    NotInstalled,
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// <summary>Outcome of running a TheFirewall.Service.exe command.</summary>
public sealed record ServiceCommandResult(bool Succeeded, bool Cancelled, string? Error)
{
    public static ServiceCommandResult Ok { get; } = new(true, false, null);

    public static ServiceCommandResult Fail(string error) => new(false, false, error);
}

/// <summary>Checks and controls the TheFirewall Windows service (installing or stopping asks for elevation).</summary>
public static class WindowsServiceControl
{
    public const string ServiceName = "TheFirewall";

    public static string ServiceExePath => Path.Combine(AppContext.BaseDirectory, "TheFirewall.Service.exe");

    public static ServiceInstallState GetState()
    {
        try
        {
            using var controller = ServiceController.GetServices().FirstOrDefault(s => string.Equals(s.ServiceName, ServiceName, StringComparison.OrdinalIgnoreCase));
            if (controller is null)
            {
                return ServiceInstallState.NotInstalled;
            }

            return controller.Status switch
            {
                ServiceControllerStatus.Running => ServiceInstallState.Running,
                ServiceControllerStatus.StartPending or ServiceControllerStatus.ContinuePending => ServiceInstallState.Starting,
                ServiceControllerStatus.StopPending or ServiceControllerStatus.PausePending => ServiceInstallState.Stopping,
                _ => ServiceInstallState.Stopped,
            };
        }
        catch (Exception)
        {
            return ServiceInstallState.Unknown;
        }
    }

    /// <summary>Path of the executable the installed service runs, or null when it is not installed.</summary>
    public static string? GetInstalledServicePath()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
            var imagePath = key?.GetValue("ImagePath") as string;
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                return null;
            }

            imagePath = Environment.ExpandEnvironmentVariables(imagePath.Trim());
            if (imagePath.StartsWith('"'))
            {
                int end = imagePath.IndexOf('"', 1);
                return end > 1 ? imagePath[1..end] : null;
            }

            int exeEnd = imagePath.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return exeEnd > 0 ? imagePath[..(exeEnd + 4)] : imagePath;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Starts the installed service without elevation. Works when the app is elevated or when the service grants
    /// signed-in users the start permission (TheFirewall.Service.exe install/configure does). Returns false when
    /// access was denied.
    /// </summary>
    public static async Task<bool> TryStartWithoutElevationAsync(TimeSpan timeout)
    {
        try
        {
            using var controller = new ServiceController(ServiceName);
            if (controller.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
            {
                return true;
            }

            if (controller.Status == ServiceControllerStatus.StopPending)
            {
                await Task.Run(() => controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)));
            }

            controller.Start();
            await Task.Run(() => controller.WaitForStatus(ServiceControllerStatus.Running, timeout));
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Runs "TheFirewall.Service.exe &lt;verb&gt;" as administrator (with a UAC prompt unless the app is elevated already)
    /// and waits for it.
    /// </summary>
    public static async Task<ServiceCommandResult> RunVerbAsync(string verb)
    {
        if (!File.Exists(ServiceExePath))
        {
            return ServiceCommandResult.Fail($"TheFirewall.Service.exe was not found next to the app ({ServiceExePath}).");
        }

        try
        {
            return Elevation.IsElevated ? await RunDirectAsync(verb) : await RunWithPromptAsync(verb);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return new ServiceCommandResult(false, true, "The administrator prompt was cancelled.");
        }
        catch (Exception ex)
        {
            return ServiceCommandResult.Fail($"TheFirewall.Service.exe could not be run: {ex.Message}");
        }
    }

    /// <summary>
    /// The app is elevated already: start the tool directly, not through the Windows shell. The shell checks files
    /// extracted from a downloaded zip ("this file came from another computer") and, because the tool runs without a
    /// window, cannot show that prompt; it then refuses to run the tool and the install silently did nothing.
    /// Running it directly also lets us show the tool's own error message.
    /// </summary>
    private static async Task<ServiceCommandResult> RunDirectAsync(string verb)
    {
        var info = new ProcessStartInfo(ServiceExePath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = AppContext.BaseDirectory,
        };
        info.ArgumentList.Add(verb);

        using var process = Process.Start(info) ?? throw new InvalidOperationException("The process did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            return ServiceCommandResult.Fail($"The command '{verb}' did not finish within 3 minutes.");
        }

        var text = ((await errors).Trim() + Environment.NewLine + (await output).Trim()).Trim();
        AppLog.Write($"TheFirewall.Service.exe {verb} exited with code {process.ExitCode}.{(text.Length > 0 ? Environment.NewLine + text : string.Empty)}");
        if (process.ExitCode == 0)
        {
            return ServiceCommandResult.Ok;
        }

        var detail = (await errors).Trim();
        if (detail.Length == 0)
        {
            detail = LastLines((await output).Trim(), 6);
        }

        return ServiceCommandResult.Fail($"The command '{verb}' failed (exit code {process.ExitCode})." +
                                         (detail.Length > 0 ? Environment.NewLine + Environment.NewLine + detail : " See %ProgramData%\\TheFirewall\\logs for details."));
    }

    /// <summary>The app is not elevated: ask for administrator permission (UAC) through the shell.</summary>
    private static async Task<ServiceCommandResult> RunWithPromptAsync(string verb)
    {
        using var process = Process.Start(new ProcessStartInfo(ServiceExePath, verb)
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = AppContext.BaseDirectory,
        });
        if (process is null)
        {
            return ServiceCommandResult.Fail("The service tool could not be started.");
        }

        await process.WaitForExitAsync();
        return process.ExitCode == 0
            ? ServiceCommandResult.Ok
            : ServiceCommandResult.Fail($"The command '{verb}' failed (exit code {process.ExitCode}). See %ProgramData%\\TheFirewall\\logs for details.");
    }

    private static string LastLines(string text, int count)
    {
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(Environment.NewLine, lines.Skip(Math.Max(0, lines.Length - count)));
    }

    private static void TryKill(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception)
        {
            // Already gone.
        }
    }

    /// <summary>Same as <see cref="RunVerbAsync"/> but returns only an error message (null on success).</summary>
    public static async Task<string?> RunElevatedAsync(string verb) => (await RunVerbAsync(verb)).Error;
}
