using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

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

/// <summary>Checks and controls the TheFirewall Windows service (control actions ask for elevation).</summary>
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

    /// <summary>
    /// Runs "TheFirewall.Service.exe &lt;verb&gt;" elevated (UAC prompt) and waits for it.
    /// Returns null on success or an error message.
    /// </summary>
    public static async Task<string?> RunElevatedAsync(string verb)
    {
        if (!File.Exists(ServiceExePath))
        {
            return $"TheFirewall.Service.exe was not found next to the app ({ServiceExePath}).";
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo(ServiceExePath, verb)
            {
                UseShellExecute = true,
                Verb = Elevation.IsElevated ? string.Empty : "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                return "The service tool could not be started.";
            }

            await process.WaitForExitAsync();
            return process.ExitCode == 0 ? null : $"The command '{verb}' failed (exit code {process.ExitCode}). See %ProgramData%\\TheFirewall\\logs for details.";
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return "The administrator prompt was cancelled.";
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }
}
