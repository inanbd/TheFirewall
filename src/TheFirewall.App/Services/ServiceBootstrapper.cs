using System.IO;

namespace TheFirewall.App.Services;

public enum EnsureServiceOutcome
{
    AlreadyRunning,
    Started,
    Installed,
    Declined,
    MissingServiceExe,
    Failed,
}

public sealed record EnsureServiceResult(EnsureServiceOutcome Outcome, string? Message = null)
{
    public bool IsRunning => Outcome is EnsureServiceOutcome.AlreadyRunning or EnsureServiceOutcome.Started or EnsureServiceOutcome.Installed;
}

/// <summary>
/// Makes sure the TheFirewall service is installed and running whenever the app starts: starts a stopped service
/// (without a UAC prompt where the service allows it), installs it from the app folder when it is missing
/// (portable copies), and repairs a service that points to a deleted copy.
/// </summary>
public static class ServiceBootstrapper
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    /// <summary>True while an install or start is in progress.</summary>
    public static bool IsBusy { get; private set; }

    /// <summary>Raised (on the calling thread) when <see cref="IsBusy"/> changes.</summary>
    public static event Action? BusyChanged;

    public static async Task<EnsureServiceResult> EnsureRunningAsync()
    {
        await Gate.WaitAsync();
        try
        {
            var state = WindowsServiceControl.GetState();
            if (state is ServiceInstallState.Running or ServiceInstallState.Starting)
            {
                return new EnsureServiceResult(EnsureServiceOutcome.AlreadyRunning);
            }

            SetBusy(true);

            var installedPath = state == ServiceInstallState.NotInstalled ? null : WindowsServiceControl.GetInstalledServicePath();
            bool needsInstall = state == ServiceInstallState.NotInstalled || (installedPath is not null && !File.Exists(installedPath));

            if (!needsInstall)
            {
                // Installed and pointing at an existing exe: just start it, without UAC when permitted.
                if (await WindowsServiceControl.TryStartWithoutElevationAsync(TimeSpan.FromSeconds(30)))
                {
                    return new EnsureServiceResult(EnsureServiceOutcome.Started);
                }

                var start = await WindowsServiceControl.RunVerbAsync("start");
                return Translate(start, EnsureServiceOutcome.Started);
            }

            if (!File.Exists(WindowsServiceControl.ServiceExePath))
            {
                return Logged(new EnsureServiceResult(EnsureServiceOutcome.MissingServiceExe,
                    "TheFirewall.Service.exe is missing from the app folder, so the service cannot be installed. Re-extract the portable zip or run the installer."));
            }

            // "install" creates (or re-points) the service, applies its settings and starts it.
            var install = await WindowsServiceControl.RunVerbAsync("install");
            return Translate(install, EnsureServiceOutcome.Installed);
        }
        finally
        {
            SetBusy(false);
            Gate.Release();
        }
    }

    private static EnsureServiceResult Translate(ServiceCommandResult result, EnsureServiceOutcome success)
    {
        if (result.Succeeded && WindowsServiceControl.GetState() is ServiceInstallState.Running or ServiceInstallState.Starting)
        {
            return Logged(new EnsureServiceResult(success));
        }

        return Logged(result.Cancelled
            ? new EnsureServiceResult(EnsureServiceOutcome.Declined, result.Error)
            : new EnsureServiceResult(EnsureServiceOutcome.Failed, result.Error ?? "The service did not start. See %ProgramData%\\TheFirewall\\logs for details."));
    }

    private static EnsureServiceResult Logged(EnsureServiceResult result)
    {
        AppLog.Write($"Service check: {result.Outcome}{(result.Message is null ? string.Empty : " - " + result.Message)}");
        return result;
    }

    private static void SetBusy(bool busy)
    {
        if (IsBusy != busy)
        {
            IsBusy = busy;
            BusyChanged?.Invoke();
        }
    }
}
