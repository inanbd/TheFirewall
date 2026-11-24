using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Extensions.Logging.Abstractions;
using TheFirewall.Core;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Platform;
using TheFirewall.Service.Windows;

namespace TheFirewall.Service;

/// <summary>Command line verbs used by the installer and the app's "install service" fallback.</summary>
[SupportedOSPlatform("windows")]
internal static class ServiceCli
{
    public static readonly string[] Verbs = ["install", "uninstall", "start", "stop", "status", "configure", "remove-rules", "register-tray", "unregister-tray", "cleanup", "help", "--help", "-h", "/?"];

    /// <summary>
    /// Service permissions: the Windows defaults plus "start" for interactive users, so the app can start a stopped
    /// service without a UAC prompt. Stopping or changing the service still requires an administrator.
    /// </summary>
    private const string ServiceSddl =
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    public static int Run(string[] args)
    {
        var verb = args[0].ToLowerInvariant();
        if (verb is "help" or "--help" or "-h" or "/?")
        {
            PrintHelp();
            return 0;
        }

        if (verb != "status" && !IsElevated())
        {
            Console.Error.WriteLine("This command must be run as administrator.");
            return 5;
        }

        try
        {
            return verb switch
            {
                "install" => Install(),
                "uninstall" => Uninstall(keepRules: args.Contains("--keep-rules", StringComparer.OrdinalIgnoreCase)),
                "start" => Start(),
                "configure" => Configure(),
                "stop" => Stop(),
                "status" => Status(),
                "remove-rules" => RemoveRules(),
                "register-tray" => RegisterTray(args.Length > 1 ? args[1] : Path.Combine(AppContext.BaseDirectory, "TheFirewall.exe")),
                "unregister-tray" => UnregisterTray(),
                "cleanup" => Cleanup(),
                _ => 1,
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine($"""
            TheFirewall service {ServiceConstants.Version}

            Usage: TheFirewall.Service.exe [command]

              (no command)       Run as a Windows service, or in the console when started interactively.
              install            Install (or repair) and start the Windows service.
              configure          Re-apply automatic start, restart-on-failure and start permissions.
              uninstall          Stop and remove the service and delete TheFirewall's firewall rules.
                                 Add --keep-rules to leave the firewall rules in place.
              start | stop       Start or stop the service.
              status             Show whether the service is installed and running.
              remove-rules       Delete every firewall rule created by TheFirewall.
              register-tray      Start the tray app for every user at sign-in (Task Scheduler).
              unregister-tray    Remove the sign-in task.
              cleanup            remove-rules + unregister-tray (used by the uninstaller).
            """);
    }

    private static int Install()
    {
        var exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "TheFirewall.Service.exe");
        if (!ServiceExists())
        {
            Sc($"create {ServiceConstants.ServiceName} binPath= \"\\\"{exe}\\\"\" start= auto DisplayName= \"{ServiceConstants.DisplayName}\"");
            Console.WriteLine("Service installed.");
        }
        else
        {
            // A portable copy may have been moved or deleted: point the service at this copy if its exe is gone.
            var current = GetInstalledServicePath();
            if (current is null || !File.Exists(current))
            {
                Sc($"config {ServiceConstants.ServiceName} binPath= \"\\\"{exe}\\\"\"");
                Console.WriteLine($"The service now runs {exe}.");
            }
            else
            {
                Console.WriteLine($"The service is already installed ({current}).");
            }
        }

        Configure();
        return Start();
    }

    /// <summary>Automatic start, restart on failure, description and start permission for signed-in users.</summary>
    private static int Configure()
    {
        Sc($"config {ServiceConstants.ServiceName} start= auto");
        Sc($"description {ServiceConstants.ServiceName} \"{ServiceConstants.Description}\"");
        Sc($"failure {ServiceConstants.ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/60000");
        TrySc($"failureflag {ServiceConstants.ServiceName} 1");
        TrySc($"sdset {ServiceConstants.ServiceName} {ServiceSddl}");
        Console.WriteLine("Service configured: starts automatically and restarts after failures.");
        return 0;
    }

    /// <summary>Path of the executable the installed service runs, or null.</summary>
    internal static string? GetInstalledServicePath()
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceConstants.ServiceName}");
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

    private static int Uninstall(bool keepRules)
    {
        if (ServiceExists())
        {
            Stop();
            Sc($"delete {ServiceConstants.ServiceName}");
            Console.WriteLine("Service removed.");
        }
        else
        {
            Console.WriteLine("The service is not installed.");
        }

        return keepRules ? 0 : RemoveRules();
    }

    private static int Start()
    {
        using var controller = new ServiceController(ServiceConstants.ServiceName);
        if (controller.Status != ServiceControllerStatus.Running)
        {
            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        }

        Console.WriteLine("Service running.");
        return 0;
    }

    private static int Stop()
    {
        using var controller = new ServiceController(ServiceConstants.ServiceName);
        if (controller.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
        {
            controller.Stop();
        }

        controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
        Console.WriteLine("Service stopped.");
        return 0;
    }

    private static int Status()
    {
        if (!ServiceExists())
        {
            Console.WriteLine("Not installed");
            return 2;
        }

        using var controller = new ServiceController(ServiceConstants.ServiceName);
        Console.WriteLine(controller.Status);
        return controller.Status == ServiceControllerStatus.Running ? 0 : 3;
    }

    private static int RemoveRules()
    {
        var settings = new SettingsStore(FirewallPaths.Default.SettingsFile, NullLogger.Instance);
        var prefix = File.Exists(settings.FilePath) ? FirewallPlanner.SanitizePrefix(settings.Load().General.FirewallRulePrefix) : "TheFirewall_";
        var backend = new WindowsFirewallBackend(NullLogger.Instance);
        int removed = 0;
        foreach (var name in backend.GetRuleNames(prefix))
        {
            backend.DeleteRule(name);
            removed++;
        }

        // Forget stored rule fingerprints so a reinstall writes everything again.
        try
        {
            using var db = new Core.Data.FirewallDatabase(FirewallPaths.Default.DatabaseFile);
            db.ReplaceRuleHashes(new Dictionary<string, string>());
        }
        catch (Exception)
        {
        }

        Console.WriteLine($"Removed {removed} firewall rule(s).");
        return 0;
    }

    private static int RegisterTray(string appPath)
    {
        if (!TrayStartupTask.Register(Path.GetFullPath(appPath), out var output))
        {
            Console.Error.WriteLine(output);
            return 1;
        }

        Console.WriteLine("Tray sign-in task registered.");
        return 0;
    }

    private static int UnregisterTray()
    {
        TrayStartupTask.Unregister(out var output);
        Console.WriteLine(output);
        return 0;
    }

    private static int Cleanup()
    {
        try
        {
            RemoveRules();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Removing firewall rules failed: " + ex.Message);
        }

        UnregisterTray();
        return 0;
    }

    private static bool ServiceExists() =>
        ServiceController.GetServices().Any(s => string.Equals(s.ServiceName, ServiceConstants.ServiceName, StringComparison.OrdinalIgnoreCase));

    private static void TrySc(string arguments)
    {
        try
        {
            Sc(arguments);
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine(ex.Message);
        }
    }

    private static void Sc(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"sc.exe {arguments.Split(' ')[0]} failed ({process.ExitCode}): {output.Trim()}");
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
