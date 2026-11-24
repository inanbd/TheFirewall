using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security;
using System.Text;
using System.Xml.Linq;

namespace TheFirewall.Core.Platform;

/// <summary>
/// A Task Scheduler task that starts the tray app whenever any user signs in. "Run with highest privileges"
/// means administrators get an elevated tray app without a UAC prompt, while standard users get a read-only one.
/// </summary>
[SupportedOSPlatform("windows")]
public static class TrayStartupTask
{
    public const string TaskName = @"TheFirewall\Tray";

    public static bool Register(string appPath, out string output)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Author>TheFirewall</Author>
                <Description>Shows the TheFirewall icon in the notification area when a user signs in.</Description>
              </RegistrationInfo>
              <Triggers>
                <LogonTrigger>
                  <Enabled>true</Enabled>
                  <Delay>PT3S</Delay>
                </LogonTrigger>
              </Triggers>
              <Principals>
                <Principal id="Users">
                  <GroupId>S-1-5-32-545</GroupId>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>true</AllowHardTerminate>
                <StartWhenAvailable>false</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <IdleSettings>
                  <StopOnIdleEnd>false</StopOnIdleEnd>
                  <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <RunOnlyIfIdle>false</RunOnlyIfIdle>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Users">
                <Exec>
                  <Command>{SecurityElement.Escape(appPath)}</Command>
                  <Arguments>--tray</Arguments>
                  <WorkingDirectory>{SecurityElement.Escape(Path.GetDirectoryName(appPath) ?? string.Empty)}</WorkingDirectory>
                </Exec>
              </Actions>
            </Task>
            """;

        var file = Path.Combine(Path.GetTempPath(), "thefirewall-tray-task-" + Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            File.WriteAllText(file, xml, Encoding.Unicode);
            return RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{file}\" /F", out output) == 0;
        }
        finally
        {
            try
            {
                File.Delete(file);
            }
            catch (IOException)
            {
            }
        }
    }

    public static bool Unregister(out string output) => RunSchtasks($"/Delete /TN \"{TaskName}\" /F", out output) == 0;

    /// <summary>Null when the task does not exist, otherwise whether it is enabled.</summary>
    public static bool? GetEnabled()
    {
        if (RunSchtasks($"/Query /TN \"{TaskName}\" /XML", out var output) != 0)
        {
            return null;
        }

        try
        {
            var doc = XDocument.Parse(output);
            var enabled = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Enabled" && e.Parent?.Name.LocalName == "Settings");
            return enabled is null || !string.Equals(enabled.Value.Trim(), "false", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return true;
        }
    }

    public static bool SetEnabled(bool enabled, out string output) =>
        RunSchtasks($"/Change /TN \"{TaskName}\" {(enabled ? "/ENABLE" : "/DISABLE")}", out output) == 0;

    private static int RunSchtasks(string arguments, out string output)
    {
        var path = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        using var process = Process.Start(new ProcessStartInfo(path, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        }) ?? throw new InvalidOperationException("schtasks.exe could not be started.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30_000))
        {
            process.Kill();
            output = "schtasks.exe timed out.";
            return -1;
        }

        output = (stdout.Result + stderr.Result).Trim();
        return process.ExitCode;
    }
}
