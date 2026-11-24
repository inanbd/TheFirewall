using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace TheFirewall.Service.Windows;

/// <summary>Makes sure failed logons are written to the Security log (event 4625).</summary>
[SupportedOSPlatform("windows")]
internal static class AuditPolicy
{
    // Subcategory GUID of "Logon" (locale independent, unlike the display name).
    private const string LogonSubcategory = "{0CCE9215-69AE-11D9-BED3-505054503030}";

    /// <summary>Returns null on success, otherwise a message for the user.</summary>
    public static string? EnsureLogonFailureAuditing(ILogger logger)
    {
        try
        {
            var auditpol = Path.Combine(Environment.SystemDirectory, "auditpol.exe");
            using var process = Process.Start(new ProcessStartInfo(auditpol, $"/set /subcategory:{LogonSubcategory} /failure:enable")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (process is null)
            {
                return "auditpol.exe could not be started.";
            }

            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            if (!process.WaitForExit(15_000))
            {
                process.Kill();
                return "auditpol.exe did not respond.";
            }

            if (process.ExitCode == 1314)
            {
                logger.LogWarning("auditpol failed: privilege not held ({Output})", output.Trim());
                return "Failed-logon auditing could not be enabled because the service lacks system privileges (error 1314). " +
                       "Make sure TheFirewall runs as the Windows service (open TheFirewall.exe), or enable 'Audit Logon: Failure' in the local security policy.";
            }

            if (process.ExitCode != 0)
            {
                logger.LogWarning("auditpol failed with exit code {Code}: {Output}", process.ExitCode, output.Trim());
                return "Failed-logon auditing could not be enabled (auditpol exit code " + process.ExitCode + "). RDP failures may not be detected. " +
                       "Enable 'Audit Logon: Failure' in the local security policy.";
            }

            logger.LogInformation("Failed-logon auditing is enabled");
            return null;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to enable logon auditing");
            return "Failed-logon auditing could not be enabled: " + ex.Message;
        }
    }
}
