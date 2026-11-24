using System.Reflection;

namespace TheFirewall.Service;

internal static class ServiceConstants
{
    public const string ServiceName = "TheFirewall";
    public const string DisplayName = "TheFirewall";
    public const string Description = "Watches Windows logs for failed logins (RDP, SSH, SQL Server, mail, FTP...) and blocks attacking IP addresses with Windows Defender Firewall.";

    public static string Version { get; } =
        typeof(ServiceConstants).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? typeof(ServiceConstants).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
}
