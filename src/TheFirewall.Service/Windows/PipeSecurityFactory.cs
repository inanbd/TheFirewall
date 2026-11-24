using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using TheFirewall.Core.Ipc;

namespace TheFirewall.Service.Windows;

/// <summary>
/// Creates the service pipe with an ACL that lets any signed-in user connect (read-only), and identifies
/// whether a connected client is an elevated administrator (allowed to change things).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class PipeSecurityFactory
{
    public static NamedPipeServerStream CreatePipe(string name)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));

        // Synchronize is required in addition to ReadWrite for clients to open the pipe. CreateNewInstance is not
        // granted, so ordinary users cannot impersonate the service by creating their own pipe instances.
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
    }

    public static IpcClientInfo Identify(NamedPipeServerStream pipe)
    {
        var info = new IpcClientInfo();
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            info.UserName = identity.Name;

            // A non-elevated administrator has a filtered token in which Administrators is deny-only,
            // so IsInRole only returns true for elevated processes (UAC is respected).
            info.IsAdministrator = identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        });
        return info;
    }
}
