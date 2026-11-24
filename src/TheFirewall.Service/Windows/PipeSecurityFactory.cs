using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
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
        // Clients connect with identification-level impersonation. While impersonating at that level, Windows
        // refuses calls that need the LSA (e.g. resolving the account name), so only capture the client's token
        // here and evaluate it after reverting to the service's own identity.
        WindowsIdentity? identity = null;
        try
        {
            pipe.RunAsClient(() =>
            {
                var current = WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.Duplicate);
                if (current.ImpersonationLevel == TokenImpersonationLevel.None)
                {
                    current.Dispose(); // not the client's token
                }
                else
                {
                    identity = current;
                }
            });
        }
        catch (Exception)
        {
            identity?.Dispose();
            identity = null;
        }

        // Fallback: the token of the client process (the kernel reports its process id).
        identity ??= FromClientProcess(pipe);
        if (identity is null)
        {
            return new IpcClientInfo();
        }

        using (identity)
        {
            var info = new IpcClientInfo();
            try
            {
                info.UserName = identity.Name;
            }
            catch (Exception)
            {
                info.UserName = identity.User?.Value;
            }

            // A non-elevated administrator has a filtered token in which Administrators is deny-only,
            // so this is only true for elevated processes (UAC is respected).
            info.IsAdministrator = identity.IsSystem ||
                                   new WindowsPrincipal(identity).IsInRole(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            return info;
        }
    }

    private static WindowsIdentity? FromClientProcess(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint processId))
        {
            return null;
        }

        using var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process.IsInvalid || !OpenProcessToken(process, (uint)(TokenAccessLevels.Query | TokenAccessLevels.Duplicate), out var token))
        {
            return null;
        }

        using (token)
        {
            return new WindowsIdentity(token.DangerousGetHandle());
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess, out SafeAccessTokenHandle token);
}
