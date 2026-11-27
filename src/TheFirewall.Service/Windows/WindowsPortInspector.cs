using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using TheFirewall.Core.Ports;

namespace TheFirewall.Service.Windows;

/// <summary>Lists listening TCP ports and bound UDP ports with their programs (IP Helper API) for the Ports page.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsPortInspector(WindowsFirewallBackend firewall) : IPortInspector
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidListener = 3;
    private const int UdpTableOwnerPid = 1;
    private const int ErrorInsufficientBuffer = 122;

    /// <summary>UDP sockets in the dynamic range are almost always outgoing (client) sockets, not services.</summary>
    private const int FirstDynamicPort = 49152;

    public IReadOnlyList<FirewallRuleInfo> GetInboundRules() => firewall.GetInboundRules();

    public FirewallPolicyInfo GetPolicy() => firewall.GetPolicyInfo();

    public IReadOnlyList<ListeningPort> GetListeningPorts()
    {
        var endpoints = new List<(string Protocol, IPAddress Address, int Port, int Pid)>();
        endpoints.AddRange(ReadTable(tcp: true, AfInet));
        endpoints.AddRange(ReadTable(tcp: true, AfInet6));
        endpoints.AddRange(ReadTable(tcp: false, AfInet).Where(e => e.Port < FirstDynamicPort));
        endpoints.AddRange(ReadTable(tcp: false, AfInet6).Where(e => e.Port < FirstDynamicPort));

        var services = ServicesByProcess();
        var processes = new Dictionary<int, (string? Name, string? Path)>();
        var result = new List<ListeningPort>();
        foreach (var group in endpoints.GroupBy(e => (e.Protocol, e.Port, e.Pid)))
        {
            if (!processes.TryGetValue(group.Key.Pid, out var process))
            {
                process = DescribeProcess(group.Key.Pid);
                processes[group.Key.Pid] = process;
            }

            var hosted = services.GetValueOrDefault(group.Key.Pid) ?? [];
            result.Add(new ListeningPort
            {
                Protocol = group.Key.Protocol,
                Port = group.Key.Port,
                Addresses = [.. group.Select(e => e.Address.ToString()).Distinct()],
                ProcessId = group.Key.Pid,
                ProcessName = process.Name,
                ProcessPath = process.Path,
                ServiceNames = [.. hosted.Select(s => s.Name)],
                Services = [.. hosted.Select(s => s.DisplayName)],
            });
        }

        return result;
    }

    private static IEnumerable<(string Protocol, IPAddress Address, int Port, int Pid)> ReadTable(bool tcp, int family)
    {
        int size = 0;
        uint status = tcp
            ? GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, TcpTableOwnerPidListener, 0)
            : GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, UdpTableOwnerPid, 0);
        for (int attempt = 0; attempt < 5 && status == ErrorInsufficientBuffer; attempt++)
        {
            size += 4096;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                status = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidListener, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerPid, 0);
                if (status == 0)
                {
                    return Parse(buffer, tcp, family);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        if (status != 0 && status != ErrorInsufficientBuffer)
        {
            throw new Win32Exception((int)status);
        }

        return [];
    }

    /// <summary>Reads MIB_TCPROW_OWNER_PID / MIB_TCP6ROW_OWNER_PID / MIB_UDPROW_OWNER_PID / MIB_UDP6ROW_OWNER_PID rows.</summary>
    private static List<(string Protocol, IPAddress Address, int Port, int Pid)> Parse(IntPtr table, bool tcp, int family)
    {
        var rows = new List<(string, IPAddress, int, int)>();
        int count = Marshal.ReadInt32(table);
        bool v6 = family == AfInet6;
        int rowSize = (tcp, v6) switch
        {
            (true, false) => 24,   // state, localAddr, localPort, remoteAddr, remotePort, pid
            (true, true) => 56,    // localAddr[16], scope, localPort, remoteAddr[16], scope, remotePort, state, pid
            (false, false) => 12,  // localAddr, localPort, pid
            (false, true) => 28,   // localAddr[16], scope, localPort, pid
        };

        var bytes = new byte[16];
        for (int i = 0; i < count; i++)
        {
            var row = table + 4 + (i * rowSize);
            IPAddress address;
            int portField;
            int pid;
            if (!v6)
            {
                int addressOffset = tcp ? 4 : 0;
                address = new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(row + addressOffset)));
                portField = Marshal.ReadInt32(row + addressOffset + 4);
                pid = Marshal.ReadInt32(row + rowSize - 4);
            }
            else
            {
                Marshal.Copy(row, bytes, 0, 16);
                address = new IPAddress(bytes);
                portField = Marshal.ReadInt32(row + 20);
                pid = Marshal.ReadInt32(row + rowSize - 4);
            }

            // The port is stored in network byte order in the low 16 bits.
            int port = ((portField & 0xFF) << 8) | ((portField >> 8) & 0xFF);
            rows.Add((tcp ? "TCP" : "UDP", address, port, pid));
        }

        return rows;
    }

    private static (string? Name, string? Path) DescribeProcess(int pid)
    {
        if (pid == 0)
        {
            return ("System Idle Process", null);
        }

        if (pid == 4)
        {
            // The kernel (http.sys, SMB, WinRM listeners...). Firewall rules for it use the program name "System".
            return ("System", "System");
        }

        string? path = null;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var builder = new StringBuilder(1024);
                int length = builder.Capacity;
                if (QueryFullProcessImageName(handle, 0, builder, ref length))
                {
                    path = builder.ToString(0, length);
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        string? name = path is null ? null : System.IO.Path.GetFileNameWithoutExtension(path);
        if (name is null)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                name = process.ProcessName;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                // The process has exited.
            }
        }

        return (name, path);
    }

    /// <summary>Windows services by the process that hosts them (several services can share one svchost.exe).</summary>
    private static Dictionary<int, List<(string Name, string DisplayName)>> ServicesByProcess()
    {
        var result = new Dictionary<int, List<(string, string)>>();
        var manager = OpenSCManager(null, null, ScManagerEnumerateService);
        if (manager == IntPtr.Zero)
        {
            return result;
        }

        try
        {
            int resume = 0;
            EnumServicesStatusEx(manager, ScEnumProcessInfo, ServiceWin32, ServiceActive, IntPtr.Zero, 0, out int needed, out _, ref resume, null);
            if (needed <= 0)
            {
                return result;
            }

            var buffer = Marshal.AllocHGlobal(needed + 4096);
            try
            {
                resume = 0;
                if (!EnumServicesStatusEx(manager, ScEnumProcessInfo, ServiceWin32, ServiceActive, buffer, needed + 4096, out _, out int returned, ref resume, null))
                {
                    return result;
                }

                int stride = Marshal.SizeOf<EnumServiceStatusProcess>();
                for (int i = 0; i < returned; i++)
                {
                    var entry = Marshal.PtrToStructure<EnumServiceStatusProcess>(buffer + (i * stride));
                    if (entry.ProcessId == 0)
                    {
                        continue;
                    }

                    var name = Marshal.PtrToStringUni(entry.ServiceName) ?? string.Empty;
                    var display = Marshal.PtrToStringUni(entry.DisplayName) ?? name;
                    if (!result.TryGetValue((int)entry.ProcessId, out var list))
                    {
                        list = [];
                        result[(int)entry.ProcessId] = list;
                    }

                    list.Add((name, display));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }

        return result;
    }

    private const int ProcessQueryLimitedInformation = 0x1000;
    private const int ScManagerEnumerateService = 0x0004;
    private const int ScEnumProcessInfo = 0;
    private const int ServiceWin32 = 0x30;
    private const int ServiceActive = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int tableClass, int reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, int access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool EnumServicesStatusEx(IntPtr manager, int infoLevel, int serviceType, int serviceState, IntPtr services,
        int bufferSize, out int bytesNeeded, out int servicesReturned, ref int resumeHandle, string? groupName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
