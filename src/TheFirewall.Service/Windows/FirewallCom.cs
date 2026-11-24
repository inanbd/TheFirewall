// COM interface layouts for the Windows Firewall API (netfw.h / NetFwTypeLib).
// Adapted from IPBan (https://github.com/DigitalRuby/IPBan), MIT License,
// Copyright (c) 2012-present Digital Ruby, LLC. Member order matters: it defines the vtable.

using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace TheFirewall.Service.Windows;

internal static class NetFw
{
    public const string PolicyClsid = "E2B3C97F-6AE1-41AC-817A-F6F92166D7DD";
    public const string RuleClsid = "2C5BC43E-3369-4C33-AB0C-BE9469677AF4";

    public const int ProfileDomain = 1;
    public const int ProfilePrivate = 2;
    public const int ProfilePublic = 4;
    public const int ProfileAll = 0x7FFFFFFF;

    public const int DirectionInbound = 1;
    public const int DirectionOutbound = 2;

    public const int ActionBlock = 0;
    public const int ActionAllow = 1;

    public const int ProtocolIcmpV4 = 1;
    public const int ProtocolTcp = 6;
    public const int ProtocolUdp = 17;
    public const int ProtocolIcmpV6 = 58;
    public const int ProtocolAny = 256;
}

[ComImport]
[Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
internal interface INetFwPolicy2
{
    int CurrentProfileTypes { get; }

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_FirewallEnabled(int profileType);

    void set_FirewallEnabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool enabled);

    [return: MarshalAs(UnmanagedType.Struct)]
    object get_ExcludedInterfaces(int profileType);

    void set_ExcludedInterfaces(int profileType, [MarshalAs(UnmanagedType.Struct)] object interfaces);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_BlockAllInboundTraffic(int profileType);

    void set_BlockAllInboundTraffic(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool block);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_NotificationsDisabled(int profileType);

    void set_NotificationsDisabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool disabled);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_UnicastResponsesToMulticastBroadcastDisabled(int profileType);

    void set_UnicastResponsesToMulticastBroadcastDisabled(int profileType, [MarshalAs(UnmanagedType.VariantBool)] bool disabled);

    INetFwRules Rules
    {
        [return: MarshalAs(UnmanagedType.Interface)]
        get;
    }

    object ServiceRestriction
    {
        [return: MarshalAs(UnmanagedType.Interface)]
        get;
    }

    void EnableRuleGroup(int profileTypesBitmask, [MarshalAs(UnmanagedType.BStr)] string group, [MarshalAs(UnmanagedType.VariantBool)] bool enable);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool IsRuleGroupEnabled(int profileTypesBitmask, [MarshalAs(UnmanagedType.BStr)] string group);

    void RestoreLocalFirewallDefaults();

    int get_DefaultInboundAction(int profileType);

    void set_DefaultInboundAction(int profileType, int action);

    int get_DefaultOutboundAction(int profileType);

    void set_DefaultOutboundAction(int profileType, int action);

    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_IsRuleGroupCurrentlyEnabled([MarshalAs(UnmanagedType.BStr)] string group);

    int LocalPolicyModifyState { get; }
}

[ComImport]
[Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
internal interface INetFwRules
{
    int Count { get; }

    void Add([MarshalAs(UnmanagedType.Interface)] INetFwRule rule);

    void Remove([MarshalAs(UnmanagedType.BStr)] string name);

    [return: MarshalAs(UnmanagedType.Interface)]
    INetFwRule Item([MarshalAs(UnmanagedType.BStr)] string name);

    [return: MarshalAs(UnmanagedType.Interface)]
    IEnumVARIANT GetEnumeratorVariant();
}

[ComImport]
[Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
internal interface INetFwRule
{
    string Name
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    string Description
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    string ApplicationName
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    string ServiceName
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    int Protocol { get; set; }

    string LocalPorts
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    string RemotePorts
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    string LocalAddresses
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    string RemoteAddresses
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    string IcmpTypesAndCodes
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    int Direction { get; set; }

    object Interfaces
    {
        [return: MarshalAs(UnmanagedType.Struct)]
        get;
        [param: MarshalAs(UnmanagedType.Struct)]
        set;
    }

    string InterfaceTypes
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    bool Enabled
    {
        [return: MarshalAs(UnmanagedType.VariantBool)]
        get;
        [param: MarshalAs(UnmanagedType.VariantBool)]
        set;
    }

    string Grouping
    {
        [return: MarshalAs(UnmanagedType.BStr)]
        get;
        [param: MarshalAs(UnmanagedType.BStr)]
        set;
    }

    int Profiles { get; set; }

    bool EdgeTraversal
    {
        [return: MarshalAs(UnmanagedType.VariantBool)]
        get;
        [param: MarshalAs(UnmanagedType.VariantBool)]
        set;
    }

    int Action { get; set; }
}
