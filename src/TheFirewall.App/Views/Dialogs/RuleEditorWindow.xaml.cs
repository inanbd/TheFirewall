using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using TheFirewall.App.ViewModels;
using TheFirewall.Core.Configuration;

namespace TheFirewall.App.Views.Dialogs;

public partial class RuleEditorWindow : Window
{
    private readonly CustomFirewallRule original;
    private bool ready;

    public RuleEditorWindow(CustomFirewallRule rule, bool isNew)
    {
        original = rule;
        InitializeComponent();
        Title = isNew ? "New firewall rule" : "Edit firewall rule";
        HeaderText.Text = Title;

        NameBox.Text = rule.Name;
        DescriptionBox.Text = rule.Description;
        ActionAllow.IsChecked = rule.Action == RuleAction.Allow;
        ActionBlock.IsChecked = rule.Action == RuleAction.Block;
        DirectionIn.IsChecked = rule.Direction == RuleDirection.Inbound;
        DirectionOut.IsChecked = rule.Direction == RuleDirection.Outbound;
        ProtocolBox.SelectedItem = ProtocolBox.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (string)i.Tag == rule.Protocol.ToString()) ?? ProtocolBox.Items[0];
        LocalPortsBox.Text = rule.LocalPorts;
        RemotePortsBox.Text = rule.RemotePorts;
        AddressesBox.Text = string.Join(Environment.NewLine, rule.RemoteAddresses.Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        ProgramBox.Text = rule.ProgramPath;
        var profiles = rule.Profiles == RuleProfiles.None ? RuleProfiles.All : rule.Profiles;
        ProfileDomain.IsChecked = profiles.HasFlag(RuleProfiles.Domain);
        ProfilePrivate.IsChecked = profiles.HasFlag(RuleProfiles.Private);
        ProfilePublic.IsChecked = profiles.HasFlag(RuleProfiles.Public);
        EnabledBox.IsChecked = rule.Enabled;
        ready = true;
        Update();
        Loaded += (_, _) => NameBox.Focus();
    }

    public CustomFirewallRule Result { get; private set; } = new();

    private void OnChanged(object sender, RoutedEventArgs e) => Update();

    private CustomFirewallRule Build()
    {
        var protocol = Enum.Parse<RuleProtocol>((string)((ComboBoxItem)ProtocolBox.SelectedItem).Tag);
        var profiles = (ProfileDomain.IsChecked == true ? RuleProfiles.Domain : RuleProfiles.None) |
                       (ProfilePrivate.IsChecked == true ? RuleProfiles.Private : RuleProfiles.None) |
                       (ProfilePublic.IsChecked == true ? RuleProfiles.Public : RuleProfiles.None);
        bool ports = protocol is RuleProtocol.Tcp or RuleProtocol.Udp;
        return new CustomFirewallRule
        {
            Id = original.Id,
            Name = NameBox.Text.Trim(),
            Description = DescriptionBox.Text.Trim(),
            Enabled = EnabledBox.IsChecked == true,
            Action = ActionAllow.IsChecked == true ? RuleAction.Allow : RuleAction.Block,
            Direction = DirectionOut.IsChecked == true ? RuleDirection.Outbound : RuleDirection.Inbound,
            Protocol = protocol,
            LocalPorts = ports ? LocalPortsBox.Text.Trim() : string.Empty,
            RemotePorts = ports ? RemotePortsBox.Text.Trim() : string.Empty,
            RemoteAddresses = string.Join(",", AddressesBox.Text.Split([',', ';', '\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)),
            ProgramPath = ProgramBox.Text.Trim(),
            Profiles = profiles == RuleProfiles.None ? RuleProfiles.All : profiles,
        };
    }

    private void Update()
    {
        if (!ready)
        {
            return;
        }

        var rule = Build();
        bool ports = rule.Protocol is RuleProtocol.Tcp or RuleProtocol.Udp;
        PortsPanel.IsEnabled = ports;
        PortsHint.Text = ports ? "e.g. 3389 or 80, 443, 8000-8100. Leave empty for all ports." : "Ports can only be set for TCP or UDP.";
        PreviewText.Text = $"{(rule.Action == RuleAction.Allow ? "Allow" : "Block")}: {RuleItem.Describe(rule)}";

        var errors = Validate(rule);
        ErrorText.Text = errors.FirstOrDefault() ?? string.Empty;
    }

    private static List<string> Validate(CustomFirewallRule rule)
    {
        var settings = new FirewallSettings { ThreatFeeds = [] };
        settings.CustomRules.Add(rule);
        return SettingsStore.Validate(settings).Select(e => e.Replace($"Firewall rule '{rule.Name}': ", string.Empty, StringComparison.Ordinal)).ToList();
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a program", Filter = "Programs (*.exe)|*.exe|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) == true)
        {
            ProgramBox.Text = dialog.FileName;
        }
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var rule = Build();
        var errors = Validate(rule);
        if (errors.Count > 0)
        {
            ErrorText.Text = string.Join(" ", errors);
            return;
        }

        Result = rule;
        DialogResult = true;
    }
}
