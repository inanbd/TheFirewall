using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TheFirewall.App.Services;
using TheFirewall.App.Views.Dialogs;
using TheFirewall.Core.Configuration;

namespace TheFirewall.App.ViewModels;

public sealed partial class RuleItem(CustomFirewallRule rule) : ObservableObject
{
    public CustomFirewallRule Rule { get; } = rule;

    public string Name => Rule.Name;

    public string Description => Rule.Description;

    public bool IsAllow => Rule.Action == RuleAction.Allow;

    public string ActionText => IsAllow ? "Allow" : "Block";

    [ObservableProperty]
    public partial bool Enabled { get; set; } = rule.Enabled;

    public string Summary => Describe(Rule);

    public static string Describe(CustomFirewallRule r)
    {
        var parts = new List<string> { r.Direction == RuleDirection.Inbound ? "Incoming" : "Outgoing" };
        var protocol = r.Protocol switch
        {
            RuleProtocol.Tcp => "TCP",
            RuleProtocol.Udp => "UDP",
            RuleProtocol.IcmpV4 => "ICMPv4 (ping)",
            RuleProtocol.IcmpV6 => "ICMPv6",
            _ => "any protocol",
        };
        if (r.Protocol is RuleProtocol.Tcp or RuleProtocol.Udp)
        {
            if (!string.IsNullOrWhiteSpace(r.LocalPorts))
            {
                protocol += $" port {r.LocalPorts.Replace(",", ", ", StringComparison.Ordinal)}";
            }

            if (!string.IsNullOrWhiteSpace(r.RemotePorts))
            {
                protocol += $" to remote port {r.RemotePorts.Replace(",", ", ", StringComparison.Ordinal)}";
            }
        }

        parts.Add(protocol);
        var addresses = r.RemoteAddresses.Split([',', ';', '\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        parts.Add(addresses.Length switch
        {
            0 => r.Direction == RuleDirection.Inbound ? "from any address" : "to any address",
            1 => (r.Direction == RuleDirection.Inbound ? "from " : "to ") + addresses[0],
            _ => (r.Direction == RuleDirection.Inbound ? "from " : "to ") + $"{addresses[0]} and {addresses.Length - 1} more",
        });
        if (!string.IsNullOrWhiteSpace(r.ProgramPath))
        {
            parts.Add("for " + System.IO.Path.GetFileName(r.ProgramPath));
        }

        return string.Join(" · ", parts);
    }
}

public sealed partial class RulesViewModel(AppServices services) : PageViewModel(services)
{
    public override string Key => "rules";

    public override string Title => "Firewall rules";

    public override string Glyph => "";

    public ObservableCollection<RuleItem> Rules { get; } = [];

    protected override async Task LoadAsync()
    {
        var settings = await Services.Settings.LoadAsync(force: true);
        Rules.Clear();
        foreach (var rule in settings.CustomRules)
        {
            Rules.Add(new RuleItem(rule));
        }
    }

    [RelayCommand]
    private async Task AddAsync(string? template)
    {
        var rule = template switch
        {
            "allow-port" => new CustomFirewallRule { Name = "Allow a port from trusted addresses", Action = RuleAction.Allow, Protocol = RuleProtocol.Tcp },
            "block-port" => new CustomFirewallRule { Name = "Block a port", Action = RuleAction.Block, Protocol = RuleProtocol.Tcp },
            "block-address" => new CustomFirewallRule { Name = "Block addresses", Action = RuleAction.Block },
            _ => new CustomFirewallRule { Name = string.Empty },
        };
        await EditAsync(rule, isNew: true);
    }

    [RelayCommand]
    private Task EditRuleAsync(RuleItem? item) => item is null ? Task.CompletedTask : EditAsync(item.Rule.Clone(), isNew: false);

    [RelayCommand]
    private Task DuplicateAsync(RuleItem? item)
    {
        if (item is null)
        {
            return Task.CompletedTask;
        }

        var copy = item.Rule.Clone();
        copy.Id = Guid.NewGuid().ToString("N")[..10];
        copy.Name += " (copy)";
        return EditAsync(copy, isNew: true);
    }

    [RelayCommand]
    private async Task DeleteAsync(RuleItem? item)
    {
        if (item is null || !UiDialogs.Confirm("Delete rule", $"Delete the rule \"{item.Name}\"? It is removed from Windows Firewall immediately.", destructive: true))
        {
            return;
        }

        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        await Services.Settings.SaveAsync(s => s.CustomRules.RemoveAll(r => r.Id == item.Rule.Id));
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task ToggleAsync(RuleItem? item)
    {
        if (item is null)
        {
            return;
        }

        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            await RefreshAsync();
            return;
        }

        var enabled = item.Enabled;
        await Services.Settings.SaveAsync(s =>
        {
            var rule = s.CustomRules.FirstOrDefault(r => r.Id == item.Rule.Id);
            if (rule is not null)
            {
                rule.Enabled = enabled;
            }
        });
        await RefreshAsync();
    }

    private async Task EditAsync(CustomFirewallRule rule, bool isNew)
    {
        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        var editor = new RuleEditorWindow(rule, isNew) { Owner = System.Windows.Application.Current.MainWindow };
        if (editor.ShowDialog() != true)
        {
            return;
        }

        var edited = editor.Result;
        if (await Services.Settings.SaveAsync(s =>
            {
                int index = s.CustomRules.FindIndex(r => r.Id == edited.Id);
                if (index >= 0)
                {
                    s.CustomRules[index] = edited;
                }
                else
                {
                    s.CustomRules.Add(edited);
                }
            }))
        {
            await RefreshAsync();
        }
    }
}
