using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TheFirewall.App.Services;
using TheFirewall.App.Views.Dialogs;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Geo;
using TheFirewall.Core.Networking;
using TheFirewall.Core.Ports;

namespace TheFirewall.App.ViewModels;

/// <summary>A port on the Ports page.</summary>
public sealed partial class PortItem(PortRule rule, PortsViewModel owner) : ObservableObject
{
    public PortRule Rule { get; } = rule;

    public string Name => Rule.Name;

    public string PortText => $"{FirewallPlanner.PortProtocolName(Rule.Protocol)} {Rule.Ports.Replace(",", ", ", StringComparison.Ordinal)}";

    public bool IsOpen => Rule.Access == PortAccess.Everyone;

    public bool IsRestricted => Rule.Access == PortAccess.Restricted;

    public bool IsClosed => Rule.Access == PortAccess.Nobody;

    public PortState State => PortPolicy.Evaluate(Rule, DateTimeOffset.UtcNow, TimeZoneInfo.Local);

    public bool IsTemporarilyOpen => State.Reason == PortStateReason.TemporarilyOpen;

    /// <summary>Who may connect right now, in words.</summary>
    public string StateText
    {
        get
        {
            var state = State;
            return state.Reason switch
            {
                PortStateReason.TemporarilyOpen => $"Temporarily open to everyone until {FormatTime(state.NextChangeUtc)}",
                PortStateReason.OutsideSchedule => $"Closed now (outside its open hours){(state.NextChangeUtc is null ? string.Empty : $" · opens {FormatTime(state.NextChangeUtc)}")}",
                _ => Describe(Rule) + (state.NextChangeUtc is null ? string.Empty : $" · until {FormatTime(state.NextChangeUtc)}"),
            };
        }
    }

    /// <summary>Exposure of the effective state, for the status dot.</summary>
    public PortExposure StateExposure => State.Access switch
    {
        PortAccess.Everyone => PortExposure.Open,
        PortAccess.Restricted => PortExposure.OpenToSome,
        _ => PortExposure.Blocked,
    };

    public string? ScheduleText => Rule.Schedule.Enabled
        ? $"Open hours: {DaysText(Rule.Schedule.Days)} {Rule.Schedule.From}–{Rule.Schedule.To}; closed at other times"
        : null;

    [ObservableProperty]
    public partial string UsageText { get; set; } = string.Empty;

    public static string Describe(PortRule rule) => rule.Access switch
    {
        PortAccess.Everyone => "Open to everyone",
        PortAccess.Restricted => $"Only {WhoText(rule)} can connect",
        _ => "Closed · everyone is blocked except your whitelist and local network",
    };

    public static string WhoText(PortRule rule)
    {
        var names = IPUtility.ParseList(rule.AllowedAddresses).Select(a => a.ToFirewallString())
            .Concat(rule.AllowedCountries.Select(Countries.GetName)).ToList();
        return names.Count switch
        {
            0 => "nobody else",
            1 => names[0],
            2 => $"{names[0]} and {names[1]}",
            3 => $"{names[0]}, {names[1]} and {names[2]}",
            _ => $"{names[0]}, {names[1]} and {names.Count - 2} more",
        };
    }

    public static string DaysText(WeekDays days) => days switch
    {
        WeekDays.All => "every day",
        WeekDays.Weekdays => "Mon–Fri",
        WeekDays.Weekend => "Sat–Sun",
        _ => string.Join(", ", Enum.GetValues<DayOfWeek>().Select(d => (Day: d, Flag: PortSchedule.ToFlag(d)))
            .OrderBy(d => ((int)d.Day + 6) % 7).Where(d => days.HasFlag(d.Flag))
            .Select(d => CultureInfo.InvariantCulture.DateTimeFormat.GetAbbreviatedDayName(d.Day))),
    };

    private static string FormatTime(DateTimeOffset? utc)
    {
        if (utc is null)
        {
            return string.Empty;
        }

        var local = utc.Value.ToLocalTime();
        return local.Date == DateTime.Today ? local.ToString("t", CultureInfo.CurrentCulture) : local.ToString("ddd t", CultureInfo.CurrentCulture);
    }

    [RelayCommand]
    private Task SetAccessAsync(string? access) => owner.SetAccessAsync(this, Enum.TryParse<PortAccess>(access, out var a) ? a : PortAccess.Everyone);

    [RelayCommand]
    private Task OpenForAsync(string? minutes) => owner.OpenForAsync(this, int.TryParse(minutes, CultureInfo.InvariantCulture, out var m) ? m : 60);

    [RelayCommand]
    private Task CloseNowAsync() => owner.CloseNowAsync(this);

    [RelayCommand]
    private Task EditAsync() => owner.EditAsync(Rule.Clone(), isNew: false);

    [RelayCommand]
    private Task DeleteAsync() => owner.DeleteAsync(this);
}

/// <summary>A port a program listens on, in the "Listening on this computer" list.</summary>
public sealed partial class ListeningPortItem(ListeningPort port, PortsViewModel owner) : ObservableObject
{
    public ListeningPort Port { get; } = port;

    public string PortText => Port.Port.ToString(CultureInfo.InvariantCulture);

    public string Protocol => Port.Protocol;

    public string ProgramText => Port.Services.Count > 0
        ? $"{Port.ProcessName} ({string.Join(", ", Port.Services.Take(2))}{(Port.Services.Count > 2 ? ", …" : string.Empty)})"
        : Port.ProcessName ?? $"Process {Port.ProcessId}";

    public string? ProgramToolTip => Port.ProcessPath;

    public string UseText => Port.KnownName ?? string.Empty;

    public string AddressText => Port.Exposure == PortExposure.LocalOnly
        ? "This computer only"
        : Port.Addresses.Any(a => a is "0.0.0.0" or "::") ? "All network addresses" : string.Join(", ", Port.Addresses);

    public PortExposure Exposure => Port.Exposure;

    public string ExposureText => Port.ExposureText;

    public bool IsManaged => Port.ManagedPortId is not null;

    /// <summary>Offer the one-click "Close" when the port can be reached from outside.</summary>
    public bool CanClose => Port.Exposure is PortExposure.Open or PortExposure.OpenToSome;

    [RelayCommand]
    private Task ManageAsync() => owner.ManageAsync(this);

    [RelayCommand]
    private Task CloseAsync() => owner.CloseListeningAsync(this);
}

public sealed partial class PortsViewModel(AppServices services) : PageViewModel(services)
{
    private List<ListeningPort> listening = [];

    public override string Key => "ports";

    public override string Title => "Ports";

    public override string Glyph => "\uE839";

    public ObservableCollection<PortItem> Ports { get; } = [];

    public ObservableCollection<ListeningPortItem> Listening { get; } = [];

    public IReadOnlyList<KnownPort> QuickAdd => PortCatalog.Common;

    [ObservableProperty]
    public partial string? ListeningError { get; set; }

    [ObservableProperty]
    public partial bool IsScanning { get; set; }

    protected override async Task LoadAsync()
    {
        var settingsTask = Services.Settings.LoadAsync(force: true);
        var listeningTask = LoadListeningAsync();
        var settings = await settingsTask;
        await listeningTask;

        Ports.Clear();
        foreach (var rule in settings.Ports)
        {
            Ports.Add(new PortItem(rule, this));
        }

        UpdateUsage();
    }

    private async Task LoadListeningAsync()
    {
        IsScanning = true;
        try
        {
            var response = await Client.GetListeningPortsAsync();
            listening = response.Ports;
            ListeningError = response.Error;
        }
        catch (Exception ex)
        {
            listening = [];
            ListeningError = ex.Message;
        }
        finally
        {
            IsScanning = false;
        }

        Listening.Clear();
        foreach (var port in listening.OrderBy(p => p.Exposure == PortExposure.LocalOnly).ThenBy(p => p.Port).ThenBy(p => p.Protocol, StringComparer.Ordinal))
        {
            Listening.Add(new ListeningPortItem(port, this));
        }
    }

    private void UpdateUsage()
    {
        foreach (var item in Ports)
        {
            var users = listening.Where(l => PortReachability.Covers(item.Rule, l.Protocol == "UDP" ? RuleProtocol.Udp : RuleProtocol.Tcp, l.Port))
                .Select(l => l.Services.Count > 0 ? $"{l.ProcessName} ({l.Services[0]})" : l.ProcessName ?? "?")
                .Distinct().ToList();
            item.UsageText = users.Count == 0 ? "Nothing listens on this port right now" : "Used by " + string.Join(", ", users.Take(3));
        }
    }

    [RelayCommand]
    private Task RescanAsync() => RefreshAsync();

    [RelayCommand]
    private Task AddAsync() => EditAsync(new PortRule { Protocol = RuleProtocol.Tcp, Access = PortAccess.Nobody }, isNew: true);

    [RelayCommand]
    private Task AddKnownAsync(KnownPort? known)
    {
        if (known is null)
        {
            return Task.CompletedTask;
        }

        var existing = Ports.FirstOrDefault(p => p.Rule.Protocol == known.Protocol &&
                                                 FirewallPlanner.NormalizePorts(p.Rule.Ports) == FirewallPlanner.NormalizePorts(known.Ports));
        if (existing is not null)
        {
            return EditAsync(existing.Rule.Clone(), isNew: false);
        }

        // Start from what the port does today, so saving without changes does not open or close anything unexpectedly.
        var first = int.Parse(known.Ports.Split(',', '-')[0], CultureInfo.InvariantCulture);
        var current = listening.FirstOrDefault(l => l.Port == first && l.Exposure != PortExposure.LocalOnly);
        return EditAsync(new PortRule
        {
            Name = known.Name,
            Protocol = known.Protocol,
            Ports = known.Ports,
            Access = current?.Exposure == PortExposure.Open ? PortAccess.Everyone : PortAccess.Nobody,
        }, isNew: true);
    }

    internal async Task EditAsync(PortRule rule, bool isNew)
    {
        var dialog = new PortEditorWindow(rule, isNew, CurrentSituation(rule)) { Owner = System.Windows.Application.Current.MainWindow };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var result = dialog.Result;
        if (!ConfirmLockout(result))
        {
            return;
        }

        await SaveAsync(s =>
        {
            var index = s.Ports.FindIndex(p => p.Id == result.Id);
            if (index >= 0)
            {
                s.Ports[index] = result;
            }
            else
            {
                s.Ports.Add(result);
            }
        });
    }

    internal async Task SetAccessAsync(PortItem item, PortAccess access)
    {
        if (item.Rule.Access == access && !item.IsTemporarilyOpen)
        {
            return;
        }

        var changed = item.Rule.Clone();
        changed.Access = access;
        changed.OpenUntilUtc = null;
        if (access == PortAccess.Restricted && string.IsNullOrWhiteSpace(changed.AllowedAddresses) && changed.AllowedCountries.Count == 0)
        {
            // Choose who may connect first.
            await EditAsync(changed, isNew: false);
            return;
        }

        if (!ConfirmLockout(changed))
        {
            return;
        }

        await SaveAsync(s =>
        {
            var rule = s.Ports.FirstOrDefault(p => p.Id == item.Rule.Id);
            if (rule is not null)
            {
                rule.Access = access;
                rule.OpenUntilUtc = null;
            }
        });
    }

    internal Task OpenForAsync(PortItem item, int minutes) =>
        SaveAsync(s =>
        {
            var rule = s.Ports.FirstOrDefault(p => p.Id == item.Rule.Id);
            if (rule is not null)
            {
                rule.OpenUntilUtc = DateTimeOffset.UtcNow.AddMinutes(Math.Clamp(minutes, 1, 7 * 24 * 60));
            }
        });

    internal Task CloseNowAsync(PortItem item) =>
        SaveAsync(s =>
        {
            var rule = s.Ports.FirstOrDefault(p => p.Id == item.Rule.Id);
            if (rule is not null)
            {
                rule.OpenUntilUtc = null;
            }
        });

    internal async Task DeleteAsync(PortItem item)
    {
        if (!UiDialogs.Confirm("Stop managing this port",
                $"Remove \"{item.Name}\" ({item.PortText}) from the Ports page?\n\nTheFirewall deletes its rules for this port, and Windows Firewall's own rules decide who can connect again.",
                destructive: true))
        {
            return;
        }

        await SaveAsync(s => s.Ports.RemoveAll(p => p.Id == item.Rule.Id));
    }

    internal Task ManageAsync(ListeningPortItem item)
    {
        var existing = Ports.FirstOrDefault(p => p.Rule.Id == item.Port.ManagedPortId);
        if (existing is not null)
        {
            return EditAsync(existing.Rule.Clone(), isNew: false);
        }

        return EditAsync(NewRuleFor(item.Port, item.Exposure == PortExposure.Open ? PortAccess.Everyone : PortAccess.Nobody), isNew: true);
    }

    internal async Task CloseListeningAsync(ListeningPortItem item)
    {
        var existing = Ports.FirstOrDefault(p => p.Rule.Id == item.Port.ManagedPortId);
        if (existing is not null)
        {
            await SetAccessAsync(existing, PortAccess.Nobody);
            return;
        }

        var rule = NewRuleFor(item.Port, PortAccess.Nobody);
        if (!ConfirmLockout(rule))
        {
            return;
        }

        await SaveAsync(s => s.Ports.Add(rule));
    }

    private static PortRule NewRuleFor(ListeningPort port, PortAccess access) => new()
    {
        Name = port.KnownName ?? port.Services.FirstOrDefault() ?? port.ProcessName ?? $"Port {port.Port}",
        Protocol = port.Protocol == "UDP" ? RuleProtocol.Udp : RuleProtocol.Tcp,
        Ports = port.Port.ToString(CultureInfo.InvariantCulture),
        Access = access,
    };

    /// <summary>What the port does today (from the listening list), shown in the editor.</summary>
    private string? CurrentSituation(PortRule rule)
    {
        var ports = FirewallPlanner.NormalizePorts(rule.Ports);
        var match = listening.FirstOrDefault(l =>
            l.Exposure != PortExposure.LocalOnly &&
            (rule.Protocol == RuleProtocol.Any || (rule.Protocol == RuleProtocol.Udp) == (l.Protocol == "UDP")) &&
            PortReachability.PortListContains(ports.Length == 0 ? "0" : ports, l.Port));
        return match is null ? null : $"Right now port {match.Port} ({match.ProgramText()}): {match.ExposureText}";
    }

    /// <summary>Warns before closing or restricting a port that may be how the user is connected right now.</summary>
    private static bool ConfirmLockout(PortRule rule)
    {
        if (rule.Access == PortAccess.Everyone && !rule.Schedule.Enabled)
        {
            return true;
        }

        var what = rule.Access switch
        {
            PortAccess.Restricted => $"everyone except {PortItem.WhoText(rule)}, your whitelist and your local network will be blocked",
            PortAccess.Nobody => "everyone except your whitelist and your local network will be blocked",
            _ => "it will be closed outside its open hours",
        };
        return UiDialogs.Confirm($"Change {rule.Name}",
            $"{rule.Name} ({FirewallPlanner.PortProtocolName(rule.Protocol)} {rule.Ports}): {what}.\n\n" +
            "If you are connected to this computer through this port from another address, you will lose the connection. " +
            "Add your own address to the whitelist first if needed.\n\nApply?");
    }

    private async Task SaveAsync(Action<FirewallSettings> change)
    {
        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        await Services.Settings.SaveAsync(change);
        await RefreshAsync();
    }
}

internal static class ListeningPortText
{
    public static string ProgramText(this ListeningPort port) =>
        port.Services.Count > 0 ? $"{port.ProcessName}, {port.Services[0]}" : port.ProcessName ?? $"process {port.ProcessId}";
}
