using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TheFirewall.App.Services;
using TheFirewall.App.Views.Dialogs;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Ipc;
using TheFirewall.Core.Monitoring;

namespace TheFirewall.App.ViewModels;

public sealed partial class SourceItem : ObservableObject
{
    public SourceItem(SourceInfoDto info)
    {
        Info = info;
        Enabled = info.Definition.Enabled;
    }

    public SourceInfoDto Info { get; }

    public LogSourceDefinition Definition => Info.Definition;

    public string Name => Definition.Name;

    public string Description => Definition.Description;

    public bool IsBuiltIn => Info.IsBuiltIn;

    public bool IsSuccessSource => Definition.EventKind == LoginEventKind.Successful;

    public string KindText => (Definition.Kind == LogSourceKind.EventLog ? $"Event log: {Definition.LogName}" : "Text log files") +
                              (IsSuccessSource ? " · successful sign-ins" : string.Empty) +
                              (Definition.FailedAttemptsBeforeBan > 0 ? $" · bans after {Definition.FailedAttemptsBeforeBan} attempts" : string.Empty) +
                              (IsBuiltIn ? string.Empty : " · custom");

    public SourceState State => Info.Status.State;

    public string? StatusMessage => Info.Status.Message;

    public string Statistics => Info.Status.EventsDetected > 0
        ? $"{Info.Status.EventsDetected:N0} detected since the service started" +
          (Info.Status.LastEventUtc is { } last ? $", last {Converters.RelativeTimeConverter.Format(last)}" : string.Empty)
        : string.Empty;

    [ObservableProperty]
    public partial bool Enabled { get; set; }
}

public sealed record SourceGroup(string Name, IReadOnlyList<SourceItem> Items);

public sealed partial class SourcesViewModel(AppServices services) : PageViewModel(services)
{
    private List<SourceInfoDto> all = [];

    public override string Key => "sources";

    public override string Title => "Login monitors";

    public override string Glyph => "\uE9D9";

    public ObservableCollection<SourceGroup> Groups { get; } = [];

    [ObservableProperty]
    public partial string? Search { get; set; }

    [ObservableProperty]
    public partial bool OnlyDetected { get; set; }

    [ObservableProperty]
    public partial int ActiveCount { get; set; }

    partial void OnSearchChanged(string? value) => Rebuild();

    partial void OnOnlyDetectedChanged(bool value) => Rebuild();

    protected override async Task LoadAsync()
    {
        all = await Client.GetSourcesAsync();
        ActiveCount = all.Count(s => s.Status.State == SourceState.Active);
        Rebuild();
    }

    private void Rebuild()
    {
        var order = new[] { BuiltInSources.RemoteAccess, BuiltInSources.Databases, BuiltInSources.Mail, BuiltInSources.Web, BuiltInSources.Other };
        var filtered = all.Where(s =>
            (!OnlyDetected || s.Status.State == SourceState.Active) &&
            (string.IsNullOrWhiteSpace(Search) ||
             s.Definition.Name.Contains(Search.Trim(), StringComparison.OrdinalIgnoreCase) ||
             s.Definition.Source.Contains(Search.Trim(), StringComparison.OrdinalIgnoreCase) ||
             s.Definition.Description.Contains(Search.Trim(), StringComparison.OrdinalIgnoreCase)));

        Groups.Clear();
        foreach (var group in filtered.GroupBy(s => s.IsBuiltIn ? s.Definition.Category : "Custom")
                     .OrderBy(g => Array.IndexOf(order, g.Key) is var i && i >= 0 ? i : 99))
        {
            Groups.Add(new SourceGroup(group.Key, group
                .OrderBy(s => s.Definition.EventKind)
                .ThenByDescending(s => s.Status.State == SourceState.Active)
                .ThenBy(s => s.Definition.Name, StringComparer.CurrentCulture)
                .Select(s => new SourceItem(s)).ToList()));
        }
    }

    [RelayCommand]
    private async Task ToggleAsync(SourceItem? item)
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
            if (item.IsBuiltIn)
            {
                var ov = s.SourceOverrides.TryGetValue(item.Definition.Id, out var existing) ? existing : new SourceOverride();
                ov.Enabled = enabled;
                s.SourceOverrides[item.Definition.Id] = ov;
            }
            else
            {
                var custom = s.CustomSources.FirstOrDefault(c => c.Id == item.Definition.Id);
                if (custom is not null)
                {
                    custom.Enabled = enabled;
                }
            }
        });
        await RefreshAsync();
    }

    [RelayCommand]
    private Task AddAsync() => EditCoreAsync(new LogSourceDefinition
    {
        Name = string.Empty,
        Source = "Custom",
        Kind = LogSourceKind.TextFile,
        PathMasks = @"C:\Logs\MyApp\*.log",
        Regex = @"login\sfailed.*?from\s(?<ipaddress>[^\s]+)",
    }, isBuiltIn: false, isNew: true);

    [RelayCommand]
    private Task EditAsync(SourceItem? item) => item is null ? Task.CompletedTask : EditCoreAsync(item.Definition.Clone(), item.IsBuiltIn, isNew: false);

    [RelayCommand]
    private Task DuplicateAsync(SourceItem? item)
    {
        if (item is null)
        {
            return Task.CompletedTask;
        }

        var copy = item.Definition.Clone();
        copy.Id = "custom-" + Guid.NewGuid().ToString("N")[..8];
        copy.Name += " (custom)";
        copy.Category = "Custom";
        return EditCoreAsync(copy, isBuiltIn: false, isNew: true);
    }

    [RelayCommand]
    private async Task DeleteAsync(SourceItem? item)
    {
        if (item is null || item.IsBuiltIn || !UiDialogs.Confirm("Delete monitor", $"Delete the custom monitor \"{item.Name}\"?", destructive: true))
        {
            return;
        }

        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        await Services.Settings.SaveAsync(s => s.CustomSources.RemoveAll(c => c.Id == item.Definition.Id));
        await RefreshAsync();
    }

    private async Task EditCoreAsync(LogSourceDefinition definition, bool isBuiltIn, bool isNew)
    {
        var editor = new SourceEditorWindow(Client, definition, isBuiltIn, isNew) { Owner = System.Windows.Application.Current.MainWindow };
        if (editor.ShowDialog() != true)
        {
            return;
        }

        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        var edited = editor.Result;
        if (await Services.Settings.SaveAsync(s =>
            {
                if (isBuiltIn)
                {
                    var ov = s.SourceOverrides.TryGetValue(edited.Id, out var existing) ? existing : new SourceOverride();
                    ov.Enabled = edited.Enabled;
                    ov.FailedAttemptsBeforeBan = edited.FailedAttemptsBeforeBan;
                    s.SourceOverrides[edited.Id] = ov;
                    return;
                }

                int index = s.CustomSources.FindIndex(c => c.Id == edited.Id);
                if (index >= 0)
                {
                    s.CustomSources[index] = edited;
                }
                else
                {
                    s.CustomSources.Add(edited);
                }
            }))
        {
            await RefreshAsync();
        }
    }
}
