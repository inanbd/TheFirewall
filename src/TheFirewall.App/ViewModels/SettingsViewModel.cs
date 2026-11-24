using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using TheFirewall.App.Services;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Ipc;
using TheFirewall.Core.Platform;

namespace TheFirewall.App.ViewModels;

public sealed partial class SettingsViewModel : PageViewModel
{
    public SettingsViewModel(AppServices services) : base(services)
    {
        Theme = services.Preferences.Theme;
    }

    public override string Key => "settings";

    public override string Title => "Settings";

    public override string Glyph => "";

    public IReadOnlyList<DurationUnit> Units => DurationField.Units;

    public IReadOnlyList<string> Themes { get; } = ["System", "Light", "Dark"];

    // ---- Ban policy
    [ObservableProperty] public partial int FailedAttemptsBeforeBan { get; set; }
    [ObservableProperty] public partial DurationField FailedAttemptWindow { get; set; } = new();
    public ObservableCollection<DurationField> BanDurations { get; } = [];
    [ObservableProperty] public partial DurationField RepeatOffenderMemory { get; set; } = new();
    [ObservableProperty] public partial bool ResetFailedAttemptsAfterUnban { get; set; }
    [ObservableProperty] public partial double MinimumSecondsBetweenAttempts { get; set; }
    [ObservableProperty] public partial bool ProcessInternalAddresses { get; set; }
    [ObservableProperty] public partial bool ClearFailedAttemptsOnSuccessfulLogin { get; set; }

    // ---- User names
    [ObservableProperty] public partial string AllowedUserNames { get; set; } = string.Empty;
    [ObservableProperty] public partial int AllowedUserNameEditDistance { get; set; }
    [ObservableProperty] public partial int FailedAttemptsBeforeBanForAllowedUserNames { get; set; }
    [ObservableProperty] public partial bool BanUnknownUserNamesImmediately { get; set; }
    [ObservableProperty] public partial string InstantBanUserNames { get; set; } = string.Empty;
    [ObservableProperty] public partial string TruncateUserNameChars { get; set; } = string.Empty;

    // ---- Notifications
    [ObservableProperty] public partial bool NotifyOnBan { get; set; }
    [ObservableProperty] public partial bool NotifyOnUnban { get; set; }
    [ObservableProperty] public partial bool NotifyOnSuccessfulLogin { get; set; }
    [ObservableProperty] public partial bool NotifyOnServiceProblems { get; set; }

    // ---- Actions
    [ObservableProperty] public partial string RunOnBan { get; set; } = string.Empty;
    [ObservableProperty] public partial string RunOnUnban { get; set; } = string.Empty;
    [ObservableProperty] public partial string RunOnSuccessfulLogin { get; set; } = string.Empty;

    // ---- Advanced
    [ObservableProperty] public partial string FirewallRulePrefix { get; set; } = string.Empty;
    [ObservableProperty] public partial int CycleSeconds { get; set; }
    [ObservableProperty] public partial int ActivityRetentionDays { get; set; }
    [ObservableProperty] public partial bool ClearBansOnStartup { get; set; }
    [ObservableProperty] public partial bool EnsureLogonFailureAuditing { get; set; }
    [ObservableProperty] public partial bool WhitelistOpensAllPorts { get; set; }

    // ---- App
    [ObservableProperty] public partial string Theme { get; set; } = "System";
    [ObservableProperty] public partial bool TrayAtSignIn { get; set; }
    [ObservableProperty] public partial bool TrayTaskRegistered { get; set; }
    [ObservableProperty] public partial string ServiceStateText { get; set; } = string.Empty;
    [ObservableProperty] public partial ServiceInstallState ServiceState { get; set; }

    public bool IsElevatedApp => Elevation.IsElevated;

    public string DataDirectory => Client.LastStatus?.DataDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TheFirewall");

    partial void OnThemeChanged(string value)
    {
        App.ApplyTheme(value);
        Services.Preferences.Theme = value;
        Services.Preferences.Save();
    }

    protected override async Task LoadAsync()
    {
        var s = await Services.Settings.LoadAsync(force: true);
        var p = s.BanPolicy;
        FailedAttemptsBeforeBan = p.FailedAttemptsBeforeBan;
        FailedAttemptWindow = DurationField.From(p.FailedAttemptWindow);
        BanDurations.Clear();
        foreach (var d in p.BanDurations)
        {
            BanDurations.Add(DurationField.From(d, allowPermanent: true));
        }

        RepeatOffenderMemory = DurationField.From(p.RepeatOffenderMemory);
        ResetFailedAttemptsAfterUnban = p.ResetFailedAttemptsAfterUnban;
        MinimumSecondsBetweenAttempts = p.MinimumTimeBetweenFailedAttempts.TotalSeconds;
        ProcessInternalAddresses = p.ProcessInternalAddresses;
        ClearFailedAttemptsOnSuccessfulLogin = p.ClearFailedAttemptsOnSuccessfulLogin;

        var u = s.UserNames;
        AllowedUserNames = string.Join(Environment.NewLine, u.AllowedUserNames);
        AllowedUserNameEditDistance = u.AllowedUserNameEditDistance;
        FailedAttemptsBeforeBanForAllowedUserNames = u.FailedAttemptsBeforeBanForAllowedUserNames;
        BanUnknownUserNamesImmediately = u.BanUnknownUserNamesImmediately;
        InstantBanUserNames = string.Join(Environment.NewLine, u.InstantBanUserNames);
        TruncateUserNameChars = u.TruncateUserNameChars;

        NotifyOnBan = s.Notifications.NotifyOnBan;
        NotifyOnUnban = s.Notifications.NotifyOnUnban;
        NotifyOnSuccessfulLogin = s.Notifications.NotifyOnSuccessfulLogin;
        NotifyOnServiceProblems = s.Notifications.NotifyOnServiceProblems;

        RunOnBan = s.Actions.RunOnBan;
        RunOnUnban = s.Actions.RunOnUnban;
        RunOnSuccessfulLogin = s.Actions.RunOnSuccessfulLogin;

        FirewallRulePrefix = s.General.FirewallRulePrefix;
        CycleSeconds = (int)s.General.CycleTime.TotalSeconds;
        ActivityRetentionDays = s.General.ActivityRetentionDays;
        ClearBansOnStartup = s.General.ClearBansOnStartup;
        EnsureLogonFailureAuditing = s.General.EnsureLogonFailureAuditing;
        WhitelistOpensAllPorts = s.General.WhitelistOpensAllPorts;

        await Task.Run(UpdateMachineState);
    }

    private void UpdateMachineState()
    {
        bool? task = null;
        if (!Client.IsDemo)
        {
            try
            {
                task = TrayStartupTask.GetEnabled();
            }
            catch (Exception)
            {
            }
        }

        var state = Client.IsDemo ? ServiceInstallState.Running : WindowsServiceControl.GetState();
        Application.Current.Dispatcher.Invoke(() =>
        {
            TrayTaskRegistered = task is not null;
            TrayAtSignIn = task == true;
            ServiceState = state;
            ServiceStateText = state switch
            {
                ServiceInstallState.Running => "Running",
                ServiceInstallState.Stopped => "Stopped",
                ServiceInstallState.Starting => "Starting…",
                ServiceInstallState.Stopping => "Stopping…",
                ServiceInstallState.NotInstalled => "Not installed",
                _ => "Unknown",
            };
        });
    }

    [RelayCommand]
    private void AddBanDuration()
    {
        var last = BanDurations.LastOrDefault()?.ToTimeSpan() ?? TimeSpan.FromDays(1);
        BanDurations.Add(DurationField.From(last <= TimeSpan.Zero ? TimeSpan.FromDays(30) : last * 4, allowPermanent: true));
    }

    [RelayCommand]
    private void RemoveBanDuration(DurationField? field)
    {
        if (field is not null && BanDurations.Count > 1)
        {
            BanDurations.Remove(field);
        }
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        static List<string> Lines(string text) =>
            text.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var durations = BanDurations.Select(d => d.ToTimeSpan()).ToList();
        if (await Services.Settings.SaveAsync(s =>
            {
                var p = s.BanPolicy;
                p.FailedAttemptsBeforeBan = FailedAttemptsBeforeBan;
                p.FailedAttemptWindow = FailedAttemptWindow.ToTimeSpan();
                p.BanDurations = durations;
                p.RepeatOffenderMemory = RepeatOffenderMemory.ToTimeSpan();
                p.ResetFailedAttemptsAfterUnban = ResetFailedAttemptsAfterUnban;
                p.MinimumTimeBetweenFailedAttempts = TimeSpan.FromSeconds(Math.Max(0, MinimumSecondsBetweenAttempts));
                p.ProcessInternalAddresses = ProcessInternalAddresses;
                p.ClearFailedAttemptsOnSuccessfulLogin = ClearFailedAttemptsOnSuccessfulLogin;

                var u = s.UserNames;
                u.AllowedUserNames = Lines(AllowedUserNames);
                u.AllowedUserNameEditDistance = AllowedUserNameEditDistance;
                u.FailedAttemptsBeforeBanForAllowedUserNames = FailedAttemptsBeforeBanForAllowedUserNames;
                u.BanUnknownUserNamesImmediately = BanUnknownUserNamesImmediately;
                u.InstantBanUserNames = Lines(InstantBanUserNames);
                u.TruncateUserNameChars = TruncateUserNameChars ?? string.Empty;

                s.Notifications.NotifyOnBan = NotifyOnBan;
                s.Notifications.NotifyOnUnban = NotifyOnUnban;
                s.Notifications.NotifyOnSuccessfulLogin = NotifyOnSuccessfulLogin;
                s.Notifications.NotifyOnServiceProblems = NotifyOnServiceProblems;

                s.Actions.RunOnBan = RunOnBan ?? string.Empty;
                s.Actions.RunOnUnban = RunOnUnban ?? string.Empty;
                s.Actions.RunOnSuccessfulLogin = RunOnSuccessfulLogin ?? string.Empty;

                s.General.FirewallRulePrefix = FirewallRulePrefix;
                s.General.CycleTime = TimeSpan.FromSeconds(CycleSeconds);
                s.General.ActivityRetentionDays = ActivityRetentionDays;
                s.General.ClearBansOnStartup = ClearBansOnStartup;
                s.General.EnsureLogonFailureAuditing = EnsureLogonFailureAuditing;
                s.General.WhitelistOpensAllPorts = WhitelistOpensAllPorts;
            }))
        {
            await RefreshAsync();
            UiDialogs.Info("Settings saved", "Your changes are in effect.");
        }
    }

    [RelayCommand]
    private Task DiscardAsync() => RefreshAsync();

    [RelayCommand]
    private async Task ToggleTrayAtSignInAsync()
    {
        var wanted = TrayAtSignIn;
        if (Client.IsDemo)
        {
            return;
        }

        if (!Elevation.IsElevated)
        {
            TrayAtSignIn = !wanted;
            UiDialogs.RequestElevation();
            return;
        }

        var ok = await Task.Run(() =>
        {
            string output;
            if (TrayStartupTask.GetEnabled() is null)
            {
                return wanted ? TrayStartupTask.Register(Environment.ProcessPath ?? "TheFirewall.exe", out output) : true;
            }

            return TrayStartupTask.SetEnabled(wanted, out output);
        });
        if (!ok)
        {
            UiDialogs.Error("Start at sign-in", "The sign-in task could not be changed.");
        }

        await Task.Run(UpdateMachineState);
    }

    [RelayCommand]
    private async Task ServiceActionAsync(string verb)
    {
        if (Client.IsDemo)
        {
            UiDialogs.Info("Demo mode", "Service controls are disabled in demo mode.");
            return;
        }

        if (verb == "uninstall" && !UiDialogs.Confirm("Uninstall service",
                "This stops TheFirewall, removes the Windows service and deletes all of TheFirewall's firewall rules. Continue?", destructive: true))
        {
            return;
        }

        string? error;
        if (verb is "start" or "install")
        {
            var result = await ServiceBootstrapper.EnsureRunningAsync();
            error = result.IsRunning || result.Outcome == EnsureServiceOutcome.Declined ? null : result.Message;
        }
        else
        {
            error = verb == "restart"
                ? await WindowsServiceControl.RunElevatedAsync("stop") ?? await WindowsServiceControl.RunElevatedAsync("start")
                : await WindowsServiceControl.RunElevatedAsync(verb);
        }
        if (error is not null)
        {
            UiDialogs.Error("TheFirewall service", error);
        }

        await Task.Run(UpdateMachineState);
    }

    [RelayCommand]
    private void OpenDataFolder()
    {
        if (Directory.Exists(DataDirectory))
        {
            Process.Start(new ProcessStartInfo(DataDirectory) { UseShellExecute = true });
        }
    }

    [RelayCommand]
    private async Task ExportAsync()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export settings",
            FileName = $"thefirewall-backup-{DateTime.Now:yyyyMMdd}.json",
            Filter = "TheFirewall backup (*.json)|*.json",
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var bundle = new ExportBundle
            {
                Version = Client.ServiceVersion ?? string.Empty,
                Settings = await Client.GetSettingsAsync(),
                Bans = await Client.GetBansAsync(),
            };
            await File.WriteAllTextAsync(dialog.FileName, JsonSerializer.Serialize(bundle, IpcJson.SettingsOptions));
            UiDialogs.Info("Export complete", $"Settings and {bundle.Bans.Count:N0} bans were saved to\n{dialog.FileName}");
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, "Export failed");
        }
    }

    [RelayCommand]
    private async Task ImportAsync()
    {
        if (!CanEdit)
        {
            UiDialogs.RequestElevation();
            return;
        }

        var dialog = new OpenFileDialog { Title = "Import settings", Filter = "TheFirewall backup (*.json)|*.json|All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        ExportBundle? bundle;
        try
        {
            var json = await File.ReadAllTextAsync(dialog.FileName);
            bundle = JsonSerializer.Deserialize<ExportBundle>(json, IpcJson.SettingsOptions);
            if (bundle?.Settings is null)
            {
                // Also accept a bare settings.json.
                var settings = JsonSerializer.Deserialize<FirewallSettings>(json, IpcJson.SettingsOptions);
                bundle = new ExportBundle { Settings = settings };
            }
        }
        catch (Exception ex)
        {
            UiDialogs.Error("Import failed", "The file is not a TheFirewall backup: " + ex.Message);
            return;
        }

        if (bundle?.Settings is null)
        {
            UiDialogs.Error("Import failed", "The file does not contain any settings.");
            return;
        }

        var banCount = bundle.Bans?.Count(b => b.IsBanned) ?? 0;
        if (!UiDialogs.Confirm("Import settings",
                $"Replace all current settings with the ones from this file?{(banCount > 0 ? $"\n\n{banCount:N0} bans from the file will also be imported." : string.Empty)}"))
        {
            return;
        }

        try
        {
            var result = await Client.SaveSettingsAsync(bundle.Settings);
            if (!result.Saved)
            {
                UiDialogs.ShowValidationErrors(result.Errors);
                return;
            }

            if (banCount > 0)
            {
                await Client.ImportBansAsync(new ImportBansRequest { Bans = bundle.Bans! });
            }

            Services.Settings.Invalidate();
            await RefreshAsync();
            UiDialogs.Info("Import complete", "The settings were imported and are in effect.");
        }
        catch (Exception ex)
        {
            UiDialogs.HandleError(ex, "Import failed");
        }
    }
}
