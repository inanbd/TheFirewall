using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using TheFirewall.App.ViewModels;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Firewall;
using TheFirewall.Core.Geo;

namespace TheFirewall.App.Views.Dialogs;

public partial class PortEditorWindow : Window
{
    private readonly PortRule original;
    private readonly ObservableCollection<CountryInfo> countries = [];
    private readonly ToggleButton[] dayButtons;
    private bool ready;

    /// <param name="rule">The port to edit (a copy).</param>
    /// <param name="isNew">True when the port is not on the Ports page yet.</param>
    /// <param name="situation">What the port does today, if known (shown at the top).</param>
    public PortEditorWindow(PortRule rule, bool isNew, string? situation = null)
    {
        original = rule;
        InitializeComponent();
        dayButtons = [DayMon, DayTue, DayWed, DayThu, DayFri, DaySat, DaySun];
        Title = isNew ? "Add a port" : $"Edit {rule.Name}";
        HeaderText.Text = Title;
        if (!string.IsNullOrWhiteSpace(situation))
        {
            SituationText.Text = situation;
            SituationText.Visibility = Visibility.Visible;
        }

        NameBox.Text = rule.Name;
        PortsBox.Text = rule.Ports.Replace(",", ", ", StringComparison.Ordinal);
        ProtocolBox.SelectedItem = ProtocolBox.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (string)i.Tag == rule.Protocol.ToString()) ?? ProtocolBox.Items[0];
        AccessEveryone.IsChecked = rule.Access == PortAccess.Everyone;
        AccessRestricted.IsChecked = rule.Access == PortAccess.Restricted;
        AccessNobody.IsChecked = rule.Access == PortAccess.Nobody;
        AddressesBox.Text = string.Join(Environment.NewLine,
            rule.AllowedAddresses.Split([',', ';', '\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        CountryPicker.ItemsSource = Countries.All;
        foreach (var code in rule.AllowedCountries)
        {
            if (Countries.All.FirstOrDefault(c => c.Code.Equals(code, StringComparison.OrdinalIgnoreCase)) is { } country)
            {
                countries.Add(country);
            }
        }

        CountryList.ItemsSource = countries;

        var schedule = rule.Schedule;
        ScheduleBox.IsChecked = schedule.Enabled;
        foreach (var button in dayButtons)
        {
            button.IsChecked = schedule.HasDay(Enum.Parse<DayOfWeek>((string)button.Tag));
        }

        FromBox.Text = schedule.From;
        ToBox.Text = schedule.To;
        ScheduleHint.Text = $"Outside these hours the port is closed. Times use this computer's clock ({TimeZoneInfo.Local.DisplayName}). " +
                            "An end time earlier than the start runs past midnight; the same time means all day.";

        ready = true;
        Update();
        Loaded += (_, _) => (string.IsNullOrWhiteSpace(NameBox.Text) ? NameBox : PortsBox).Focus();
    }

    public PortRule Result { get; private set; } = new();

    private void OnChanged(object sender, RoutedEventArgs e) => Update();

    private PortRule Build()
    {
        var days = dayButtons.Where(b => b.IsChecked == true)
            .Aggregate(WeekDays.None, (all, b) => all | PortSchedule.ToFlag(Enum.Parse<DayOfWeek>((string)b.Tag)));
        var rule = original.Clone();
        rule.Name = NameBox.Text.Trim();
        rule.Ports = PortsBox.Text.Trim();
        rule.Protocol = Enum.Parse<RuleProtocol>((string)((ComboBoxItem)ProtocolBox.SelectedItem).Tag);
        rule.Access = AccessRestricted.IsChecked == true ? PortAccess.Restricted : AccessNobody.IsChecked == true ? PortAccess.Nobody : PortAccess.Everyone;
        rule.AllowedAddresses = string.Join(",", AddressesBox.Text.Split([',', ';', '\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        rule.AllowedCountries = [.. countries.Select(c => c.Code)];
        rule.Schedule = new PortSchedule { Enabled = ScheduleBox.IsChecked == true, Days = days, From = FromBox.Text.Trim(), To = ToBox.Text.Trim() };
        if (original.Access != rule.Access || original.Schedule.Enabled != rule.Schedule.Enabled)
        {
            // Changing who may connect ends a temporary opening.
            rule.OpenUntilUtc = null;
        }

        return rule;
    }

    private void Update()
    {
        if (!ready)
        {
            return;
        }

        var rule = Build();
        RestrictedPanel.IsEnabled = rule.Access == PortAccess.Restricted;
        RestrictedPanel.Opacity = RestrictedPanel.IsEnabled ? 1 : 0.5;
        SchedulePanel.Visibility = rule.Schedule.Enabled ? Visibility.Visible : Visibility.Collapsed;

        var ports = FirewallPlanner.TryNormalizePorts(rule.Ports, out var normalized, out _) && normalized.Length > 0
            ? $"{FirewallPlanner.PortProtocolName(rule.Protocol)} {normalized.Replace(",", ", ", StringComparison.Ordinal)}"
            : "(no port yet)";
        var schedule = rule.Schedule.Enabled
            ? $" Open {PortItem.DaysText(rule.Schedule.Days)} {rule.Schedule.From}–{rule.Schedule.To}, closed at other times."
            : string.Empty;
        PreviewText.Text = $"{(string.IsNullOrWhiteSpace(rule.Name) ? "This port" : rule.Name)} ({ports}): {PortItem.Describe(rule)}.{schedule}";

        ErrorText.Text = Validate(rule).FirstOrDefault() ?? string.Empty;
    }

    private static List<string> Validate(PortRule rule)
    {
        var settings = new FirewallSettings { ThreatFeeds = [] };
        var copy = rule.Clone();
        settings.Ports.Add(copy);
        SettingsStore.Normalize(settings);
        var prefix = $"Port '{(string.IsNullOrWhiteSpace(copy.Name) ? copy.Ports : copy.Name)}': ";
        return SettingsStore.Validate(settings).Select(e => e.Replace(prefix, string.Empty, StringComparison.Ordinal)).ToList();
    }

    private void OnAddCountry(object sender, RoutedEventArgs e)
    {
        var country = CountryPicker.SelectedItem as CountryInfo ??
                      Countries.All.FirstOrDefault(c => c.Name.Equals(CountryPicker.Text?.Trim(), StringComparison.CurrentCultureIgnoreCase) ||
                                                        c.Code.Equals(CountryPicker.Text?.Trim(), StringComparison.OrdinalIgnoreCase));
        if (country is not null && countries.All(c => c.Code != country.Code))
        {
            countries.Add(country);
        }

        CountryPicker.SelectedItem = null;
        CountryPicker.Text = string.Empty;
        Update();
    }

    private void OnRemoveCountry(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string code } && countries.FirstOrDefault(c => c.Code == code) is { } country)
        {
            countries.Remove(country);
            Update();
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

        var settings = new FirewallSettings { ThreatFeeds = [] };
        settings.Ports.Add(rule);
        SettingsStore.Normalize(settings);
        Result = settings.Ports[0];
        DialogResult = true;
    }
}
