using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using TheFirewall.App.Services;
using TheFirewall.Core.Configuration;
using TheFirewall.Core.Ipc;

namespace TheFirewall.App.Views.Dialogs;

public partial class SourceEditorWindow : Window
{
    private readonly IFirewallClient client;
    private readonly LogSourceDefinition original;
    private readonly bool isBuiltIn;
    private readonly ObservableCollection<ExpressionRow> expressions = [];

    public SourceEditorWindow(IFirewallClient client, LogSourceDefinition definition, bool isBuiltIn, bool isNew)
    {
        this.client = client;
        original = definition;
        this.isBuiltIn = isBuiltIn;
        InitializeComponent();

        Title = isBuiltIn ? definition.Name : isNew ? "New login monitor" : "Edit login monitor";
        HeaderText.Text = Title;
        BuiltInBanner.Visibility = isBuiltIn ? Visibility.Visible : Visibility.Collapsed;

        NameBox.Text = definition.Name;
        SourceBox.Text = definition.Source;
        DescriptionBox.Text = definition.Description;
        KindEventLog.IsChecked = definition.Kind == LogSourceKind.EventLog;
        KindTextFile.IsChecked = definition.Kind == LogSourceKind.TextFile;
        EventKindBox.SelectedIndex = definition.EventKind == LoginEventKind.Successful ? 1 : 0;
        ThresholdBox.Text = definition.FailedAttemptsBeforeBan.ToString(CultureInfo.CurrentCulture);
        LogNameBox.Text = definition.LogName;
        QueryBox.Text = definition.Query;
        foreach (var e in definition.Expressions)
        {
            expressions.Add(new ExpressionRow { XPath = e.XPath, Regex = LoginRegexDisplay(e.Regex), Optional = e.Optional });
        }

        ExpressionsGrid.ItemsSource = expressions;
        PathMasksBox.Text = string.Join(Environment.NewLine, definition.PathMasks.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        RegexBox.Text = definition.Regex.Trim();
        TimestampBox.Text = definition.TimestampFormat;
        PollBox.Text = definition.PollIntervalSeconds.ToString(CultureInfo.CurrentCulture);
        EnabledBox.IsChecked = definition.Enabled;

        if (isBuiltIn)
        {
            foreach (var control in new Control[] { NameBox, SourceBox, DescriptionBox, KindEventLog, KindTextFile, EventKindBox, LogNameBox, QueryBox, PathMasksBox, RegexBox, TimestampBox, PollBox })
            {
                control.IsEnabled = false;
            }

            ExpressionsGrid.IsReadOnly = true;
            ExpressionsGrid.CanUserAddRows = false;
        }
        else if (!isNew)
        {
            KindEventLog.IsEnabled = KindTextFile.IsEnabled = false;
        }

        UpdateKind();
    }

    public LogSourceDefinition Result { get; private set; } = new();

    private static string LoginRegexDisplay(string regex) => regex.Trim();

    private void OnKindChanged(object sender, RoutedEventArgs e) => UpdateKind();

    private void UpdateKind()
    {
        if (EventLogPanel is null)
        {
            return;
        }

        bool eventLog = KindEventLog.IsChecked == true;
        EventLogPanel.Visibility = eventLog ? Visibility.Visible : Visibility.Collapsed;
        TextFilePanel.Visibility = eventLog ? Visibility.Collapsed : Visibility.Visible;
        SampleHint.Text = eventLog
            ? "Paste the XML of an event: in Event Viewer open the event, choose Details > XML View and copy everything."
            : "Paste a few lines from the log file to see what the expression picks up.";
    }

    private LogSourceDefinition Build()
    {
        var def = original.Clone();
        if (!isBuiltIn)
        {
            def.Name = NameBox.Text.Trim();
            def.Source = string.IsNullOrWhiteSpace(SourceBox.Text) ? "Custom" : SourceBox.Text.Trim();
            def.Description = DescriptionBox.Text.Trim();
            def.Category = "Custom";
            def.Kind = KindEventLog.IsChecked == true ? LogSourceKind.EventLog : LogSourceKind.TextFile;
            def.EventKind = EventKindBox.SelectedIndex == 1 ? LoginEventKind.Successful : LoginEventKind.Failed;
            def.LogName = LogNameBox.Text.Trim();
            def.Query = QueryBox.Text.Trim();
            def.Expressions = expressions.Where(e => !string.IsNullOrWhiteSpace(e.XPath))
                .Select(e => new EventXPathExpression { XPath = e.XPath!.Trim(), Regex = e.Regex ?? string.Empty, Optional = e.Optional }).ToList();
            def.PathMasks = PathMasksBox.Text.Trim();
            def.Regex = RegexBox.Text;
            def.TimestampFormat = TimestampBox.Text.Trim();
            def.PollIntervalSeconds = int.TryParse(PollBox.Text, NumberStyles.None, CultureInfo.CurrentCulture, out var poll) ? Math.Clamp(poll, 1, 3600) : 10;
        }

        def.FailedAttemptsBeforeBan = int.TryParse(ThresholdBox.Text, NumberStyles.None, CultureInfo.CurrentCulture, out var threshold) ? Math.Clamp(threshold, 0, 10_000) : 0;
        def.Enabled = EnabledBox.IsChecked == true;
        return def;
    }

    private async void OnTest(object sender, RoutedEventArgs e)
    {
        ResultsList.ItemsSource = null;
        if (string.IsNullOrWhiteSpace(SampleBox.Text))
        {
            TestStatus.Text = "Paste a sample first.";
            return;
        }

        TestStatus.Text = "Testing…";
        try
        {
            var result = await client.TestSourceAsync(new SourceTestRequest { Definition = Build(), Sample = SampleBox.Text });
            if (result.Error is not null)
            {
                TestStatus.Text = result.Error;
                return;
            }

            ResultsList.ItemsSource = result.Matches;
            TestStatus.Text = result.Matches.Count switch
            {
                0 => "No match. Check the expression and that the sample contains an IP address.",
                1 => "1 match:",
                var n => $"{n} matches:",
            };
        }
        catch (Exception ex)
        {
            TestStatus.Text = ex is System.IO.IOException ? "The service must be running to test expressions." : ex.Message;
        }
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var def = Build();
        if (!isBuiltIn)
        {
            var errors = SettingsStore.Validate(new FirewallSettings { ThreatFeeds = [], CustomSources = [def] });
            if (errors.Count > 0)
            {
                ErrorText.Text = string.Join(" ", errors);
                return;
            }
        }

        Result = def;
        DialogResult = true;
    }

    public sealed class ExpressionRow
    {
        public string? XPath { get; set; }

        public string? Regex { get; set; }

        public bool Optional { get; set; }
    }
}
