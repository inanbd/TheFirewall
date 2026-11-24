using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using TheFirewall.Core.Ipc;
using TheFirewall.Core.Networking;

namespace TheFirewall.App.Views.Dialogs;

public partial class BanDialog : Window
{
    public BanDialog()
    {
        InitializeComponent();
        Loaded += (_, _) => AddressBox.Focus();
    }

    public BanRequest Request { get; private set; } = new();

    private void OnChanged(object sender, TextChangedEventArgs e)
    {
        var text = AddressBox.Text.Trim();
        bool valid = IPUtility.TryParseAddress(text, out _);
        OkButton.IsEnabled = valid;
        AddressError.Text = text.Length == 0 || valid ? string.Empty : "This is not a valid IPv4 or IPv6 address.";
        AddressError.Visibility = AddressError.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var tag = (DurationBox.SelectedItem as ComboBoxItem)?.Tag as string;
        Request = new BanRequest
        {
            IPAddress = IPUtility.NormalizeText(AddressBox.Text) ?? AddressBox.Text.Trim(),
            DurationMinutes = string.IsNullOrEmpty(tag) ? null : int.Parse(tag, CultureInfo.InvariantCulture),
            Reason = string.IsNullOrWhiteSpace(ReasonBox.Text) ? null : ReasonBox.Text.Trim(),
        };
        DialogResult = true;
    }
}
