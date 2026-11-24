using System.Diagnostics;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace TheFirewall.App.Views.Pages;

public partial class CountriesPage : UserControl
{
    public CountriesPage() => InitializeComponent();

    private void OnRequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
