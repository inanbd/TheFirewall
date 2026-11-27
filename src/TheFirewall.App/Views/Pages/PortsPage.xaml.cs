using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;

namespace TheFirewall.App.Views.Pages;

public partial class PortsPage : UserControl
{
    public PortsPage()
    {
        InitializeComponent();
    }

    /// <summary>"Open for…" shows its menu on a normal click.</summary>
    private void OnOpenForClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { ContextMenu: { } menu } button)
        {
            menu.DataContext = button.DataContext;
            menu.PlacementTarget = button;
            menu.Placement = PlacementMode.Bottom;
            menu.IsOpen = true;
        }
    }
}
