using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace TheFirewall.App.Controls;

/// <summary>
/// Lightweight column chart with an optional line series, drawn directly with DrawingContext so it needs
/// no charting library. Hovering a column shows its value.
/// </summary>
public sealed class BarChart : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(nameof(Values), typeof(IList<long>), typeof(BarChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty LineValuesProperty = DependencyProperty.Register(nameof(LineValues), typeof(IList<long>), typeof(BarChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty LabelsProperty = DependencyProperty.Register(nameof(Labels), typeof(IList<string>), typeof(BarChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty BarBrushProperty = DependencyProperty.Register(nameof(BarBrush), typeof(Brush), typeof(BarChart),
        new FrameworkPropertyMetadata(Brushes.SteelBlue, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty LineBrushProperty = DependencyProperty.Register(nameof(LineBrush), typeof(Brush), typeof(BarChart),
        new FrameworkPropertyMetadata(Brushes.OrangeRed, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ForegroundProperty = TextElement.ForegroundProperty.AddOwner(typeof(BarChart),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender | FrameworkPropertyMetadataOptions.Inherits));

    public static readonly DependencyProperty GridBrushProperty = DependencyProperty.Register(nameof(GridBrush), typeof(Brush), typeof(BarChart),
        new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromArgb(40, 128, 128, 128)), FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ValueLabelProperty = DependencyProperty.Register(nameof(ValueLabel), typeof(string), typeof(BarChart),
        new FrameworkPropertyMetadata("failed logins"));

    public static readonly DependencyProperty LineLabelProperty = DependencyProperty.Register(nameof(LineLabel), typeof(string), typeof(BarChart),
        new FrameworkPropertyMetadata("bans"));

    private int hoverIndex = -1;

    public BarChart()
    {
        ToolTipService.SetInitialShowDelay(this, 0);
        ToolTipService.SetBetweenShowDelay(this, 0);
    }

    public IList<long>? Values
    {
        get => (IList<long>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public IList<long>? LineValues
    {
        get => (IList<long>?)GetValue(LineValuesProperty);
        set => SetValue(LineValuesProperty, value);
    }

    public IList<string>? Labels
    {
        get => (IList<string>?)GetValue(LabelsProperty);
        set => SetValue(LabelsProperty, value);
    }

    public Brush BarBrush
    {
        get => (Brush)GetValue(BarBrushProperty);
        set => SetValue(BarBrushProperty, value);
    }

    public Brush LineBrush
    {
        get => (Brush)GetValue(LineBrushProperty);
        set => SetValue(LineBrushProperty, value);
    }

    public Brush Foreground
    {
        get => (Brush)GetValue(ForegroundProperty);
        set => SetValue(ForegroundProperty, value);
    }

    public Brush GridBrush
    {
        get => (Brush)GetValue(GridBrushProperty);
        set => SetValue(GridBrushProperty, value);
    }

    public string ValueLabel
    {
        get => (string)GetValue(ValueLabelProperty);
        set => SetValue(ValueLabelProperty, value);
    }

    public string LineLabel
    {
        get => (string)GetValue(LineLabelProperty);
        set => SetValue(LineLabelProperty, value);
    }

    private const double AxisWidth = 36;
    private const double LabelHeight = 20;

    protected override void OnRender(DrawingContext dc)
    {
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(RenderSize));
        var values = Values;
        if (values is null || values.Count == 0 || ActualWidth < 60 || ActualHeight < 40)
        {
            return;
        }

        var line = LineValues;
        double max = Math.Max(1, Math.Max(values.Max(), line is { Count: > 0 } ? line.Max() : 0));
        max = NiceCeiling(max);

        var plot = new Rect(AxisWidth, 6, ActualWidth - AxisWidth, ActualHeight - LabelHeight - 6);
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var typeface = new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        var gridPen = new Pen(GridBrush, 1);
        gridPen.Freeze();

        // Horizontal grid lines and axis values.
        for (int i = 0; i <= 3; i++)
        {
            double y = plot.Bottom - (plot.Height * i / 3);
            dc.DrawLine(gridPen, new Point(plot.Left, Math.Round(y) + 0.5), new Point(plot.Right, Math.Round(y) + 0.5));
            var text = new FormattedText(Compact(max * i / 3), CultureInfo.CurrentCulture, FlowDirection.LeftToRight, typeface, 11, Foreground, dpi);
            dc.DrawText(text, new Point(plot.Left - text.Width - 6, y - (text.Height / 2)));
        }

        int count = values.Count;
        double slot = plot.Width / count;
        double barWidth = Math.Max(2, slot * 0.62);
        for (int i = 0; i < count; i++)
        {
            double h = plot.Height * values[i] / max;
            if (h <= 0)
            {
                continue;
            }

            double x = plot.Left + (i * slot) + ((slot - barWidth) / 2);
            var rect = new Rect(x, plot.Bottom - h, barWidth, h);
            double radius = Math.Min(3, Math.Min(barWidth / 2, h / 2));
            var brush = BarBrush;
            if (i == hoverIndex)
            {
                brush = brush.Clone();
                brush.Opacity = 0.75;
            }

            dc.DrawRoundedRectangle(brush, null, rect, radius, radius);
        }

        if (line is { Count: > 1 } && line.Count == count && line.Any(v => v > 0))
        {
            var pen = new Pen(LineBrush, 2) { LineJoin = PenLineJoin.Round };
            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                for (int i = 0; i < count; i++)
                {
                    var p = new Point(plot.Left + (i * slot) + (slot / 2), plot.Bottom - (plot.Height * line[i] / max));
                    if (i == 0)
                    {
                        ctx.BeginFigure(p, false, false);
                    }
                    else
                    {
                        ctx.LineTo(p, true, true);
                    }
                }
            }

            dc.DrawGeometry(null, pen, geometry);
            for (int i = 0; i < count; i++)
            {
                if (line[i] > 0)
                {
                    dc.DrawEllipse(LineBrush, null, new Point(plot.Left + (i * slot) + (slot / 2), plot.Bottom - (plot.Height * line[i] / max)), 3, 3);
                }
            }
        }

        // X axis labels: show a few evenly spaced ones so they never overlap.
        var labels = Labels;
        if (labels is { Count: > 0 } && labels.Count == count)
        {
            int step = Math.Max(1, (int)Math.Ceiling(count / Math.Max(1, plot.Width / 56)));
            for (int i = 0; i < count; i += step)
            {
                var text = new FormattedText(labels[i], CultureInfo.CurrentCulture, FlowDirection.LeftToRight, typeface, 11, Foreground, dpi);
                double x = plot.Left + (i * slot) + (slot / 2) - (text.Width / 2);
                dc.DrawText(text, new Point(Math.Max(plot.Left, Math.Min(x, plot.Right - text.Width)), plot.Bottom + 4));
            }
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var values = Values;
        if (values is null || values.Count == 0)
        {
            return;
        }

        double x = e.GetPosition(this).X - AxisWidth;
        double slot = (ActualWidth - AxisWidth) / values.Count;
        int index = x < 0 ? -1 : Math.Min(values.Count - 1, (int)(x / slot));
        if (index == hoverIndex)
        {
            return;
        }

        hoverIndex = index;
        if (index >= 0)
        {
            var label = Labels is { } l && l.Count == values.Count ? l[index] + ": " : string.Empty;
            var lineText = LineValues is { } lv && lv.Count == values.Count ? $", {lv[index]:N0} {LineLabel}" : string.Empty;
            ToolTip = $"{label}{values[index]:N0} {ValueLabel}{lineText}";
        }
        else
        {
            ToolTip = null;
        }

        InvalidateVisual();
    }

    protected override void OnMouseLeave(MouseEventArgs e)
    {
        base.OnMouseLeave(e);
        hoverIndex = -1;
        ToolTip = null;
        InvalidateVisual();
    }

    private static double NiceCeiling(double value)
    {
        if (value <= 3)
        {
            return 3;
        }

        double magnitude = Math.Pow(10, Math.Floor(Math.Log10(value)));
        foreach (var step in new[] { 1.5, 3, 6, 9, 12 })
        {
            if (step * magnitude >= value && (step * magnitude) % 3 == 0)
            {
                return step * magnitude;
            }
        }

        return Math.Ceiling(value / magnitude) * magnitude;
    }

    private static string Compact(double value) => value switch
    {
        >= 1_000_000 => (value / 1_000_000).ToString("0.#", CultureInfo.CurrentCulture) + "M",
        >= 10_000 => (value / 1_000).ToString("0", CultureInfo.CurrentCulture) + "k",
        >= 1_000 => (value / 1_000).ToString("0.#", CultureInfo.CurrentCulture) + "k",
        _ => value.ToString("0", CultureInfo.CurrentCulture),
    };
}
