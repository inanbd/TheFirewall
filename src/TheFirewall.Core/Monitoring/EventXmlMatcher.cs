using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using TheFirewall.Core.Configuration;

namespace TheFirewall.Core.Monitoring;

/// <summary>
/// Evaluates an event-log source's XPath/regex expressions against the XML of an event record.
/// Every non-optional expression must match and at least one must yield an IP address.
/// </summary>
public static class EventXmlMatcher
{
    /// <summary>Parses event XML (as returned by EventRecord.ToXml()) into a namespace-free navigator.</summary>
    public static XPathNavigator? CreateNavigator(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            return null;
        }

        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            var doc = XDocument.Load(reader);
            foreach (var element in doc.Descendants())
            {
                element.Name = element.Name.LocalName;
                element.Attributes().Where(a => a.IsNamespaceDeclaration || a.Name.Namespace != XNamespace.None).Remove();
            }

            return doc.CreateNavigator();
        }
        catch (XmlException)
        {
            return null;
        }
    }

    public static LoginEvent? Match(LogSourceDefinition source, string xml, DateTimeOffset now)
    {
        var navigator = CreateNavigator(xml);
        return navigator is null ? null : Match(source, navigator, now);
    }

    public static LoginEvent? Match(LogSourceDefinition source, XPathNavigator navigator, DateTimeOffset now)
    {
        if (source.Expressions.Count == 0)
        {
            return null;
        }

        var capture = new MatchCapture();
        var logParts = new List<string>();

        foreach (var expression in source.Expressions)
        {
            if (!EvaluateExpression(expression, navigator, capture, logParts))
            {
                if (!expression.Optional)
                {
                    return null;
                }
            }
        }

        if (capture.IPAddress is null)
        {
            return null;
        }

        var timestamp = capture.Timestamp ?? ReadSystemTime(navigator) ?? now;
        return new LoginEvent
        {
            IPAddress = capture.IPAddress,
            UserName = capture.UserName,
            Source = string.IsNullOrWhiteSpace(capture.Source) ? source.Source : capture.Source,
            SourceId = source.Id,
            Kind = source.EventKind,
            Timestamp = timestamp,
            LogText = capture.Log ?? string.Join(" | ", logParts),
            FailedAttemptsBeforeBan = source.FailedAttemptsBeforeBan,
        };
    }

    private static bool EvaluateExpression(EventXPathExpression expression, XPathNavigator navigator, MatchCapture capture, List<string> logParts)
    {
        XPathNodeIterator nodes;
        try
        {
            nodes = navigator.Select(expression.XPath);
        }
        catch (XPathException)
        {
            return false;
        }

        var regex = LoginRegex.Get(expression.Regex);
        while (nodes.MoveNext())
        {
            var current = nodes.Current;
            if (current is null)
            {
                continue;
            }

            if (regex is null)
            {
                return true;
            }

            var value = current.Value.Trim();
            System.Text.RegularExpressions.Match match;
            try
            {
                match = regex.Match(value);
            }
            catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
            {
                continue;
            }

            if (match.Success && capture.TryApply(match))
            {
                if (logParts.Count < 4 && match.Value.Length > 0)
                {
                    logParts.Add(match.Value.Length > 200 ? match.Value[..200] : match.Value);
                }

                return true;
            }
        }

        return false;
    }

    private static DateTimeOffset? ReadSystemTime(XPathNavigator navigator)
    {
        var node = navigator.SelectSingleNode("/Event/System/TimeCreated/@SystemTime");
        if (node is not null && DateTimeOffset.TryParse(node.Value, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal, out var time))
        {
            return time.ToUniversalTime();
        }

        return null;
    }
}
