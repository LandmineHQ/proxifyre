using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows.Data;

namespace ProxiFyre;

internal sealed class ApplicationRulesManager
{
    private string _searchText = string.Empty;

    public ApplicationRulesManager()
    {
        View = CollectionViewSource.GetDefaultView(Rules);
        View.Filter = FilterRule;
        View.SortDescriptions.Add(new SortDescription(nameof(ConfiguredApplication.Kind), ListSortDirection.Ascending));
        View.SortDescriptions.Add(new SortDescription(nameof(ConfiguredApplication.Name), ListSortDirection.Ascending));
    }

    public ObservableCollection<ConfiguredApplication> Rules { get; } = [];

    public ICollectionView View { get; }

    public void SetSearchText(string? searchText)
    {
        _searchText = searchText ?? string.Empty;
        View.Refresh();
    }

    public void Clear()
    {
        Rules.Clear();
    }

    public bool AddRule(string value, out ConfiguredApplication app)
    {
        app = default!;
        if (!TryCreateApplication(value, out app) || Contains(app.Value))
        {
            return false;
        }

        Rules.Add(app);
        return true;
    }

    public bool AddLoadedRule(string value)
    {
        if (!TryCreateApplication(value, out var app) || Contains(app.Value))
        {
            return false;
        }

        Rules.Add(app);
        return true;
    }

    public bool AddApplicationPath(string filePath, out ConfiguredApplication app)
    {
        app = default!;
        if (!TryCreateApplicationPath(filePath, out app) || Contains(app.FilePath))
        {
            return false;
        }

        Rules.Add(app);
        return true;
    }

    public bool AddDirectoryPath(string directoryPath, out ConfiguredApplication app)
    {
        app = default!;
        if (!TryCreateDirectoryPath(directoryPath, out app) || Contains(app.Value))
        {
            return false;
        }

        Rules.Add(app);
        return true;
    }

    public bool Replace(ConfiguredApplication selected, ConfiguredApplication replacement)
    {
        if (string.Equals(selected.Value, replacement.Value, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (Contains(replacement.Value, selected))
        {
            return false;
        }

        var index = Rules.IndexOf(selected);
        if (index < 0)
        {
            return false;
        }

        Rules[index] = replacement;
        View.Refresh();
        return true;
    }

    public bool Remove(ConfiguredApplication selected)
    {
        return Rules.Remove(selected);
    }

    public IEnumerable<string> BuildApps()
    {
        foreach (var app in Rules
            .OrderBy(app => app.Kind)
            .ThenBy(app => app.Name, StringComparer.OrdinalIgnoreCase))
        {
            yield return app.Value;
        }
    }

    public bool Contains(string value)
    {
        return Contains(value, except: null);
    }

    public bool Contains(string value, ConfiguredApplication? except)
    {
        return Rules.Any(app =>
            !ReferenceEquals(app, except)
            && string.Equals(app.Value, value, StringComparison.OrdinalIgnoreCase));
    }

    public static bool TryCreateApplication(string value, out ConfiguredApplication app)
    {
        app = default!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (TryCreateApplicationPath(trimmed, out app))
        {
            return true;
        }

        if (TryCreateDirectoryPath(trimmed, out app))
        {
            return true;
        }

        app = ConfiguredApplication.CreateRule(trimmed);
        return true;
    }

    public static bool TryCreateApplicationPath(string value, out ConfiguredApplication app)
    {
        app = default!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (!trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!Path.IsPathFullyQualified(trimmed))
        {
            return false;
        }

        var fullPath = Path.GetFullPath(trimmed);
        app = ConfiguredApplication.CreateExecutable(fullPath, IconLoader.ExtractIcon(fullPath));
        return true;
    }

    public static bool TryCreateDirectoryPath(string value, out ConfiguredApplication app)
    {
        app = default!;
        if (!ProcessMatcher.TryNormalizeDirectoryPattern(value, out var directoryPath))
        {
            return false;
        }

        app = ConfiguredApplication.CreateDirectory(directoryPath);
        return true;
    }

    private bool FilterRule(object item)
    {
        return item is ConfiguredApplication app
            && FuzzyMatcher.IsMatch(_searchText, app.SearchText);
    }
}
