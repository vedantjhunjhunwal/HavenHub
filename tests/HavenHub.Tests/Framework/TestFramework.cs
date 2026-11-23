using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;

namespace HavenHub.Tests.Framework;

/// <summary>Marks a test and the requirement IDs (from docs/requirements.md) it verifies.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class TestAttribute(params string[] requirements) : Attribute
{
    public IReadOnlyList<string> Requirements { get; } = requirements;
}

public sealed class AssertionException(string message) : Exception(message)
{
    public AssertionException()
        : this("assertion failed")
    {
    }

    public AssertionException(string message, Exception inner)
        : this(message + ": " + inner.Message)
    {
    }
}

public static class Assert
{
    public static void True(bool condition, string what = "condition")
    {
        if (!condition)
        {
            throw new AssertionException($"expected true: {what}");
        }
    }

    public static void False(bool condition, string what = "condition") => True(!condition, "not " + what);

    public static void Equal<T>(T expected, T actual, string what = "value")
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new AssertionException($"{what}: expected <{expected}> but was <{actual}>");
        }
    }

    public static T NotNull<T>(T? value, string what = "value")
        where T : class => value ?? throw new AssertionException($"{what} was null");

    public static TException Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException e)
        {
            return e;
        }

        throw new AssertionException($"expected {typeof(TException).Name}");
    }

    public static void Contains(string expected, string? actual, string what = "text")
    {
        if (actual is null || !actual.Contains(expected, StringComparison.Ordinal))
        {
            throw new AssertionException($"{what}: expected to contain <{expected}> but was <{actual}>");
        }
    }
}

/// <summary>
/// Minimal test runner (the repo takes no third-party packages, see ADR-0001). Discovers [Test]
/// methods, runs each on a fresh instance, disposes it, and checks that every requirement has a test.
/// </summary>
public static partial class Runner
{
    public static async Task<int> RunAsync(string[] args)
    {
        var filter = args.FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));
        var tests = typeof(Runner).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance).Select(m => (Type: t, Method: m, Attr: m.GetCustomAttribute<TestAttribute>())))
            .Where(x => x.Attr is not null)
            .OrderBy(x => x.Type.Name, StringComparer.Ordinal).ThenBy(x => x.Method.Name, StringComparer.Ordinal)
            .ToList();

        var failures = new List<string>();
        var total = Stopwatch.StartNew();
        var ran = 0;
        foreach (var (type, method, _) in tests)
        {
            var name = $"{type.Name}.{method.Name}";
            if (filter is not null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            ran++;
            var sw = Stopwatch.StartNew();
            object? instance = null;
            try
            {
                instance = Activator.CreateInstance(type)!;
                if (method.Invoke(instance, null) is Task task)
                {
                    await task.WaitAsync(TimeSpan.FromSeconds(60));
                }

                Console.WriteLine($"  PASS  {name} ({sw.ElapsedMilliseconds} ms)");
            }
            catch (Exception e)
            {
                var inner = e is TargetInvocationException { InnerException: { } ie } ? ie : e;
                failures.Add($"{name}: {inner.GetType().Name}: {inner.Message}");
                Console.WriteLine($"  FAIL  {name}: {inner.GetType().Name}: {inner.Message}");
                Console.WriteLine(inner.StackTrace?.Split('\n').FirstOrDefault(l => l.Contains("HavenHub", StringComparison.Ordinal))?.Trim());
            }
            finally
            {
                switch (instance)
                {
                    case IAsyncDisposable ad:
                        await ad.DisposeAsync();
                        break;
                    case IDisposable d:
                        d.Dispose();
                        break;
                }
            }
        }

        Console.WriteLine();
        Console.WriteLine($"{ran - failures.Count} passed, {failures.Count} failed, {ran} total in {total.Elapsed.TotalSeconds:F1} s");

        var untested = 0;
        if (filter is null)
        {
            untested = CheckTraceability(tests.Select(t => (Name: $"{t.Type.Name}.{t.Method.Name}", Reqs: t.Attr!.Requirements)).ToList(), args.Contains("--matrix"));
        }

        return failures.Count == 0 && untested == 0 ? 0 : 1;
    }

    private static int CheckTraceability(List<(string Name, IReadOnlyList<string> Reqs)> tests, bool printMatrix)
    {
        var doc = Path.Combine(RepoRoot(), "docs", "requirements.md");
        var ids = ReqId().Matches(File.ReadAllText(doc)).Select(m => m.Value).Distinct().Order(StringComparer.Ordinal).ToList();
        var unknown = tests.SelectMany(t => t.Reqs).Except(ids).ToList();
        var missing = ids.Where(id => !tests.Any(t => t.Reqs.Contains(id))).ToList();
        if (printMatrix)
        {
            Console.WriteLine();
            Console.WriteLine("| Requirement | Tests |");
            Console.WriteLine("|---|---|");
            foreach (var id in ids)
            {
                var covering = tests.Where(t => t.Reqs.Contains(id)).Select(t => t.Name).ToList();
                Console.WriteLine($"| {id} | {covering.Count}: {string.Join(", ", covering)} |");
            }
        }

        Console.WriteLine($"Traceability: {ids.Count - missing.Count}/{ids.Count} requirements covered by tests");
        foreach (var id in missing)
        {
            Console.WriteLine($"  NO TEST for {id}");
        }

        foreach (var id in unknown)
        {
            Console.WriteLine($"  tag {id} is not in docs/requirements.md");
        }

        return missing.Count + unknown.Count;
    }

    public static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "HavenHub.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("repository root not found");
    }

    [GeneratedRegex(@"REQ-\d{2}")]
    private static partial Regex ReqId();
}
