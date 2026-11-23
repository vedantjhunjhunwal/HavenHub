# Static code analysis

## What runs

| Layer | Tool | Where | Fails the build? |
|---|---|---|---|
| Compiler | C# nullable reference analysis (`<Nullable>enable</Nullable>`) | every build | yes (warnings are errors) |
| Code quality | .NET analyzers, `AnalysisLevel=latest`, `AnalysisMode=Recommended` | every build | yes |
| Security | .NET security analyzers, `AnalysisModeSecurity=All` (CA2100 SQL injection, CA3xxx injection, CA5xxx crypto and P/Invoke rules...) | every build | yes |
| Reliability | `AnalysisModeReliability=All` (CA2000 dispose, CA2007, CA1806 ignored results...) | every build | yes |
| Style | `.editorconfig` rules with `EnforceCodeStyleInBuild` (unused usings, file-scoped namespaces, readonly fields) | every build | yes |
| Data flow / taint | GitHub CodeQL (`security-and-quality` queries) for C# and JavaScript | every push and PR, weekly | reported as code-scanning alerts |
| Dependencies | CI check that no project has a `PackageReference` (zero third-party packages, ADR-0001); Dependabot for GitHub Actions | CI | yes |

All settings live in `Directory.Build.props`, so no project can opt out.

## Findings fixed during development

The analyzers found real defects while HavenHub was being written. Each was fixed in code, not suppressed:

| Rule | Finding | Fix |
|---|---|---|
| CA5392 | P/Invoke to SQLite did not restrict the native library search path, allowing DLL planting | `[assembly: DefaultDllImportSearchPaths(SafeDirectories)]` |
| CA1806 | Return codes from `sqlite3_busy_timeout` and `sqlite3_close_v2` were ignored | Checked or deliberately discarded with a comment explaining why |
| CA2000 / CA1001 | WebSocket session owned a `SemaphoreSlim` but was never disposed; HTTP client factory leaked on exception | Sessions are disposed when their connection ends; the client owns and disposes its `HttpClient` |
| CA1822 | Stateless repository instances | Repositories became static classes |

## Documented suppressions

Each is in `.editorconfig` with its reason:

| Rule | Scope | Reason |
|---|---|---|
| CA2007 ConfigureAwait | all | ASP.NET Core and console apps have no synchronisation context |
| CA1848 LoggerMessage | all | Low log volume; readability preferred |
| CA1303 localisation | all | English-only tool output |
| CA1515 internal types | all | Types are shared with the test project |
| CA1724 namespace clash | all | Type names such as `Devices` |
| CA1062 null checks | all | Nullable reference analysis already enforces non-null arguments |
| CA5394 insecure Random | tools, tests | Seeded `Random` keeps load runs reproducible; secrets always come from the CSPRNG in the service |
| CA1707, CA1822 | tests | Sentence-style test names; tests are instance methods |
