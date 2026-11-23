using System.Runtime.InteropServices;

namespace HavenHub.Data.Sqlite;

/// <summary>Raised for any SQLite failure. <see cref="IsConstraint"/> marks UNIQUE/CHECK/FK violations.</summary>
public sealed class DbException : Exception
{
    public DbException()
    {
    }

    public DbException(string message)
        : base(message)
    {
    }

    public DbException(string message, Exception inner)
        : base(message, inner)
    {
    }

    public DbException(int code, string message)
        : base($"SQLite error {code}: {message}") => Code = code;

    public int Code { get; }

    public bool IsConstraint => (Code & 0xFF) == Native.CONSTRAINT;
}

/// <summary>One row of a query result, read by column name.</summary>
public sealed class Row
{
    private readonly Dictionary<string, object?> _values;

    internal Row(Dictionary<string, object?> values) => _values = values;

    public long Num(string col) => Convert.ToInt64(_values[col], System.Globalization.CultureInfo.InvariantCulture);

    public long? NumOrNull(string col) => _values[col] is null ? null : Num(col);

    public double Real(string col) => Convert.ToDouble(_values[col], System.Globalization.CultureInfo.InvariantCulture);

    public string Text(string col) => (string)_values[col]!;

    public string? TextOrNull(string col) => _values[col] as string;

    public byte[]? Blob(string col) => _values[col] as byte[];

    public bool Bool(string col) => Num(col) != 0;
}

/// <summary>
/// A single SQLite connection with a prepared-statement cache. Not thread-safe: <see cref="Database"/>
/// hands each connection to one caller at a time. All values are bound as parameters, never spliced
/// into SQL text, which rules out SQL injection by construction.
/// </summary>
public sealed class SqliteConnection : IDisposable
{
    private readonly Dictionary<string, IntPtr> _statements = new(StringComparer.Ordinal);
    private IntPtr _db;

    public SqliteConnection(string path)
    {
        var rc = Native.sqlite3_open_v2(Native.Utf8Z(path), out _db, Native.OPEN_READWRITE | Native.OPEN_CREATE | Native.OPEN_NOMUTEX, IntPtr.Zero);
        if (rc != Native.OK)
        {
            var msg = _db == IntPtr.Zero ? "open failed" : Error();
            _ = Native.sqlite3_close_v2(_db);
            throw new DbException(rc, msg);
        }

        Check(Native.sqlite3_busy_timeout(_db, 5000), Native.OK);
        Execute("PRAGMA foreign_keys = ON");
        Execute("PRAGMA journal_mode = WAL");
        Execute("PRAGMA synchronous = NORMAL");
    }

    public static string LibraryVersion => Marshal.PtrToStringUTF8(Native.sqlite3_libversion()) ?? "?";

    public long LastInsertRowId => Native.sqlite3_last_insert_rowid(_db);

    /// <summary>Run a statement; returns the number of rows changed.</summary>
    public int Execute(string sql, params (string Name, object? Value)[] args)
    {
        var stmt = Prepare(sql, args);
        try
        {
            int rc;
            while ((rc = Native.sqlite3_step(stmt)) == Native.ROW)
            {
                // Drain rows of statements such as PRAGMA that return results.
            }

            Check(rc, Native.DONE);
            return Native.sqlite3_changes(_db);
        }
        finally
        {
            Release(stmt);
        }
    }

    public List<T> Query<T>(string sql, Func<Row, T> map, params (string Name, object? Value)[] args)
    {
        var stmt = Prepare(sql, args);
        try
        {
            var result = new List<T>();
            var cols = Native.sqlite3_column_count(stmt);
            var names = new string[cols];
            for (var i = 0; i < cols; i++)
            {
                names[i] = Marshal.PtrToStringUTF8(Native.sqlite3_column_name(stmt, i)) ?? $"c{i}";
            }

            int rc;
            while ((rc = Native.sqlite3_step(stmt)) == Native.ROW)
            {
                var values = new Dictionary<string, object?>(cols, StringComparer.Ordinal);
                for (var i = 0; i < cols; i++)
                {
                    values[names[i]] = ReadColumn(stmt, i);
                }

                result.Add(map(new Row(values)));
            }

            Check(rc, Native.DONE);
            return result;
        }
        finally
        {
            Release(stmt);
        }
    }

    public T? QuerySingle<T>(string sql, Func<Row, T> map, params (string Name, object? Value)[] args)
    {
        var rows = Query(sql, map, args);
        return rows.Count == 0 ? default : rows[0];
    }

    /// <summary>Single integer result. The query must alias its column as <c>v</c>, e.g. <c>SELECT COUNT(*) AS v</c>.</summary>
    public long Scalar(string sql, params (string Name, object? Value)[] args) =>
        QuerySingle(sql, r => r.Num("v"), args);

    /// <summary>Run <paramref name="work"/> in one IMMEDIATE transaction; any exception rolls everything back.</summary>
    public T Transaction<T>(Func<SqliteConnection, T> work)
    {
        Execute("BEGIN IMMEDIATE");
        try
        {
            var result = work(this);
            Execute("COMMIT");
            return result;
        }
        catch
        {
            Execute("ROLLBACK");
            throw;
        }
    }

    public void Dispose()
    {
        foreach (var stmt in _statements.Values)
        {
            _ = Native.sqlite3_finalize(stmt); // finalize returns the last step's error, already reported
        }

        _statements.Clear();
        if (_db != IntPtr.Zero)
        {
            var rc = Native.sqlite3_close_v2(_db);
            _db = IntPtr.Zero;
            System.Diagnostics.Debug.Assert(rc == Native.OK, "all statements were finalized before close");
        }
    }

    private IntPtr Prepare(string sql, (string Name, object? Value)[] args)
    {
        ObjectDisposedException.ThrowIf(_db == IntPtr.Zero, this);
        if (!_statements.TryGetValue(sql, out var stmt))
        {
            var bytes = Native.Utf8Z(sql);
            Check(Native.sqlite3_prepare_v2(_db, bytes, bytes.Length, out stmt, IntPtr.Zero), Native.OK);
            _statements[sql] = stmt;
        }

        foreach (var (name, value) in args)
        {
            var index = Native.sqlite3_bind_parameter_index(stmt, Native.Utf8Z(name));
            if (index == 0)
            {
                throw new DbException($"Unknown SQL parameter {name}");
            }

            var rc = value switch
            {
                null => Native.sqlite3_bind_null(stmt, index),
                long l => Native.sqlite3_bind_int64(stmt, index, l),
                int i => Native.sqlite3_bind_int64(stmt, index, i),
                bool b => Native.sqlite3_bind_int64(stmt, index, b ? 1 : 0),
                double d => Native.sqlite3_bind_double(stmt, index, d),
                string s => BindText(stmt, index, s),
                byte[] blob => Native.sqlite3_bind_blob(stmt, index, blob, blob.Length, Native.Transient),
                Enum e => BindText(stmt, index, e.ToString()),
                _ => throw new DbException($"Unsupported parameter type {value.GetType().Name}"),
            };
            Check(rc, Native.OK);
        }

        return stmt;
    }

    private static int BindText(IntPtr stmt, int index, string s)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(s);
        return Native.sqlite3_bind_text(stmt, index, bytes, bytes.Length, Native.Transient);
    }

    private static void Release(IntPtr stmt)
    {
        // reset() repeats the last step's error code, which Check() has already turned into an exception.
        _ = Native.sqlite3_reset(stmt);
        _ = Native.sqlite3_clear_bindings(stmt);
    }

    private static object? ReadColumn(IntPtr stmt, int i) => Native.sqlite3_column_type(stmt, i) switch
    {
        Native.INTEGER => Native.sqlite3_column_int64(stmt, i),
        Native.FLOAT => Native.sqlite3_column_double(stmt, i),
        Native.TEXT => Marshal.PtrToStringUTF8(Native.sqlite3_column_text(stmt, i), Native.sqlite3_column_bytes(stmt, i)),
        Native.BLOB => ReadBlob(stmt, i),
        _ => null,
    };

    private static byte[] ReadBlob(IntPtr stmt, int i)
    {
        var length = Native.sqlite3_column_bytes(stmt, i);
        var bytes = new byte[length];
        if (length > 0)
        {
            Marshal.Copy(Native.sqlite3_column_blob(stmt, i), bytes, 0, length);
        }

        return bytes;
    }

    private string Error() => Marshal.PtrToStringUTF8(Native.sqlite3_errmsg(_db)) ?? "unknown error";

    private void Check(int rc, int expected)
    {
        if (rc != expected)
        {
            throw new DbException(Native.sqlite3_extended_errcode(_db), Error());
        }
    }
}
