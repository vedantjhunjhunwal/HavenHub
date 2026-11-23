using System.Collections.Concurrent;
using HavenHub.Data.Sqlite;

namespace HavenHub.Data;

/// <summary>
/// Owns the SQLite database file. Writes go through one connection under a lock (SQLite allows one
/// writer at a time); reads use a pool of connections that run concurrently thanks to WAL mode.
/// </summary>
public sealed class Database : IDisposable
{
    private readonly string _path;
    private readonly SqliteConnection _writer;
    private readonly object _writeGate = new();
    private readonly ConcurrentBag<SqliteConnection> _readers = [];
    private bool _disposed;

    public Database(string path)
    {
        _path = path;
        _writer = new SqliteConnection(path);
        Migrations.Apply(_writer);
    }

    public string Path => _path;

    public T Write<T>(Func<SqliteConnection, T> work)
    {
        lock (_writeGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return work(_writer);
        }
    }

    public void Write(Action<SqliteConnection> work) => Write(c =>
    {
        work(c);
        return 0;
    });

    /// <summary>Run <paramref name="work"/> atomically: all of its statements commit together or not at all.</summary>
    public T Transaction<T>(Func<SqliteConnection, T> work) => Write(c => c.Transaction(work));

    public void Transaction(Action<SqliteConnection> work) => Transaction(c =>
    {
        work(c);
        return 0;
    });

    public T Read<T>(Func<SqliteConnection, T> work)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var conn = _readers.TryTake(out var pooled) ? pooled : new SqliteConnection(_path);
        try
        {
            return work(conn);
        }
        finally
        {
            _readers.Add(conn);
        }
    }

    public void Dispose()
    {
        lock (_writeGate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _writer.Dispose();
            while (_readers.TryTake(out var r))
            {
                r.Dispose();
            }
        }
    }
}
