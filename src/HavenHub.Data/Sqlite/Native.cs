using System.Reflection;
using System.Runtime.InteropServices;

// Only load native libraries from safe system directories (CA5392: guards against DLL planting).
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]

namespace HavenHub.Data.Sqlite;

/// <summary>
/// P/Invoke bindings to the operating system's SQLite 3 library (ADR-0001). Only the calls the data
/// layer needs are bound; every string crosses the boundary as NUL-terminated UTF-8.
/// </summary>
internal static class Native
{
    private const string Lib = "sqlite3";

    public const int OK = 0;
    public const int ROW = 100;
    public const int DONE = 101;
    public const int CONSTRAINT = 19;
    public const int BUSY = 5;

    public const int OPEN_READWRITE = 0x02;
    public const int OPEN_CREATE = 0x04;
    public const int OPEN_NOMUTEX = 0x8000;

    public const int INTEGER = 1;
    public const int FLOAT = 2;
    public const int TEXT = 3;
    public const int BLOB = 4;
    public const int NULL = 5;

    public static readonly IntPtr Transient = new(-1);

    static Native()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve);
    }

    private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? path)
    {
        if (name != Lib)
        {
            return IntPtr.Zero;
        }

        foreach (var candidate in new[] { "libsqlite3.so.0", "libsqlite3.so", "libsqlite3.dylib", "sqlite3" })
        {
            if (NativeLibrary.TryLoad(candidate, assembly, path, out var handle))
            {
                return handle;
            }
        }

        throw new DllNotFoundException("SQLite 3 was not found. Install libsqlite3 (e.g. apt install libsqlite3-0).");
    }

    [DllImport(Lib)] public static extern int sqlite3_open_v2(byte[] filename, out IntPtr db, int flags, IntPtr vfs);
    [DllImport(Lib)] public static extern int sqlite3_close_v2(IntPtr db);
    [DllImport(Lib)] public static extern int sqlite3_busy_timeout(IntPtr db, int ms);
    [DllImport(Lib)] public static extern IntPtr sqlite3_errmsg(IntPtr db);
    [DllImport(Lib)] public static extern int sqlite3_extended_errcode(IntPtr db);
    [DllImport(Lib)] public static extern int sqlite3_changes(IntPtr db);
    [DllImport(Lib)] public static extern long sqlite3_last_insert_rowid(IntPtr db);
    [DllImport(Lib)] public static extern IntPtr sqlite3_libversion();

    [DllImport(Lib)] public static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int nBytes, out IntPtr stmt, IntPtr tail);
    [DllImport(Lib)] public static extern int sqlite3_step(IntPtr stmt);
    [DllImport(Lib)] public static extern int sqlite3_reset(IntPtr stmt);
    [DllImport(Lib)] public static extern int sqlite3_clear_bindings(IntPtr stmt);
    [DllImport(Lib)] public static extern int sqlite3_finalize(IntPtr stmt);

    [DllImport(Lib)] public static extern int sqlite3_bind_parameter_index(IntPtr stmt, byte[] name);
    [DllImport(Lib)] public static extern int sqlite3_bind_int64(IntPtr stmt, int index, long value);
    [DllImport(Lib)] public static extern int sqlite3_bind_double(IntPtr stmt, int index, double value);
    [DllImport(Lib)] public static extern int sqlite3_bind_text(IntPtr stmt, int index, byte[] value, int nBytes, IntPtr destructor);
    [DllImport(Lib)] public static extern int sqlite3_bind_blob(IntPtr stmt, int index, byte[] value, int nBytes, IntPtr destructor);
    [DllImport(Lib)] public static extern int sqlite3_bind_null(IntPtr stmt, int index);

    [DllImport(Lib)] public static extern int sqlite3_column_count(IntPtr stmt);
    [DllImport(Lib)] public static extern IntPtr sqlite3_column_name(IntPtr stmt, int col);
    [DllImport(Lib)] public static extern int sqlite3_column_type(IntPtr stmt, int col);
    [DllImport(Lib)] public static extern long sqlite3_column_int64(IntPtr stmt, int col);
    [DllImport(Lib)] public static extern double sqlite3_column_double(IntPtr stmt, int col);
    [DllImport(Lib)] public static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
    [DllImport(Lib)] public static extern IntPtr sqlite3_column_blob(IntPtr stmt, int col);
    [DllImport(Lib)] public static extern int sqlite3_column_bytes(IntPtr stmt, int col);

    public static byte[] Utf8Z(string s)
    {
        var bytes = new byte[System.Text.Encoding.UTF8.GetByteCount(s) + 1];
        System.Text.Encoding.UTF8.GetBytes(s, bytes);
        return bytes;
    }
}
