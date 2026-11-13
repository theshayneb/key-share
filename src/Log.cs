using System.Collections.Concurrent;

namespace KeyShare;

/// <summary>
/// Tiny file log in %APPDATA%\KeyShare\log.txt, capped at ~1 MB. Writing
/// happens on a background thread: callers (including the input hooks) only
/// queue a line, so a slow disk or virus scanner can never hold up the mouse.
/// </summary>
internal static class Log
{
    public static string Dir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "KeyShare");
    private static readonly string FilePath = Path.Combine(Dir, "log.txt");
    private static readonly BlockingCollection<string> Queue = new(new ConcurrentQueue<string>(), 10_000);

    static Log()
    {
        var t = new Thread(WriteLoop) { IsBackground = true, Name = "log writer", Priority = ThreadPriority.BelowNormal };
        t.Start();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Flush();
    }

    public static void Info(string message) => Add("INFO", message);
    public static void Error(string context, Exception ex) => Add("ERROR", $"{context}: {ex}");

    private static void Add(string level, string message) =>
        Queue.TryAdd($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {level} {message}"); // drops lines rather than block if the disk is stuck

    private static void WriteLoop()
    {
        foreach (var line in Queue.GetConsumingEnumerable())
        {
            var batch = new List<string> { line };
            while (batch.Count < 500 && Queue.TryTake(out var more)) batch.Add(more);
            WriteBatch(batch);
        }
    }

    private static readonly object FileGate = new();

    private static void WriteBatch(List<string> lines)
    {
        try
        {
            lock (FileGate)
            {
                Directory.CreateDirectory(Dir);
                var fi = new FileInfo(FilePath);
                if (fi.Exists && fi.Length > 1_000_000) File.Move(FilePath, FilePath + ".old", true);
                File.AppendAllLines(FilePath, lines);
            }
        }
        catch
        {
            // Logging must never take the app down.
        }
    }

    /// <summary>Writes out whatever is queued (on exit, so the last lines aren't lost).</summary>
    public static void Flush()
    {
        var rest = new List<string>();
        while (Queue.TryTake(out var line)) rest.Add(line);
        if (rest.Count > 0) WriteBatch(rest);
    }
}
