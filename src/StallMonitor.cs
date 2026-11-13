namespace KeyShare;

/// <summary>
/// Notices when a thread stops answering for more than a second, and logs how
/// long it was stuck. Purely diagnostic: it makes freezes show up in the log.
/// </summary>
internal static class StallMonitor
{
    /// <param name="post">Queues an action to run on the watched thread.</param>
    /// <param name="stopped">True once the thread is gone, which ends the watch.</param>
    public static void Watch(string name, Action<Action> post, Func<bool> stopped)
    {
        var t = new Thread(() =>
        {
            while (!stopped())
            {
                Thread.Sleep(2000);
                if (stopped()) return;
                long sent = Environment.TickCount64;
                using var answered = new ManualResetEventSlim();
                try { post(answered.Set); } catch { return; }
                if (answered.Wait(1000)) continue;
                Log.Info($"The {name} isn't responding…");
                while (!answered.Wait(5000)) { if (stopped()) return; }
                Log.Info($"The {name} was stuck for {(Environment.TickCount64 - sent) / 1000.0:0.0} s");
            }
        }) { IsBackground = true, Name = "stall monitor: " + name, Priority = ThreadPriority.BelowNormal };
        t.Start();
    }
}

/// <summary>Runs clipboard work on its own short-lived STA thread (the clipboard needs STA).</summary>
internal static class StaWorker
{
    /// <summary>
    /// Runs <paramref name="work"/> on a new STA thread. Reading the clipboard asks
    /// the app that copied to produce the data, which can be slow or hang; on its
    /// own thread that never holds up anything else. Gives up waiting after
    /// <paramref name="timeout"/> (the thread finishes or not in the background).
    /// </summary>
    public static Task<bool> Run(string what, Action work, TimeSpan timeout)
    {
        var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var t = new Thread(() =>
        {
            try { work(); done.TrySetResult(true); }
            catch (Exception ex) { Log.Error(what, ex); done.TrySetResult(false); }
        }) { IsBackground = true, Name = what };
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        return Task.Run(async () =>
        {
            var finished = await Task.WhenAny(done.Task, Task.Delay(timeout));
            if (finished == done.Task) return done.Task.Result;
            Log.Info($"{what}: still waiting after {timeout.TotalSeconds:0} s (the app that copied isn't answering); skipping it");
            return false;
        });
    }
}
