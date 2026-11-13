using System.ComponentModel;
using System.Diagnostics;
using System.ServiceProcess;
using System.Text;
using static KeyShare.UnlockNative;

namespace KeyShare;

/// <summary>
/// Optional Windows service that lets the other PC type on this PC's lock screen.
///
/// Normal apps can't send input to the lock screen; Windows only allows that
/// for SYSTEM. The service runs as SYSTEM and keeps one small helper running in
/// the signed-in user's session (<see cref="UnlockHelper"/>). While this PC is
/// locked, the KeyShare app hands the keys it receives to that helper instead
/// of typing them itself.
///
/// The service runs from a copy in Program Files, which only administrators can
/// change, so nobody can swap in a different program to run as SYSTEM.
/// </summary>
internal static class UnlockService
{
    public const string Name = "KeyShareUnlock";
    private static string InstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "KeyShare");

    // Each version goes in its own file, named after its contents (KeyShare-1a2b3c4d.exe),
    // and the service is pointed at it. Nothing ever has to overwrite or move a file
    // that's in use (by a helper, a virus scanner or anything else), and "is the
    // service up to date?" is a name comparison.
    private static readonly Lazy<string> MyFileName = new(() =>
    {
        using var f = File.OpenRead(Environment.ProcessPath!);
        return "KeyShare-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(f), 0, 4).ToLowerInvariant() + ".exe";
    });

    public static bool IsInstalled()
    {
        try { return ServiceController.GetServices().Any(s => s.ServiceName == Name); }
        catch { return false; }
    }

    /// <summary>The exe the installed service runs, from its registry entry; null if none.</summary>
    public static string? ServiceExe()
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{Name}");
        if (key?.GetValue("ImagePath") is not string image) return null;
        image = Environment.ExpandEnvironmentVariables(image.Trim());
        if (image.StartsWith('"'))
        {
            int end = image.IndexOf('"', 1);
            return end > 1 ? image[1..end] : null;
        }
        int space = image.IndexOf(" --", StringComparison.Ordinal);
        return space > 0 ? image[..space] : image;
    }

    private static string? _lastCheck;

    /// <summary>Does the installed service run a different version from this exe?</summary>
    public static bool IsOutOfDate()
    {
        try
        {
            if (!IsInstalled()) return false;
            string? exe = ServiceExe();
            bool outOfDate = exe == null || !string.Equals(Path.GetFileName(exe), MyFileName.Value, StringComparison.OrdinalIgnoreCase);
            string line = $"Lock-screen helper version check: service runs {Path.GetFileName(exe ?? "?")}, this is {MyFileName.Value} ({(outOfDate ? "out of date" : "up to date")})";
            if (line != _lastCheck) Log.Info(line); // only when it changes, so the 10-second re-check doesn't fill the log
            _lastCheck = line;
            return outOfDate;
        }
        catch (Exception ex)
        {
            Log.Error("Checking lock-screen helper version", ex);
            return false;
        }
    }

    /// <summary>Runs this exe with <paramref name="argument"/> as administrator (shows the UAC prompt) and waits.</summary>
    /// <returns>true on success, false if cancelled or failed.</returns>
    public static async Task<bool> RunElevatedAsync(string argument)
    {
        var psi = new ProcessStartInfo(Environment.ProcessPath!, argument) { UseShellExecute = true, Verb = "runas" };
        try
        {
            using var p = Process.Start(psi);
            if (p == null) { Log.Info($"Running {argument} as administrator: no process came back"); return false; }
            await p.WaitForExitAsync();
            Log.Info($"Running {argument} as administrator finished with code {p.ExitCode}");
            return p.ExitCode == 0;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            Log.Info($"Running {argument} as administrator: cancelled at the UAC prompt");
            return false;
        }
    }

    // ---- Install / uninstall (run elevated, from the command line) -------

    public static int InstallFromCommandLine()
    {
        try
        {
            StopIfRunning();
            StopLeftoverHelpers();
            Directory.CreateDirectory(InstallDir);

            string target = Path.Combine(InstallDir, MyFileName.Value);
            if (!File.Exists(target) || new FileInfo(target).Length != new FileInfo(Environment.ProcessPath!).Length)
            {
                string temp = target + ".partial";
                File.Copy(Environment.ProcessPath!, temp, overwrite: true);
                File.Move(temp, target, overwrite: true);
            }

            string binPath = $"binPath= \"\\\"{target}\\\" --service\"";
            if (IsInstalled()) Sc($"config {Name} {binPath} start= auto");
            else Sc($"create {Name} {binPath} start= auto DisplayName= \"KeyShare unlock helper\"");
            Sc($"description {Name} \"Lets KeyShare type on this PC's lock screen. Turn it off in KeyShare.\"");
            Sc($"failure {Name} reset= 86400 actions= restart/5000/restart/5000/restart/60000");

            DeleteOtherCopies(keep: target);

            using var sc = new ServiceController(Name);
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
            Log.Info($"Unlock service installed ({MyFileName.Value})");
            Log.Flush();
            return 0;
        }
        catch (Exception ex)
        {
            Log.Error("Installing unlock service", ex);
            Log.Flush();
            MessageBox.Show("Couldn't set up lock-screen typing:\n\n" + ex.Message, "KeyShare", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    public static int UninstallFromCommandLine()
    {
        try
        {
            StopIfRunning();
            StopLeftoverHelpers();
            if (IsInstalled()) Sc($"delete {Name}");
            DeleteOtherCopies(keep: null);
            try { Directory.Delete(InstallDir); } catch { } // fails harmlessly if a copy is waiting for a restart
            Log.Info("Unlock service removed");
            Log.Flush();
            return 0;
        }
        catch (Exception ex)
        {
            Log.Error("Removing unlock service", ex);
            Log.Flush();
            MessageBox.Show("Couldn't remove lock-screen typing:\n\n" + ex.Message, "KeyShare", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private static void StopIfRunning()
    {
        if (!IsInstalled()) return;
        using var sc = new ServiceController(Name);
        if (sc.Status is ServiceControllerStatus.Stopped) return;
        try { sc.Stop(); } catch (InvalidOperationException) { }
        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
    }

    /// <summary>Ends any KeyShare process still running from the install folder (a helper left behind).</summary>
    private static void StopLeftoverHelpers()
    {
        try { Process.EnterDebugMode(); } catch { } // lets an administrator end SYSTEM processes
        string dir = Path.GetFullPath(InstallDir).TrimEnd('\\') + "\\";
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id == Environment.ProcessId || !p.ProcessName.StartsWith("KeyShare", StringComparison.OrdinalIgnoreCase)) continue;
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { }
                if (path == null || !Path.GetFullPath(path).StartsWith(dir, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    p.Kill();
                    p.WaitForExit(5000);
                    Log.Info($"Ended a leftover lock-screen helper (process {p.Id})");
                }
                catch (Exception ex)
                {
                    Log.Error($"Ending leftover helper {p.Id}", ex);
                }
            }
        }
    }

    /// <summary>Removes older copies; any still in use are deleted by Windows at the next restart.</summary>
    private static void DeleteOtherCopies(string? keep)
    {
        if (!Directory.Exists(InstallDir)) return;
        foreach (var file in Directory.GetFiles(InstallDir, "KeyShare*.exe*"))
        {
            if (keep != null && string.Equals(Path.GetFullPath(file), Path.GetFullPath(keep), StringComparison.OrdinalIgnoreCase)) continue;
            try { File.Delete(file); }
            catch (Exception)
            {
                MoveFileEx(file, null, 4 /* MOVEFILE_DELAY_UNTIL_REBOOT */);
                Log.Info($"{Path.GetFileName(file)} is in use; Windows will delete it at the next restart");
            }
        }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string existing, string? replacement, int flags);

    private static void Sc(string arguments)
    {
        var psi = new ProcessStartInfo("sc.exe", arguments)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) throw new InvalidOperationException($"sc {arguments.Split(' ')[0]} failed ({p.ExitCode}): {output.Trim()}");
    }
}

/// <summary>The service itself: keeps a helper running in whichever session is on the screen.</summary>
internal sealed class UnlockServiceHost : ServiceBase
{
    private readonly ManualResetEvent _stop = new(false);
    private Thread? _thread;
    private Process? _helper;
    private uint _helperSession = NoSession;

    public UnlockServiceHost()
    {
        ServiceName = UnlockService.Name;
        CanStop = true;
    }

    protected override void OnStart(string[] args)
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "helper watchdog" };
        _thread.Start();
    }

    protected override void OnStop()
    {
        _stop.Set();
        _thread?.Join(5000);
        KillHelper();
    }

    private void Loop()
    {
        do
        {
            try
            {
                uint session = WTSGetActiveConsoleSessionId();
                bool valid = session != NoSession && session != 0;
                if (!valid || session != _helperSession || _helper == null || _helper.HasExited)
                {
                    KillHelper();
                    if (valid) Launch(session);
                }
            }
            catch (Exception ex)
            {
                Log.Error("Unlock service", ex);
            }
        }
        while (!_stop.WaitOne(3000));
    }

    /// <summary>Starts the helper as SYSTEM inside <paramref name="session"/>.</summary>
    private void Launch(uint session)
    {
        IntPtr token = IntPtr.Zero, dup = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out token)) throw new Win32Exception();
            if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out dup)) throw new Win32Exception();
            if (!SetTokenInformation(dup, TokenSessionId, ref session, sizeof(uint))) throw new Win32Exception();

            string exe = Environment.ProcessPath!;
            // The helper watches this process and quits when the service stops, so none are left behind.
            var cmd = new StringBuilder($"\"{exe}\" --unlock-helper {Environment.ProcessId}");
            var si = new STARTUPINFO { cb = System.Runtime.InteropServices.Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            if (!CreateProcessAsUser(dup, exe, cmd, IntPtr.Zero, IntPtr.Zero, false, CREATE_NO_WINDOW,
                    IntPtr.Zero, Path.GetDirectoryName(exe), ref si, out var pi))
                throw new Win32Exception();
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            _helper = Process.GetProcessById(pi.dwProcessId);
            _helperSession = session;
        }
        finally
        {
            if (dup != IntPtr.Zero) CloseHandle(dup);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    private void KillHelper()
    {
        try { if (_helper is { HasExited: false }) _helper.Kill(); } catch { }
        _helper?.Dispose();
        _helper = null;
        _helperSession = NoSession;
    }
}
