using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace KeyShare;

/// <summary>
/// Brings back taskbar icons that Windows 11 sometimes loses after monitors
/// come and go (for example when a KVM switch moves the screens to another PC).
///
/// The manual fix is to open Taskbar settings and switch any option off and on
/// again, which makes the taskbar lay itself out afresh. This does the same with
/// "Show badges on taskbar apps": it flips the setting, tells Explorer, and puts
/// it back a moment later. The setting always ends where it started.
/// </summary>
internal static class TaskbarFixer
{
    private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    private const string Value = "TaskbarBadges";
    private static int _running;

    public static Task RefreshAsync(string reason) => Task.Run(() =>
    {
        if (Interlocked.Exchange(ref _running, 1) == 1) return; // one at a time
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(Key);
            object? original = key.GetValue(Value);
            int current = original is int v ? v : 1; // badges are on unless set otherwise
            Log.Info($"Refreshing the taskbar ({reason})");
            try
            {
                key.SetValue(Value, current == 0 ? 1 : 0, RegistryValueKind.DWord);
                Announce();
                Thread.Sleep(800);
            }
            finally
            {
                if (original is int) key.SetValue(Value, current, RegistryValueKind.DWord);
                else key.DeleteValue(Value, throwOnMissingValue: false);
                Announce();
            }
        }
        catch (Exception ex)
        {
            Log.Error("Refreshing the taskbar", ex);
        }
        finally
        {
            Interlocked.Exchange(ref _running, 0);
        }
    });

    /// <summary>Tells Explorer the taskbar settings changed, as the Settings app does.</summary>
    private static void Announce() =>
        SendMessageTimeout(new IntPtr(0xFFFF) /* HWND_BROADCAST */, 0x001A /* WM_SETTINGCHANGE */, IntPtr.Zero,
            "TraySettings", 0x0002 /* SMTO_ABORTIFHUNG */, 2000, out _);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr wParam, string lParam,
        uint flags, uint timeoutMs, out IntPtr result);
}
