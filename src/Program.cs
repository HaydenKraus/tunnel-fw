// «Тоннель FW»: запуск приложений только при включённом VPN + ограничение через брандмауэр Windows.
// Без аргументов открывается окно для создания ярлыков.
// С аргументами "<адаптер VPN>" "<цель>" работает как ярлык: запускает цель, только если VPN подключён.
// Дополнительно (опция в окне) создаёт правила брандмауэра: приложение может выходить в сеть
// только через выбранный VPN-адаптер. Без VPN — соединения нет вообще, даже если запустить .exe напрямую.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("Тоннель FW — приложения и правила брандмауэра")]
[assembly: AssemblyDescription("Управление приложениями и правилами Windows Firewall: доступ в сеть только через VPN.")]
[assembly: AssemblyProduct("Тоннель FW")]
[assembly: AssemblyCopyright("")]
[assembly: AssemblyVersion("3.1.0.0")]
[assembly: AssemblyFileVersion("3.1.0.0")]

public static class Program
{
    public const string AppName = "Тоннель FW";

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length == 2) return Gate(args[0], args[1]);
        bool rules = args.Length == 1 && string.Equals(args[0], "--rules", StringComparison.OrdinalIgnoreCase);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm(rules));
        return 0;
    }

    static int Gate(string adapter, string target)
    {
        if (VpnUp(adapter))
        {
            var psi = new ProcessStartInfo(target) { UseShellExecute = true };
            if (File.Exists(target)) psi.WorkingDirectory = Path.GetDirectoryName(target);
            Process.Start(psi);
            return 0;
        }
        MessageBox.Show(adapter + " не подключён.\nВключите VPN и запустите ярлык снова.", AppName,
            MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return 1;
    }

    public static bool VpnUp(string adapter)
    {
        return NetworkInterface.GetAllNetworkInterfaces().Any(n =>
            string.Equals(n.Name, adapter, StringComparison.OrdinalIgnoreCase) &&
            n.OperationalStatus == OperationalStatus.Up);
    }

    // ---- брандмауэр: сеть приложению ТОЛЬКО через выбранный VPN-адаптер ----
    // Идея: правила блокировки действуют на всех адаптерах, КРОМЕ VPN,
    // а разрешение — только на VPN. Блокирующие правила в Windows имеют приоритет,
    // поэтому на VPN-адаптере срабатывает только разрешение, а без VPN
    // единственный доступный путь (физический адаптер) закрыт.

    public static bool IsAdmin()
    {
        try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
        catch { return false; }
    }

    // Все адаптеры, на которых приложению запрещаем сеть (всё, кроме VPN и loopback).
    public static string[] FirewallAliases(string vpn)
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        !string.Equals(n.Name, vpn, StringComparison.OrdinalIgnoreCase))
            .Select(n => n.Name)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static bool HasAdapter(string name)
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Any(n => string.Equals(n.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    // Экранирование одиночных кавычек для строк PowerShell в одиночных кавычках.
    static string Ps(string s) { return "'" + (s ?? "").Replace("'", "''") + "'"; }

    static string BlockName(string program) { return "TunnelFW-B-" + Hash(program); }
    static string AllowName(string program) { return "TunnelFW-A-" + Hash(program); }

    public static string FirewallInstallBody(string program, string vpn, string[] other)
    {
        string b = BlockName(program), a = AllowName(program);
        var sb = new StringBuilder();
        sb.AppendLine("Remove-NetFirewallRule -DisplayName " + Ps(b) + " -ErrorAction SilentlyContinue");
        sb.AppendLine("Remove-NetFirewallRule -DisplayName " + Ps(a) + " -ErrorAction SilentlyContinue");
        if (other != null && other.Length > 0)
            sb.AppendLine("New-NetFirewallRule -DisplayName " + Ps(b) +
                " -Direction Outbound -Action Block -Program " + Ps(program) +
                " -InterfaceAlias @(" + string.Join(",", other.Select(Ps)) + ")" +
                " -Profile Any -Enabled True -Description " + Ps("Тоннель FW: запрет сети вне VPN — " + program) + " | Out-Null");
        sb.AppendLine("New-NetFirewallRule -DisplayName " + Ps(a) +
            " -Direction Outbound -Action Allow -Program " + Ps(program) +
            " -InterfaceAlias @(" + Ps(vpn) + ")" +
            " -Profile Any -Enabled True -Description " + Ps("Тоннель FW: сеть только через " + vpn) + " | Out-Null");
        return sb.ToString();
    }

    public static string FirewallRemoveBody(string program)
    {
        return "Remove-NetFirewallRule -DisplayName " + Ps(BlockName(program)) + " -ErrorAction SilentlyContinue\r\n" +
               "Remove-NetFirewallRule -DisplayName " + Ps(AllowName(program)) + " -ErrorAction SilentlyContinue";
    }

    // Запускает PowerShell с повышением прав (если нужно) и ждёт результат.
    public static string RunPs(string body)
    {
        string ps1 = Path.Combine(Path.GetTempPath(), "tunnel-fw-" + Guid.NewGuid().ToString("N") + ".ps1");
        string status = Path.Combine(Path.GetTempPath(), "tunnel-fw-" + Guid.NewGuid().ToString("N") + ".txt");
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("try {");
        sb.AppendLine(body);
        sb.AppendLine("  'OK' | Out-File -FilePath " + Ps(status) + " -Encoding ascii");
        sb.AppendLine("} catch {");
        sb.AppendLine("  ('ERROR: ' + $_.Exception.Message) | Out-File -FilePath " + Ps(status) + " -Encoding ascii");
        sb.AppendLine("}");
        File.WriteAllText(ps1, sb.ToString(), Encoding.UTF8);
        try
        {
            var psi = new ProcessStartInfo("powershell.exe")
            {
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + ps1 + "\"",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            if (!IsAdmin()) psi.Verb = "runas";
            Process p = Process.Start(psi);
            if (p != null) { try { p.WaitForExit(30000); } catch { } }
            for (int i = 0; i < 100 && !File.Exists(status); i++) Thread.Sleep(200);
            return File.Exists(status) ? File.ReadAllText(status).Trim() : "TIMEOUT";
        }
        catch (Exception ex) { return "ERROR: " + ex.Message; }
        finally
        {
            try { File.Delete(ps1); } catch { }
            try { File.Delete(status); } catch { }
        }
    }

    // ---- чтение, переключение и редактирование правил (версия 3) ----

    // Чтение правил не требует повышения прав.
    public static string RunPsRead(string body)
    {
        string ps1 = Path.Combine(Path.GetTempPath(), "tunnel-fw-r-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(ps1, body, Encoding.UTF8);
        try
        {
            var psi = new ProcessStartInfo("powershell.exe")
            {
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + ps1 + "\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            Process p = Process.Start(psi);
            string output = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(25000);
            return output;
        }
        catch { return ""; }
        finally { try { File.Delete(ps1); } catch { } }
    }

    static string Dec(string s)
    {
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(s ?? "")); }
        catch { return ""; }
    }

    public static List<FwRule> ReadFwRules()
    {
        const string script =
@"function E([string]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$s)) }
Get-NetFirewallRule -DisplayName 'TunnelFW-*' -ErrorAction SilentlyContinue | ForEach-Object {
  $r = $_
  $p = ''
  try { $p = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program } catch {}
  $a = @()
  try { $a = @($r | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias }) } catch {}
  [string]::Join(""`t"", @(
    (E $r.DisplayName), (E $p), (E ([string]$r.Action)), (E ([string]$r.Enabled)),
    (E ([string]::Join(';', $a))), (E ([string]$r.Description))
  ))
}";
        var result = new List<FwRule>();
        foreach (string line in RunPsRead(script).Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
        {
            string[] f = line.Split('\t');
            if (f.Length < 6) continue;
            result.Add(new FwRule
            {
                Name = Dec(f[0]),
                Program = Dec(f[1]),
                Action = Dec(f[2]),
                Enabled = string.Equals(Dec(f[3]), "True", StringComparison.OrdinalIgnoreCase),
                Interfaces = Dec(f[4]).Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries),
                Description = Dec(f[5])
            });
        }
        return result;
    }

    public static string FirewallSetEnabledBody(string program, bool enabled)
    {
        string verb = enabled ? "Enable" : "Disable";
        return verb + "-NetFirewallRule -DisplayName " + Ps(BlockName(program)) + " -ErrorAction SilentlyContinue\r\n" +
               verb + "-NetFirewallRule -DisplayName " + Ps(AllowName(program)) + " -ErrorAction SilentlyContinue";
    }

    public static string FirewallDeleteRuleBody(string name)
    {
        return "Remove-NetFirewallRule -DisplayName " + Ps(name) + " -ErrorAction SilentlyContinue";
    }

    public static string FirewallEditRuleBody(FwRule old, string program, string action, string[] interfaces, bool enabled)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Remove-NetFirewallRule -DisplayName " + Ps(old.Name) + " -ErrorAction SilentlyContinue");
        sb.AppendLine("New-NetFirewallRule -DisplayName " + Ps(old.Name) +
            " -Direction Outbound -Action " + (string.Equals(action, "Allow", StringComparison.OrdinalIgnoreCase) ? "Allow" : "Block") +
            " -Program " + Ps(program) +
            " -InterfaceAlias @(" + string.Join(",", interfaces.Select(Ps)) + ")" +
            " -Profile Any -Enabled " + (enabled ? "True" : "False") +
            " -Description " + Ps(old.Description) + " | Out-Null");
        if (!string.Equals(program, old.Program, StringComparison.OrdinalIgnoreCase))
        {
            string other = old.Name.StartsWith("TunnelFW-B-")
                ? "TunnelFW-A-" + old.Name.Substring(11) : "TunnelFW-B-" + old.Name.Substring(11);
            sb.AppendLine("$o = Get-NetFirewallRule -DisplayName " + Ps(other) + " -ErrorAction SilentlyContinue");
            sb.AppendLine("if ($o) {");
            sb.AppendLine("  $oi = @($o | Get-NetFirewallInterfaceFilter -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias })");
            sb.AppendLine("  $oa = [string]$o.Action; $od = [string]$o.Description; $oe = [string]$o.Enabled");
            sb.AppendLine("  Remove-NetFirewallRule -DisplayName " + Ps(other) + " -ErrorAction SilentlyContinue");
            sb.AppendLine("  New-NetFirewallRule -DisplayName " + Ps(other) + " -Direction Outbound -Action $oa -Program " + Ps(program) +
                " -InterfaceAlias $oi -Profile Any -Enabled $oe -Description $od | Out-Null");
            sb.AppendLine("}");
        }
        return sb.ToString();
    }

    public static void OpenFolder(string target)
    {
        try
        {
            if (target != null && target.StartsWith("shell:AppsFolder", StringComparison.OrdinalIgnoreCase))
                Process.Start("explorer.exe", "shell:AppsFolder");
            else if (Directory.Exists(target))
                Process.Start("explorer.exe", "\"" + target + "\"");
            else
                Process.Start("explorer.exe", "/select,\"" + (target ?? "") + "\"");
        }
        catch { }
    }

    public static bool IsExe(string t)
    {
        return !string.IsNullOrEmpty(t) && File.Exists(t) &&
               string.Equals(Path.GetExtension(t), ".exe", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsUrl(string t)
    {
        return t.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
               t.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
    }

    // Создаёт ярлык на рабочем столе, возвращает путь к нему.
    public static string CreateShortcut(string name, string target, string adapter)
    {
        string exe = typeof(Program).Assembly.Location;
        string dir = Path.GetDirectoryName(exe);
        string safe = new string(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c).ToArray()).Trim();
        string id = Hash(target);

        string ico = null;
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, "icons"));
            ico = Path.Combine(dir, "icons", id + ".ico");
            using (var bmp = GetIcon(target, 256)) { AddBadge(bmp); SaveIco(bmp, ico); }
        }
        catch { ico = null; } // без значка ярлык всё равно работает

        string lnk = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), safe + " (VPN).lnk");
        var link = (IShellLinkW)new CShellLink();
        link.SetPath(exe);
        link.SetArguments("\"" + adapter + "\" \"" + target + "\"");
        link.SetWorkingDirectory(dir);
        link.SetDescription(name + " — запуск только при включённом VPN (" + adapter + ")");
        if (ico != null) link.SetIconLocation(ico, 0);

        // Свой AppUserModelID, чтобы каждый ярлык закреплялся на панели задач отдельно.
        var key = new PROPERTYKEY { fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"), pid = 5 };
        var pv = new PROPVARIANT { vt = 31, p = Marshal.StringToCoTaskMemUni("Tunnel." + id) };
        var store = (IPropertyStore)link;
        store.SetValue(ref key, ref pv);
        store.Commit();
        Marshal.FreeCoTaskMem(pv.p);

        ((IPersistFile)link).Save(lnk, true);
        return lnk;
    }

    static string Hash(string s)
    {
        using (var md5 = MD5.Create())
            return BitConverter.ToString(md5.ComputeHash(Encoding.UTF8.GetBytes(s)), 0, 6).Replace("-", "");
    }

    public static Bitmap GetIcon(string target, int size)
    {
        string parse = target;
        if (IsUrl(target))
        {
            parse = Path.Combine(Path.GetTempPath(), "tunnel.url");
            File.WriteAllText(parse, "[InternetShortcut]\r\nURL=" + target + "\r\n");
        }
        IShellItemImageFactory f;
        SHCreateItemFromParsingName(parse, IntPtr.Zero, typeof(IShellItemImageFactory).GUID, out f);
        IntPtr hb;
        f.GetImage(new SIZE { cx = size, cy = size }, 0x1 | 0x4, out hb); // BIGGERSIZEOK | ICONONLY
        try
        {
            using (var raw = Image.FromHbitmap(hb))
            {
                var d = raw.LockBits(new Rectangle(0, 0, raw.Width, raw.Height), ImageLockMode.ReadOnly, raw.PixelFormat);
                try
                {
                    using (var argb = new Bitmap(d.Width, d.Height, d.Stride, PixelFormat.Format32bppArgb, d.Scan0))
                    {
                        var result = new Bitmap(size, size, PixelFormat.Format32bppArgb);
                        using (var g = Graphics.FromImage(result))
                        {
                            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                            g.DrawImage(argb, 0, 0, size, size);
                        }
                        return result;
                    }
                }
                finally { raw.UnlockBits(d); }
            }
        }
        finally { DeleteObject(hb); }
    }

    // Зелёная точка в углу: отличает VPN-ярлык от обычного.
    static void AddBadge(Bitmap bmp)
    {
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.FillEllipse(Brushes.White, 168, 168, 88, 88);
            using (var b = new SolidBrush(Color.FromArgb(22, 163, 74))) g.FillEllipse(b, 178, 178, 68, 68);
        }
    }

    static void SaveIco(Bitmap bmp, string path)
    {
        byte[] png;
        using (var ms = new MemoryStream()) { bmp.Save(ms, ImageFormat.Png); png = ms.ToArray(); }
        using (var w = new BinaryWriter(File.Create(path)))
        {
            w.Write((short)0); w.Write((short)1); w.Write((short)1);  // заголовок ICO, 1 картинка
            w.Write((byte)0); w.Write((byte)0); w.Write((byte)0); w.Write((byte)0); // 256x256
            w.Write((short)1); w.Write((short)32); w.Write(png.Length); w.Write(22);
            w.Write(png);
        }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    static extern void SHCreateItemFromParsingName(string path, IntPtr pbc,
        [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IShellItemImageFactory ppv);

    [DllImport("gdi32.dll")]
    static extern bool DeleteObject(IntPtr h);
}


// ---- COM-интерфейсы Windows ----
[ComImport, Guid("00021401-0000-0000-C000-000000000046")]
class CShellLink { }

[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
interface IShellLinkW
{
    void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder f, int cch, IntPtr pfd, int flags);
    void GetIDList(out IntPtr ppidl);
    void SetIDList(IntPtr pidl);
    void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int cch);
    void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string s);
    void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int cch);
    void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string s);
    void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int cch);
    void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string s);
    void GetHotkey(out short h);
    void SetHotkey(short h);
    void GetShowCmd(out int c);
    void SetShowCmd(int c);
    void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int cch, out int i);
    void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string s, int i);
    void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string s, int r);
    void Resolve(IntPtr hwnd, int flags);
    void SetPath([MarshalAs(UnmanagedType.LPWStr)] string s);
}

[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
interface IPropertyStore
{
    void GetCount(out uint c);
    void GetAt(uint i, out PROPERTYKEY k);
    void GetValue(ref PROPERTYKEY k, out PROPVARIANT v);
    void SetValue(ref PROPERTYKEY k, ref PROPVARIANT v);
    void Commit();
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
struct PROPERTYKEY { public Guid fmtid; public uint pid; }

[StructLayout(LayoutKind.Explicit, Size = 24)]
struct PROPVARIANT { [FieldOffset(0)] public ushort vt; [FieldOffset(8)] public IntPtr p; }

[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("bcc18b79-ba16-442f-80c4-8a59c30c463b")]
interface IShellItemImageFactory { void GetImage(SIZE size, int flags, out IntPtr phbm); }

[StructLayout(LayoutKind.Sequential)]
struct SIZE { public int cx, cy; }
