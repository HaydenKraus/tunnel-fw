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
[assembly: AssemblyVersion("3.0.1.0")]
[assembly: AssemblyFileVersion("3.0.1.0")]

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

class AppEntry
{
    public string Name, Target;
    public override string ToString() { return Name; }
}

// Одно правило брандмауэра, созданное Тоннель FW.
public class FwRule
{
    public string Name;
    public string Program;
    public string Action;      // Block / Allow
    public bool Enabled;
    public string[] Interfaces;
    public string Description;

    public bool IsBlock { get { return string.Equals(Action, "Block", StringComparison.OrdinalIgnoreCase); } }
    public string InterfaceText { get { return Interfaces == null ? "" : string.Join("; ", Interfaces); } }
    public override string ToString() { return Name; }
}

// Цвета: минимализм, чёрный и красный.
class Theme
{
    public Color Back, Surface, SurfaceHover, Text, Muted, Border, Accent, AccentHover, AccentDim, Select, Bad;
    public bool Dark = true;

    public static Theme Current()
    {
        return new Theme
        {
            Dark = true,
            Back = Color.FromArgb(10, 10, 10),
            Surface = Color.FromArgb(20, 20, 20),
            SurfaceHover = Color.FromArgb(30, 30, 30),
            Text = Color.FromArgb(242, 242, 242),
            Muted = Color.FromArgb(138, 138, 138),
            Border = Color.FromArgb(40, 40, 40),
            Accent = Color.FromArgb(225, 29, 46),
            AccentHover = Color.FromArgb(255, 51, 68),
            AccentDim = Color.FromArgb(74, 12, 18),
            Select = Color.FromArgb(58, 12, 18),
            Bad = Color.FromArgb(225, 29, 46)
        };
    }
}

// ---- оформление: анимации, курсор, переключатели ----

static class Ui
{
    public static Cursor Arrow, Hand;
    public static bool Effects = true;

    public static void InitCursors()
    {
        if (Arrow != null) return;
        try { Arrow = BuildCursor(false); } catch { Arrow = Cursors.Default; }
        try { Hand = BuildCursor(true); } catch { Hand = Cursors.Hand; }
    }

    static Cursor BuildCursor(bool hand)
    {
        int s = 32;
        using (var bmp = new Bitmap(s, s, PixelFormat.Format32bppArgb))
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            PointF[] pts = hand
                ? new[] { new PointF(11, 29), new PointF(11, 9), new PointF(14, 6), new PointF(17, 9), new PointF(17, 16),
                          new PointF(19, 14), new PointF(22, 17), new PointF(22, 26), new PointF(18, 30) }
                : new[] { new PointF(4, 2), new PointF(4, 25), new PointF(10, 19), new PointF(14, 29),
                          new PointF(19, 27), new PointF(15, 17), new PointF(23, 16) };
            // тень
            using (var sh = new SolidBrush(Color.FromArgb(170, 0, 0, 0)))
            {
                var shadow = pts.Select(p => new PointF(p.X + 1.4f, p.Y + 1.4f)).ToArray();
                g.FillPolygon(sh, shadow);
            }
            using (var fill = new SolidBrush(Color.White))
            using (var pen = new Pen(Color.FromArgb(225, 29, 46), 1.6f) { LineJoin = LineJoin.Round })
            {
                g.FillPolygon(fill, pts);
                g.DrawPolygon(pen, pts);
            }
            int hotX = hand ? 14 : 4, hotY = hand ? 8 : 2;
            return IconFromBitmap(bmp, hotX, hotY);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ICONINFO { public bool fIcon; public int xHotspot; public int yHotspot; public IntPtr hbmMask; public IntPtr hbmColor; }

    [DllImport("user32.dll")] static extern IntPtr CreateIconIndirect(ref ICONINFO piconinfo);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr hObject);

    static Cursor IconFromBitmap(Bitmap bmp, int hotX, int hotY)
    {
        int w = bmp.Width, h = bmp.Height;
        IntPtr hColor = bmp.GetHbitmap(Color.FromArgb(0));
        IntPtr hMask = IntPtr.Zero;
        Bitmap mask = new Bitmap(w, h, PixelFormat.Format1bppIndexed);
        try
        {
            var data = mask.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.WriteOnly, PixelFormat.Format1bppIndexed);
            try
            {
                int stride = data.Stride;
                byte[] row = new byte[Math.Abs(stride)];
                for (int y = 0; y < h; y++)
                {
                    Array.Clear(row, 0, row.Length);
                    for (int x = 0; x < w; x++)
                        if (bmp.GetPixel(x, y).A == 0)
                            row[x >> 3] |= (byte)(0x80 >> (x & 7));
                    Marshal.Copy(row, 0, new IntPtr(data.Scan0.ToInt64() + y * stride), row.Length);
                }
            }
            finally { mask.UnlockBits(data); }
            hMask = mask.GetHbitmap(Color.FromArgb(0));
            var ii = new ICONINFO { fIcon = false, xHotspot = hotX, yHotspot = hotY, hbmMask = hMask, hbmColor = hColor };
            IntPtr hIcon = CreateIconIndirect(ref ii);
            return new Cursor(hIcon);
        }
        finally
        {
            if (hMask != IntPtr.Zero) DeleteObject(hMask);
            DeleteObject(hColor);
            mask.Dispose();
        }
    }

    public static GraphicsPath Round(Rectangle r, int radius)
    {
        int d = radius * 2;
        var p = new GraphicsPath();
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }
}

// Кнопка с анимацией наведения, нажатия и «волной» по клику.
class AnimButton : Button
{
    readonly Theme th;
    readonly bool primary;
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 15 };
    float hover, press, ripple, rippleR;
    Point ripplePt;
    bool rippleOn;

    public AnimButton(Theme theme, bool isPrimary)
    {
        th = theme;
        primary = isPrimary;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.SupportsTransparentBackColor |
                 ControlStyles.ResizeRedraw, true);
        FlatStyle = FlatStyle.Flat;
        FlatAppearance.BorderSize = 0;
        BackColor = Color.Transparent;
        ForeColor = theme.Text;
        Cursor = Ui.Hand;
        timer.Tick += delegate
        {
            bool busy = false;
            if (hover < 1 && hoverOn) { hover = Math.Min(1, hover + 0.16f); busy = true; }
            if (hover > 0 && !hoverOn) { hover = Math.Max(0, hover - 0.16f); busy = true; }
            if (pressOn) { press = Math.Min(1, press + 0.25f); busy = true; }
            else if (press > 0) { press = Math.Max(0, press - 0.3f); busy = true; }
            if (rippleOn)
            {
                rippleR += 9f; ripple -= 0.045f; busy = true;
                if (ripple <= 0) rippleOn = false;
            }
            Invalidate();
            if (!busy) timer.Stop();
        };
    }

    bool hoverOn, pressOn;
    protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); hoverOn = true; timer.Start(); }
    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); hoverOn = false; pressOn = false; timer.Start(); }
    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        pressOn = true;
        if (Enabled && e.Button == MouseButtons.Left)
        {
            ripplePt = e.Location; rippleR = 2; ripple = 0.9f; rippleOn = true;
        }
        timer.Start();
    }
    protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); pressOn = false; timer.Start(); }
    protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent != null ? Parent.BackColor : th.Back);

        int shrink = (int)(press * 2);
        var r = new Rectangle(shrink, shrink, Width - 1 - shrink * 2, Height - 1 - shrink * 2);
        if (r.Width <= 0 || r.Height <= 0) return;
        int radius = Math.Min(9, r.Height / 2);

        Color fill = primary
            ? Blend(th.Accent, th.AccentHover, hover)
            : Blend(th.Surface, th.SurfaceHover, hover);
        if (!Enabled) fill = Blend(th.Surface, th.Back, 0.5f);

        using (var path = Ui.Round(r, radius))
        {
            if (primary && Enabled && hover > 0.02f)
                using (var glow = new Pen(Color.FromArgb((int)(70 * hover), th.Accent), 2f))
                    g.DrawPath(glow, path);
            using (var b = new SolidBrush(fill)) g.FillPath(b, path);
            Color border = primary ? fill : Blend(th.Border, th.Accent, hover * 0.9f);
            using (var p = new Pen(border, primary ? 0f : 1f)) if (!primary) g.DrawPath(p, path);

            if (rippleOn)
            {
                g.SetClip(path);
                using (var rb = new SolidBrush(Color.FromArgb((int)(70 * Math.Max(0, ripple)), Color.White)))
                    g.FillEllipse(rb, ripplePt.X - rippleR, ripplePt.Y - rippleR, rippleR * 2, rippleR * 2);
                g.ResetClip();
            }
        }

        Color text = !Enabled ? th.Muted : (primary ? Color.White : Blend(th.Text, Color.White, hover * 0.5f));
        TextRenderer.DrawText(g, Text, Font, r, text,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
    }

    static Color Blend(Color a, Color b, float t)
    {
        t = Math.Max(0, Math.Min(1, t));
        return Color.FromArgb(
            (int)(a.R + (b.R - a.R) * t),
            (int)(a.G + (b.G - a.G) * t),
            (int)(a.B + (b.B - a.B) * t));
    }
}

// Переключатель-пилюля с анимированным бегунком.
class ToggleSwitch : CheckBox
{
    readonly Theme th;
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 15 };
    float pos;

    public ToggleSwitch(Theme theme)
    {
        th = theme;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.SupportsTransparentBackColor |
                 ControlStyles.ResizeRedraw, true);
        FlatStyle = FlatStyle.Flat;
        BackColor = Color.Transparent;
        ForeColor = theme.Text;
        Cursor = Ui.Hand;
        timer.Tick += delegate
        {
            float want = Checked ? 1f : 0f;
            if (Math.Abs(pos - want) < 0.03f) { pos = want; timer.Stop(); }
            else pos += (want - pos) * 0.28f;
            Invalidate();
        };
    }

    protected override void OnCheckedChanged(EventArgs e)
    {
        base.OnCheckedChanged(e);
        timer.Start();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Parent != null ? Parent.BackColor : th.Back);

        int h = 20, w = 38, y = (Height - h) / 2;
        var track = new Rectangle(1, y, w, h);
        Color off = Color.FromArgb(55, 55, 55);
        Color on = th.Accent;
        Color trackColor = Color.FromArgb(
            (int)(off.R + (on.R - off.R) * pos),
            (int)(off.G + (on.G - off.G) * pos),
            (int)(off.B + (on.B - off.B) * pos));
        using (var path = Ui.Round(track, h / 2))
        using (var b = new SolidBrush(trackColor)) g.FillPath(b, path);

        int knob = h - 6;
        float kx = track.X + 3 + (w - knob - 6) * pos;
        using (var kb = new SolidBrush(Color.White))
            g.FillEllipse(kb, kx, y + 3, knob, knob);

        int tx = w + 10;
        var tr = new Rectangle(tx, 0, Width - tx, Height);
        TextRenderer.DrawText(g, Text, Font, tr, Enabled ? th.Text : th.Muted,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
    }
}


// Кастомная полоса вкладок с анимированным красным подчёркиванием.
class TabStrip : Control
{
    readonly Theme th;
    public string[] Titles = new string[0];
    int selected, hoverIndex = -1;
    float underX = -1, underTarget;
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 15 };
    Rectangle[] rects = new Rectangle[0];

    public TabStrip(Theme theme)
    {
        th = theme;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.SupportsTransparentBackColor |
                 ControlStyles.ResizeRedraw, true);
        BackColor = theme.Back;
        ForeColor = theme.Text;
        Font = new Font("Segoe UI Semibold", 10f);
        Cursor = Ui.Hand;
        Height = 42;
        timer.Tick += delegate
        {
            if (underX < 0) underX = underTarget;
            float d = underTarget - underX;
            if (Math.Abs(d) < 0.6f) { underX = underTarget; timer.Stop(); }
            else underX += d * 0.28f;
            Invalidate();
        };
    }

    public event EventHandler SelectedChanged;

    public int SelectedIndex
    {
        get { return selected; }
        set
        {
            if (value == selected || value < 0 || value >= Titles.Length) return;
            selected = value;
            underTarget = TabCenter(value);
            if (underX < 0) underX = underTarget;
            timer.Start();
            Invalidate();
            if (SelectedChanged != null) SelectedChanged(this, EventArgs.Empty);
        }
    }

    float TabCenter(int i)
    {
        float x = 16;
        for (int k = 0; k < i; k++) x += WidthOf(k) + 28;
        return x + WidthOf(i) / 2f;
    }

    int WidthOf(int i) { return TextRenderer.MeasureText(Titles[i], Font).Width; }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int h = Hit(e.X, e.Y);
        if (h != hoverIndex) { hoverIndex = h; Invalidate(); }
    }

    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); hoverIndex = -1; Invalidate(); }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        int h = Hit(e.X, e.Y);
        if (h >= 0) SelectedIndex = h;
    }

    int Hit(int x, int y)
    {
        for (int i = 0; i < rects.Length; i++)
            if (rects[i].Contains(x, y)) return i;
        return -1;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        g.Clear(th.Back);
        using (var pen = new Pen(th.Border)) g.DrawLine(pen, 0, Height - 1, Width, Height - 1);

        rects = new Rectangle[Titles.Length];
        float x = 16;
        for (int i = 0; i < Titles.Length; i++)
        {
            int w = WidthOf(i);
            rects[i] = new Rectangle((int)x, 0, w, Height - 1);
            Color c = i == selected ? th.Text : (i == hoverIndex ? Color.FromArgb(200, 200, 200) : th.Muted);
            TextRenderer.DrawText(g, Titles[i], Font, rects[i], c,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
            x += w + 28;
        }

        if (underX < 0) underX = TabCenter(selected);
        int idx = selected;
        int wsel = idx < Titles.Length ? WidthOf(idx) : 40;
        var ur = new RectangleF(underX - wsel / 2f, Height - 4, wsel, 3);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        using (var b = new SolidBrush(th.Accent)) g.FillRectangle(b, ur);
    }
}

// Слой эффектов курсора: красное свечение и кольцо при клике, поверх окна.
class CursorOverlay : Form
{
    readonly Theme th;
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 20 };
    float ringR, ringA;
    bool ringOn, shown, dirty = true;
    Point halo = new Point(-999, -999);

    public CursorOverlay(Theme theme)
    {
        th = theme;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        BackColor = Color.Black;
        Size = new Size(1, 1);
        timer.Tick += delegate { Frame(); };
    }

    protected override bool ShowWithoutActivation { get { return true; } }

    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            cp.ExStyle |= 0x80000 | 0x20 | 0x80 | 0x08000000; // LAYERED | TRANSPARENT | TOOLWINDOW | NOACTIVATE
            return cp;
        }
    }

    public void Pulse()
    {
        ringOn = true; ringR = 4; ringA = 0.85f; dirty = true;
        if (!timer.Enabled) timer.Start();
    }

    public void Follow(Rectangle screen)
    {
        if (Bounds != screen) { Bounds = screen; dirty = true; }
        if (!shown) { Show(); shown = true; }
        if (!timer.Enabled) timer.Start();
    }

    public void Stop()
    {
        timer.Stop();
        if (shown) { Hide(); shown = false; }
    }

    void Frame()
    {
        bool active = Ui.Effects && Owner != null && Owner.WindowState != FormWindowState.Minimized && Form.ActiveForm == Owner;
        Point sp = Cursor.Position;
        bool inside = active && ClientRectangle.Contains(PointToClient(sp));
        if (!inside && !ringOn)
        {
            if (shown) { Hide(); shown = false; }
            timer.Stop();
            return;
        }
        if (inside)
        {
            var np = PointToClient(sp);
            if (np != halo) { halo = np; dirty = true; }
        }
        if (ringOn) { ringR += 7f; ringA -= 0.06f; if (ringA <= 0) ringOn = false; }
        if (!dirty && !ringOn) return;
        dirty = false;
        Render(inside);
    }

    void Render(bool drawHalo)
    {
        int w = Math.Max(1, Width), h = Math.Max(1, Height);
        dirty = false;
        try
        {
            using (var bmp = new Bitmap(w, h, PixelFormat.Format32bppPArgb))
            {
                using (var g = Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.Clear(Color.Transparent);
                    if (drawHalo && Ui.Effects)
                    {
                        for (int i = 3; i >= 1; i--)
                        {
                            int r = 6 + i * 5;
                            int a = 26 - i * 5;
                            using (var b = new SolidBrush(Color.FromArgb(a, th.Accent)))
                                g.FillEllipse(b, halo.X - r, halo.Y - r, r * 2, r * 2);
                        }
                    }
                    if (ringOn)
                    {
                        int r = (int)ringR;
                        using (var p = new Pen(Color.FromArgb((int)(160 * Math.Max(0, ringA)), th.Accent), 2f))
                            g.DrawEllipse(p, halo.X - r, halo.Y - r, r * 2, r * 2);
                    }
                }
                Present(bmp);
            }
        }
        catch { Ui.Effects = false; timer.Stop(); if (shown) Hide(); shown = false; }
    }

    [StructLayout(LayoutKind.Sequential)] struct POINT { public int x, y; }
    [StructLayout(LayoutKind.Sequential)] struct SIZE2 { public int cx, cy; }
    [StructLayout(LayoutKind.Sequential)]
    struct BLENDFUNCTION { public byte BlendOp, BlendFlags, SourceConstantAlpha, AlphaFormat; }

    [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr hWnd);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);
    [DllImport("user32.dll")] static extern bool UpdateLayeredWindow(IntPtr hwnd, IntPtr hdcDst,
        ref POINT pptDst, ref SIZE2 psize, IntPtr hdcSrc, ref POINT pptSrc, int crKey, ref BLENDFUNCTION pblend, int dwFlags);
    [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr hDC);
    [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr hdc);
    [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr hDC, IntPtr h);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr h);

    void Present(Bitmap bmp)
    {
        IntPtr screen = GetDC(IntPtr.Zero);
        IntPtr mem = CreateCompatibleDC(screen);
        IntPtr hbmp = bmp.GetHbitmap(Color.FromArgb(0));
        IntPtr old = SelectObject(mem, hbmp);
        try
        {
            var size = new SIZE2 { cx = bmp.Width, cy = bmp.Height };
            var src = new POINT { x = 0, y = 0 };
            var dst = new POINT { x = Left, y = Top };
            var blend = new BLENDFUNCTION { BlendOp = 0, BlendFlags = 0, SourceConstantAlpha = 255, AlphaFormat = 1 };
            if (!UpdateLayeredWindow(Handle, screen, ref dst, ref size, mem, ref src, 0, ref blend, 2))
            {
                Ui.Effects = false;
                timer.Stop();
                if (shown) Hide();
                shown = false;
            }
        }
        finally
        {
            SelectObject(mem, old);
            DeleteObject(hbmp);
            DeleteDC(mem);
            ReleaseDC(IntPtr.Zero, screen);
        }
    }
}

class MainForm : Form, IMessageFilter
{
    readonly Theme th = Theme.Current();
    readonly Font fSmall = new Font("Segoe UI", 8f);
    readonly Font fSmallB = new Font("Segoe UI Semibold", 8.5f);
    readonly TextBox txtSearch = new TextBox(), txtUrl = new TextBox(), txtName = new TextBox();
    readonly ListBox lst = new ListBox();
    readonly ToolTip tip = new ToolTip();
    readonly ComboBox cmbVpn = new ComboBox();
    ToggleSwitch chkFirewall;
    readonly PictureBox pic = new PictureBox();
    readonly Label lblStatus = new Label(), lblTarget = new Label();
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 1000 };
    readonly Panel pageApps = new Panel(), pageRules = new Panel();
    TabStrip tabStrip;
    CursorOverlay overlay;
    readonly ListBox lstRules = new ListBox();
    readonly Label lblRulesStatus = new Label();
    readonly TextBox txtRuleProgram = new TextBox(), txtRuleIfaces = new TextBox();
    readonly ComboBox cmbRuleAction = new ComboBox(), cmbRuleVpn = new ComboBox();
    ToggleSwitch chkRuleEnabled;
    AnimButton btnToggleApp;
    volatile bool rulesLoading;

    List<FwRule> rules = new List<FwRule>();
    readonly Dictionary<string, List<FwRule>> rulesByProgram = new Dictionary<string, List<FwRule>>(StringComparer.OrdinalIgnoreCase);

    List<AppEntry> apps = new List<AppEntry>();
    readonly Dictionary<string, Bitmap> icons = new Dictionary<string, Bitmap>();
    Thread iconThread;
    DateTime lastLoad;
    string target;
    int hoverApp = -1, hoverRule = -1;

    public MainForm(bool startRules = false)
    {
        Text = Program.AppName + " — приложения и правила брандмауэра (v3.0.1)";
        Font = new Font("Segoe UI", 10f);
        ClientSize = new Size(460, 704);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = th.Back;
        ForeColor = th.Text;
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

        Ui.InitCursors();
        Cursor = Ui.Arrow;
        chkFirewall = new ToggleSwitch(th);
        chkRuleEnabled = new ToggleSwitch(th);

        Put(new Label { Text = Program.AppName, AutoSize = true, Font = new Font("Segoe UI Semibold", 18f) }, 18, 12);
        var sub = new Label
        {
            Text = "Сеть только через VPN. Ограничение — на уровне брандмауэра Windows.",
            ForeColor = th.Muted, Font = fSmall
        };
        sub.SetBounds(20, 52, 420, 20);
        Controls.Add(sub);

        lblStatus.SetBounds(20, 78, 420, 22);
        Controls.Add(lblStatus);

        Input(txtSearch, 20, 108, 376, "Поиск приложения");
        var btnRefresh = FlatButton("⟳", false);
        btnRefresh.SetBounds(404, 108, 36, 36);
        btnRefresh.Font = new Font("Segoe UI", 12f);
        tip.SetToolTip(btnRefresh, "Обновить список приложений");
        Controls.Add(btnRefresh);

        var listFrame = Frame(20, 152, 420, 244);
        lst.BorderStyle = BorderStyle.None;
        lst.BackColor = th.Surface;
        lst.ForeColor = th.Text;
        lst.DrawMode = DrawMode.OwnerDrawFixed;
        lst.ItemHeight = 38;
        lst.IntegralHeight = false;
        lst.SetBounds(1, 1, 418, 230);
        listFrame.Controls.Add(lst);

        var btnExe = FlatButton("Выбрать .exe…", false);
        btnExe.SetBounds(20, 410, 136, 36);
        Controls.Add(btnExe);
        Input(txtUrl, 164, 410, 276, "или ссылка https://…");

        pic.SetBounds(20, 462, 24, 24);
        pic.SizeMode = PictureBoxSizeMode.Zoom;
        Controls.Add(pic);
        lblTarget.SetBounds(50, 464, 236, 22);
        lblTarget.ForeColor = th.Muted;
        lblTarget.AutoEllipsis = true;
        lblTarget.Text = "Ничего не выбрано";
        Controls.Add(lblTarget);

        var btnFolder = FlatButton("Папка", false);
        btnFolder.SetBounds(292, 460, 76, 30);
        btnFolder.Font = fSmall;
        tip.SetToolTip(btnFolder, "Открыть папку выбранного приложения");
        btnFolder.Click += delegate { OpenAppFolder(); };
        Controls.Add(btnFolder);

        btnToggleApp = (AnimButton)FlatButton("Выкл.", false);
        btnToggleApp.SetBounds(372, 460, 68, 30);
        btnToggleApp.Font = fSmall;
        tip.SetToolTip(btnToggleApp, "Включить или выключить ограничение брандмауэра для приложения");
        btnToggleApp.Click += delegate { ToggleAppRestriction(); };
        Controls.Add(btnToggleApp);

        Input(txtName, 20, 496, 420, "Название ярлыка");

        chkFirewall.SetBounds(20, 540, 282, 34);
        chkFirewall.Text = "Только через VPN (брандмауэр)";
        chkFirewall.ForeColor = th.Text;
        chkFirewall.FlatStyle = FlatStyle.Flat;
        chkFirewall.Font = new Font("Segoe UI", 9f);
        chkFirewall.Checked = true;
        tip.SetToolTip(chkFirewall,
            "Создать правила брандмауэра: без VPN у программы нет сети, даже если запустить .exe напрямую. Понадобятся права администратора.");
        Controls.Add(chkFirewall);

        var btnFwRemove = FlatButton("Удалить правила", false);
        btnFwRemove.SetBounds(306, 540, 134, 30);
        btnFwRemove.Font = new Font("Segoe UI", 9f);
        tip.SetToolTip(btnFwRemove, "Удалить правила брандмауэра для выбранной программы");
        btnFwRemove.Click += delegate { RemoveFirewall(); };
        Controls.Add(btnFwRemove);

        Put(new Label { Text = "VPN-адаптер", AutoSize = true, ForeColor = th.Muted }, 20, 582);
        cmbVpn.SetBounds(124, 578, 316, 28);
        cmbVpn.FlatStyle = FlatStyle.Flat;
        cmbVpn.BackColor = th.Surface;
        cmbVpn.ForeColor = th.Text;
        Controls.Add(cmbVpn);

        var btnCreate = FlatButton("Создать ярлык на рабочем столе", true);
        btnCreate.SetBounds(20, 616, 420, 44);
        btnCreate.Font = new Font("Segoe UI Semibold", 10.5f);
        Controls.Add(btnCreate);
        AcceptButton = btnCreate;

        // Адаптеры: список обновляется при каждом открытии, введённое имя сохраняется даже без VPN.
        FillAdapters();
        cmbVpn.Text = cmbVpn.Items.Contains("AmneziaVPN") || !cmbVpn.Items.Cast<string>().Any() ? "AmneziaVPN" : GuessVpn();
        cmbVpn.DropDown += delegate { string t = cmbVpn.Text; FillAdapters(); cmbVpn.Text = t; };
        cmbVpn.TextChanged += delegate { UpdateStatus(); };

        // Статус VPN обновляется сам: раз в секунду и при любом изменении сети.
        timer.Tick += delegate { UpdateStatus(); };
        timer.Start();
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;
        UpdateStatus();

        // Приложения Windows: подтягиваются при открытии, при возврате в окно и по кнопке.
        LoadApps();
        Activated += delegate { if ((DateTime.Now - lastLoad).TotalSeconds > 5) LoadApps(); };
        btnRefresh.Click += delegate { LoadApps(); };

        txtSearch.TextChanged += delegate { Filter(); };
        lst.DrawItem += DrawApp;
        lst.MouseMove += delegate
        {
            int i = lst.IndexFromPoint(lst.PointToClient(Cursor.Position));
            if (i != hoverApp) { hoverApp = i; lst.Invalidate(); }
        };
        lst.MouseLeave += delegate { if (hoverApp != -1) { hoverApp = -1; lst.Invalidate(); } };
        lst.SelectedIndexChanged += delegate
        {
            var a = lst.SelectedItem as AppEntry;
            if (a != null) { SetTarget(a.Target, a.Name); RefreshToggleButton(); }
        };
        txtUrl.TextChanged += delegate
        {
            string u = txtUrl.Text.Trim();
            Uri uri;
            if (Program.IsUrl(u)) SetTarget(u, Uri.TryCreate(u, UriKind.Absolute, out uri) ? uri.Host : u);
        };
        btnExe.Click += delegate
        {
            using (var dlg = new OpenFileDialog { Filter = "Программы (*.exe)|*.exe" })
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    string desc = FileVersionInfo.GetVersionInfo(dlg.FileName).FileDescription;
                    SetTarget(dlg.FileName, string.IsNullOrWhiteSpace(desc) ? Path.GetFileNameWithoutExtension(dlg.FileName) : desc);
                    RefreshToggleButton();
                }
        };
        btnCreate.Click += delegate { Create(); };
        Shown += delegate { cmbVpn.Select(0, 0); txtSearch.Focus(); };

        // ---- шапка: кастомные вкладки и переключатель эффектов ----
        pageApps.BackColor = th.Back;
        pageRules.BackColor = th.Back;
        var holder = new Panel { Dock = DockStyle.Fill, BackColor = th.Back };
        foreach (var c in Controls.Cast<Control>().ToList()) holder.Controls.Add(c);
        pageApps.Controls.Add(holder);

        BuildRulesPage();

        pageApps.Dock = DockStyle.Fill;
        pageRules.Dock = DockStyle.Fill;
        pageRules.Visible = false;
        var body = new Panel { Dock = DockStyle.Fill, BackColor = th.Back };
        body.Controls.Add(pageApps);
        body.Controls.Add(pageRules);

        tabStrip = new TabStrip(th) { Titles = new[] { "Приложения", "Правила" }, Dock = DockStyle.Fill };
        var effects = new AnimButton(th, false) { Text = "Эффекты", Dock = DockStyle.Right, Width = 96, Font = fSmall };
        tip.SetToolTip(effects, "Красное свечение и кольцо вокруг курсора");
        effects.Click += delegate { ToggleEffects(effects); };

        var header = new Panel { Dock = DockStyle.Top, Height = 42, BackColor = th.Back };
        header.Controls.Add(tabStrip);
        header.Controls.Add(effects);

        Controls.Add(body);
        Controls.Add(header);

        tabStrip.SelectedChanged += delegate
        {
            bool rulesTab = tabStrip.SelectedIndex == 1;
            pageApps.Visible = !rulesTab;
            pageRules.Visible = rulesTab;
            if (rulesTab) LoadRules();
            else RefreshToggleButton();
        };

        // Слой эффектов курсора: поверх окна, клики проходят насквозь.
        try
        {
            overlay = new CursorOverlay(th) { Owner = this };
            Application.AddMessageFilter(this);
            Move += delegate { if (overlay != null) overlay.Follow(Bounds); };
            Resize += delegate { if (overlay != null) overlay.Follow(Bounds); };
            Activated += delegate { if (overlay != null) overlay.Follow(Bounds); };
            Deactivate += delegate { if (overlay != null) overlay.Stop(); };
        }
        catch { overlay = null; }

        LoadRules();
        RefreshToggleButton();
        if (startRules) tabStrip.SelectedIndex = 1;
    }

    // Переключение эффектов курсора из шапки.
    void ToggleEffects(AnimButton b)
    {
        Ui.Effects = !Ui.Effects;
        b.Text = Ui.Effects ? "Эффекты" : "Без эффектов";
        if (overlay == null) return;
        if (Ui.Effects) overlay.Follow(Bounds); else overlay.Stop();
    }

    // Перехват кликов по любым дочерним контролам для кольца у курсора.
    bool IMessageFilter.PreFilterMessage(ref Message m)
    {
        if (overlay == null || !Ui.Effects || Form.ActiveForm != this) return false;
        if (m.Msg == 0x200) { overlay.Follow(Bounds); return false; }   // WM_MOUSEMOVE — будим слой
        if (m.Msg == 0x201 && Bounds.Contains(Cursor.Position)) overlay.Pulse();
        return false;
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        int on = 1;
        DwmSetWindowAttribute(Handle, 20, ref on, 4);   // тёмный заголовок
        DwmSetWindowAttribute(Handle, 19, ref on, 4);   // тёмная рамка
        SetCaptionColor();
        SetWindowTheme(lst.Handle, "DarkMode_Explorer", null);
        SetWindowTheme(lstRules.Handle, "DarkMode_Explorer", null);
        SetWindowTheme(cmbVpn.Handle, "DarkMode_CFD", null);
        SetWindowTheme(cmbRuleAction.Handle, "DarkMode_CFD", null);
        SetWindowTheme(cmbRuleVpn.Handle, "DarkMode_CFD", null);
    }

    // Чёрный заголовок и красная рамка окна (Windows 11; на Windows 10 молча игнорируется).
    void SetCaptionColor()
    {
        try
        {
            int caption = 0x000A0A0A; // COLORREF BGR
            int text = 0x00F2F2F2;
            int borderCol = 0x002E1DE1;
            DwmSetWindowAttribute(Handle, 35, ref caption, 4);
            DwmSetWindowAttribute(Handle, 36, ref text, 4);
            DwmSetWindowAttribute(Handle, 34, ref borderCol, 4);
        }
        catch { }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
        try { Application.RemoveMessageFilter(this); } catch { }
        if (overlay != null) { try { overlay.Dispose(); } catch { } overlay = null; }
        base.OnFormClosed(e);
    }

    void OnNetworkChanged(object s, EventArgs e)
    {
        if (IsHandleCreated) BeginInvoke((Action)UpdateStatus);
    }

    // ---- элементы интерфейса ----

    void Put(Control c, int x, int y)
    {
        c.Location = new Point(x, y);
        Controls.Add(c);
    }

    Panel Frame(int x, int y, int w, int h)
    {
        var p = new Panel { BackColor = th.Surface };
        p.SetBounds(x, y, w, h);
        p.Paint += (s, e) => { using (var pen = new Pen(th.Border)) e.Graphics.DrawRectangle(pen, 0, 0, p.Width - 1, p.Height - 1); };
        Controls.Add(p);
        return p;
    }

    void Input(TextBox tb, int x, int y, int w, string cue)
    {
        var p = Frame(x, y, w, 36);
        tb.BorderStyle = BorderStyle.None;
        tb.BackColor = th.Surface;
        tb.ForeColor = th.Text;
        tb.SetBounds(10, 8, w - 20, 22);
        p.Controls.Add(tb);
        p.Click += delegate { tb.Focus(); };
        SendMessage(tb.Handle, 0x1501, (IntPtr)1, cue); // подсказка в пустом поле
    }

    Button FlatButton(string text, bool primary)
    {
        return new AnimButton(th, primary) { Text = text };
    }

    // ---- VPN ----

    void FillAdapters()
    {
        cmbVpn.Items.Clear();
        foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            if (n.NetworkInterfaceType != NetworkInterfaceType.Loopback && !cmbVpn.Items.Contains(n.Name)) cmbVpn.Items.Add(n.Name);
    }

    string GuessVpn()
    {
        var n = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(i =>
            i.Description.IndexOf("WireGuard", StringComparison.OrdinalIgnoreCase) >= 0 ||
            i.Description.IndexOf("TAP", StringComparison.OrdinalIgnoreCase) >= 0 ||
            i.Description.IndexOf("Wintun", StringComparison.OrdinalIgnoreCase) >= 0);
        return n != null ? n.Name : "";
    }

    void UpdateStatus()
    {
        string a = cmbVpn.Text.Trim();
        if (a.Length == 0) { lblStatus.Text = "●  Укажите VPN-адаптер"; lblStatus.ForeColor = th.Muted; return; }
        bool up = Program.VpnUp(a);
        lblStatus.Text = up ? "●  " + a + " — подключён" : "○  " + a + " — не подключён";
        lblStatus.ForeColor = up ? th.Accent : th.Muted;
    }

    // ---- приложения ----

    void LoadApps()
    {
        lastLoad = DateTime.Now;
        var list = new List<AppEntry>();
        try
        {
            dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application"));
            foreach (dynamic item in shell.NameSpace("shell:AppsFolder").Items())
                list.Add(new AppEntry { Name = item.Name, Target = "shell:AppsFolder\\" + item.Path });
        }
        catch { } // список не загрузился: остаются .exe и ссылка
        AddRuleApps(list);
        list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase));
        if (list.Select(a => a.Target).SequenceEqual(apps.Select(a => a.Target))) return; // ничего не изменилось
        apps = list;
        Filter();
        LoadIconsAsync();
    }

    // Приложения с правилами TunnelFW должны быть видны, даже если их нет в меню «Пуск».
    void AddRuleApps(List<AppEntry> list)
    {
        foreach (var kv in rulesByProgram)
        {
            if (!kv.Key.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (list.Any(a => string.Equals(a.Target, kv.Key, StringComparison.OrdinalIgnoreCase))) continue;
            string name = "";
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(kv.Key);
                name = vi.FileDescription;
            }
            catch { }
            if (string.IsNullOrWhiteSpace(name)) name = Path.GetFileNameWithoutExtension(kv.Key);
            list.Add(new AppEntry { Name = name, Target = kv.Key });
        }
    }

    void Filter()
    {
        string q = txtSearch.Text.Trim();
        var sel = lst.SelectedItem as AppEntry;
        lst.BeginUpdate();
        lst.Items.Clear();
        foreach (var a in apps)
            if (q.Length == 0 || a.Name.IndexOf(q, StringComparison.CurrentCultureIgnoreCase) >= 0) lst.Items.Add(a);
        if (sel != null)
            for (int i = 0; i < lst.Items.Count; i++)
                if (((AppEntry)lst.Items[i]).Target == sel.Target) { lst.SelectedIndex = i; break; }
        lst.EndUpdate();
    }

    // Значки грузятся в фоне, чтобы окно открывалось сразу.
    void LoadIconsAsync()
    {
        if (iconThread != null && iconThread.IsAlive) return;
        iconThread = new Thread(() =>
        {
            while (true)
            {
                List<string> todo;
                lock (icons) todo = apps.Select(a => a.Target).Where(t => !icons.ContainsKey(t)).ToList();
                if (todo.Count == 0) return;
                int n = 0;
                foreach (var t in todo)
                {
                    Bitmap b = null;
                    try { b = Program.GetIcon(t, 32); } catch { }
                    lock (icons) icons[t] = b;
                    if (++n % 12 == 0 && IsHandleCreated) BeginInvoke((Action)lst.Invalidate);
                }
                if (IsHandleCreated) BeginInvoke((Action)lst.Invalidate);
            }
        });
        iconThread.IsBackground = true;
        iconThread.SetApartmentState(ApartmentState.STA);
        iconThread.Start();
    }

    void DrawApp(object sender, DrawItemEventArgs e)
    {
        if (e.Index < 0) return;
        var a = (AppEntry)lst.Items[e.Index];
        bool selected = (e.State & DrawItemState.Selected) != 0;
        bool hover = e.Index == hoverApp && !selected;
        using (var b = new SolidBrush(selected ? th.AccentDim : (hover ? th.SurfaceHover : th.Surface)))
            e.Graphics.FillRectangle(b, e.Bounds);
        if (selected)
            using (var bar = new SolidBrush(th.Accent))
                e.Graphics.FillRectangle(bar, e.Bounds.X, e.Bounds.Y, 3, e.Bounds.Height);

        Bitmap ic;
        lock (icons) icons.TryGetValue(a.Target, out ic);
        if (ic != null)
        {
            e.Graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
            e.Graphics.DrawImage(ic, e.Bounds.X + 12, e.Bounds.Y + 7, 24, 24);
        }
        var r = new Rectangle(e.Bounds.X + 46, e.Bounds.Y, e.Bounds.Width - 74, e.Bounds.Height);
        TextRenderer.DrawText(e.Graphics, a.Name, lst.Font, r, th.Text,
            TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

        var rr = RulesFor(a.Target);
        if (rr != null && rr.Count > 0)
        {
            bool anyOn = rr.Any(x => x.Enabled);
            int cx = e.Bounds.Right - 18, cy = e.Bounds.Y + e.Bounds.Height / 2;
            if (anyOn)
            {
                using (var glow = new SolidBrush(Color.FromArgb(70, th.Accent)))
                    e.Graphics.FillEllipse(glow, cx - 4, cy - 8, 16, 16);
                using (var dot = new SolidBrush(th.Accent))
                    e.Graphics.FillEllipse(dot, cx, cy - 4, 8, 8);
            }
            else
            {
                using (var ring = new Pen(th.Muted, 1.4f))
                    e.Graphics.DrawEllipse(ring, cx, cy - 4, 8, 8);
            }
        }
    }

    void SetTarget(string t, string name)
    {
        target = t;
        txtName.Text = name;
        lblTarget.Text = name + "  ·  " + (t.StartsWith("shell:AppsFolder\\") ? "приложение Windows" : t);
        lblTarget.ForeColor = th.Text;
        var old = pic.Image;
        try { pic.Image = Program.GetIcon(t, 48); } catch { pic.Image = null; }
        if (old != null) old.Dispose();
    }

    void Create()
    {
        if (target == null) { Warn("Выберите приложение, .exe или вставьте ссылку."); return; }
        if (txtName.Text.Trim().Length == 0) { Warn("Введите название ярлыка."); return; }
        string vpn = cmbVpn.Text.Trim();
        if (vpn.Length == 0) { Warn("Укажите VPN-адаптер."); return; }

        bool fw = chkFirewall.Checked;
        if (fw)
        {
            if (!Program.IsExe(target))
            {
                Warn("Ограничение через брандмауэр работает только для программ .exe.\n" +
                     "Выберите программу кнопкой «Выбрать .exe…». Для ссылок и приложений Windows\n" +
                     "снимите галочку «Только через VPN (брандмауэр)» — там работает только проверка при запуске.");
                return;
            }
            if (!Program.HasAdapter(vpn))
            {
                Warn("VPN-адаптер «" + vpn + "» не найден в системе.\nВыберите адаптер из списка — иначе правила брандмауэра запретят сети приложению всегда.");
                return;
            }
        }

        try
        {
            string lnk = Program.CreateShortcut(txtName.Text.Trim(), target, vpn);
            string msg = "Ярлык «" + Path.GetFileNameWithoutExtension(lnk) + "» создан на рабочем столе.\n\n" +
                "Чтобы закрепить его на панели задач: правой кнопкой по ярлыку → «Показать дополнительные параметры» → «Закрепить на панели задач».";

            if (fw)
            {
                string[] others = Program.FirewallAliases(vpn);
                string res = Program.RunPs(Program.FirewallInstallBody(target, vpn, others));
                msg += res == "OK"
                    ? "\n\nБрандмауэр настроен: «" + Path.GetFileName(target) + "» сможет выходить в сеть только через «" + vpn +
                      "». Без VPN соединения нет, даже при прямом запуске .exe."
                    : "\n\nВНИМАНИЕ: не удалось создать правила брандмауэра (" + res + "). Ярлык создан, но жёсткой блокировки нет.";
            }
            if (fw) LoadRules();
            MessageBox.Show(this, msg, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { Warn("Не удалось создать ярлык: " + ex.Message); }
    }

    void RemoveFirewall()
    {
        if (!Program.IsExe(target)) { Warn("Сначала выберите программу .exe через «Выбрать .exe…»."); return; }
        string res = Program.RunPs(Program.FirewallRemoveBody(target));
        if (res == "OK") LoadRules();
        MessageBox.Show(this, res == "OK"
                ? "Правила брандмауэра для «" + Path.GetFileName(target) + "» удалены."
                : "Не удалось удалить правила: " + res,
            Program.AppName, MessageBoxButtons.OK,
            res == "OK" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
    }

    // ---- вкладка «Правила брандмауэра» (версия 3) ----

    void BuildRulesPage()
    {
        pageRules.BackColor = th.Back;
        Action<Control, int, int, int, int> put = (c, x, y, w, h) => { c.SetBounds(x, y, w, h); pageRules.Controls.Add(c); };

        var head = new Label { Text = "Правила Тоннель FW", AutoSize = false, ForeColor = th.Text,
            Font = new Font("Segoe UI Semibold", 14f) };
        put(head, 18, 10, 300, 26);
        lblRulesStatus.ForeColor = th.Muted;
        lblRulesStatus.Font = new Font("Segoe UI", 9f);
        put(lblRulesStatus, 20, 40, 420, 20);

        var frame = FrameOn(pageRules, 20, 66, 420, 214);
        lstRules.BorderStyle = BorderStyle.None;
        lstRules.BackColor = th.Surface;
        lstRules.ForeColor = th.Text;
        lstRules.DrawMode = DrawMode.OwnerDrawFixed;
        lstRules.ItemHeight = 34;
        lstRules.IntegralHeight = false;
        lstRules.SetBounds(1, 1, 418, 212);
        frame.Controls.Add(lstRules);
        lstRules.DrawItem += DrawRule;
        lstRules.MouseMove += delegate
        {
            int i = lstRules.IndexFromPoint(lstRules.PointToClient(Cursor.Position));
            if (i != hoverRule) { hoverRule = i; lstRules.Invalidate(); }
        };
        lstRules.MouseLeave += delegate { if (hoverRule != -1) { hoverRule = -1; lstRules.Invalidate(); } };
        lstRules.SelectedIndexChanged += delegate { FillRuleEdit(lstRules.SelectedItem as FwRule); };

        var bRefresh = FlatButton("⟳", false); bRefresh.Font = new Font("Segoe UI", 12f);
        tip.SetToolTip(bRefresh, "Обновить список правил");
        bRefresh.Click += delegate { LoadRules(); };
        put(bRefresh, 20, 286, 36, 30);

        var bOn = FlatButton("Включить", false); bOn.Font = new Font("Segoe UI", 9f);
        bOn.Click += delegate { ToggleSelectedRule(true); };
        put(bOn, 62, 286, 100, 30);

        var bOff = FlatButton("Выключить", false); bOff.Font = new Font("Segoe UI", 9f);
        bOff.Click += delegate { ToggleSelectedRule(false); };
        put(bOff, 168, 286, 100, 30);

        var bDel = FlatButton("Удалить", false); bDel.Font = new Font("Segoe UI", 9f);
        bDel.Click += delegate { DeleteRule(); };
        put(bDel, 274, 286, 100, 30);

        var bDir = FlatButton("Папка", false); bDir.Font = new Font("Segoe UI", 9f);
        tip.SetToolTip(bDir, "Открыть папку программы выбранного правила");
        bDir.Click += delegate
        {
            var r = lstRules.SelectedItem as FwRule;
            if (r != null) Program.OpenFolder(r.Program);
        };
        put(bDir, 380, 286, 60, 30);

        var editHead = new Label { Text = "Редактирование выбранного правила", ForeColor = th.Text,
            Font = new Font("Segoe UI Semibold", 10f) };
        put(editHead, 20, 324, 420, 22);

        var lblProg = new Label { Text = "Программа (.exe)", ForeColor = th.Muted, Font = new Font("Segoe UI", 9f) };
        put(lblProg, 20, 348, 300, 18);
        var pf = FrameOn(pageRules, 20, 368, 420, 36);
        txtRuleProgram.BorderStyle = BorderStyle.None;
        txtRuleProgram.BackColor = th.Surface; txtRuleProgram.ForeColor = th.Text;
        txtRuleProgram.Font = new Font("Segoe UI", 9f);
        txtRuleProgram.SetBounds(10, 8, 338, 22);
        pf.Controls.Add(txtRuleProgram);
        var bBrowse = FlatButton("…", false);
        bBrowse.Font = new Font("Segoe UI", 12f);
        bBrowse.SetBounds(356, 3, 60, 30);
        bBrowse.Click += delegate
        {
            using (var dlg = new OpenFileDialog { Filter = "Программы (*.exe)|*.exe" })
                if (dlg.ShowDialog(this) == DialogResult.OK) txtRuleProgram.Text = dlg.FileName;
        };
        pf.Controls.Add(bBrowse);

        put(new Label { Text = "Действие", ForeColor = th.Muted, Font = new Font("Segoe UI", 9f) }, 20, 412, 110, 18);
        put(new Label { Text = "VPN-адаптер", ForeColor = th.Muted, Font = new Font("Segoe UI", 9f) }, 140, 412, 160, 18);
        cmbRuleAction.Items.AddRange(new object[] { "Block", "Allow" });
        cmbRuleAction.DropDownStyle = ComboBoxStyle.DropDownList;
        cmbRuleAction.FlatStyle = FlatStyle.Flat;
        cmbRuleAction.BackColor = th.Surface; cmbRuleAction.ForeColor = th.Text;
        cmbRuleAction.Font = new Font("Segoe UI", 9f);
        put(cmbRuleAction, 20, 432, 112, 28);

        FillAdaptersInto(cmbRuleVpn);
        cmbRuleVpn.FlatStyle = FlatStyle.Flat;
        cmbRuleVpn.BackColor = th.Surface; cmbRuleVpn.ForeColor = th.Text;
        cmbRuleVpn.Font = new Font("Segoe UI", 9f);
        put(cmbRuleVpn, 140, 432, 160, 28);

        chkRuleEnabled.Text = "Включено";
        chkRuleEnabled.ForeColor = th.Text;
        chkRuleEnabled.FlatStyle = FlatStyle.Flat;
        chkRuleEnabled.Font = new Font("Segoe UI", 9f);
        put(chkRuleEnabled, 308, 434, 132, 24);

        put(new Label { Text = "Интерфейсы (через ';')", ForeColor = th.Muted, Font = new Font("Segoe UI", 9f) }, 20, 466, 300, 18);
        var ff = FrameOn(pageRules, 20, 486, 420, 36);
        txtRuleIfaces.BorderStyle = BorderStyle.None;
        txtRuleIfaces.BackColor = th.Surface; txtRuleIfaces.ForeColor = th.Text;
        txtRuleIfaces.Font = new Font("Segoe UI", 9f);
        txtRuleIfaces.SetBounds(10, 8, 400, 22);
        ff.Controls.Add(txtRuleIfaces);

        var bApply = FlatButton("Применить изменения", true);
        bApply.Font = new Font("Segoe UI", 9f);
        bApply.Click += delegate { ApplyRuleEdit(); };
        put(bApply, 20, 532, 200, 38);

        var bReset = FlatButton("Сбросить", false);
        bReset.Font = new Font("Segoe UI", 9f);
        bReset.Click += delegate { FillRuleEdit(lstRules.SelectedItem as FwRule); };
        put(bReset, 230, 532, 210, 38);

        var hint = new Label
        {
            Text = "Изменения применяются к выбранному правилу. При смене пути .exe парное правило обновляется автоматически. " +
                   "Чтобы снять ограничение полностью, используйте «Удалить правила» на вкладке «Приложения».",
            ForeColor = th.Muted, Font = new Font("Segoe UI", 8.5f)
        };
        put(hint, 20, 580, 420, 54);
    }

    Panel FrameOn(Control parent, int x, int y, int w, int h)
    {
        var p = new Panel { BackColor = th.Surface };
        p.SetBounds(x, y, w, h);
        p.Paint += (s, e) => { using (var pen = new Pen(th.Border)) e.Graphics.DrawRectangle(pen, 0, 0, p.Width - 1, p.Height - 1); };
        parent.Controls.Add(p);
        return p;
    }

    void FillAdaptersInto(ComboBox cb)
    {
        cb.Items.Clear();
        cb.Items.Add("— не менять —");
        foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            if (n.NetworkInterfaceType != NetworkInterfaceType.Loopback && !cb.Items.Contains(n.Name)) cb.Items.Add(n.Name);
        cb.SelectedIndex = 0;
    }

    void LoadRules()
    {
        if (rulesLoading) return;
        rulesLoading = true;
        lblRulesStatus.Text = "Загрузка правил…";
        ThreadPool.QueueUserWorkItem(delegate
        {
            List<FwRule> list = null;
            try { list = Program.ReadFwRules(); } catch { }
            try
            {
                if (!IsDisposed && IsHandleCreated) BeginInvoke((Action)delegate { ApplyRules(list); });
                else rulesLoading = false;
            }
            catch { rulesLoading = false; }
        });
    }

    void ApplyRules(List<FwRule> list)
    {
        rulesLoading = false;
        rules = list ?? new List<FwRule>();
        rulesByProgram.Clear();
        foreach (var r in rules)
            if (!string.IsNullOrEmpty(r.Program))
            {
                List<FwRule> l;
                if (!rulesByProgram.TryGetValue(r.Program, out l)) rulesByProgram[r.Program] = l = new List<FwRule>();
                l.Add(r);
            }
        LoadApps(); // подтянуть .exe, которых нет в меню «Пуск», но у которых есть правила
        RefreshRulesList();
        RefreshToggleButton();
    }

    void RefreshRulesList()
    {
        var cur = lstRules.SelectedItem as FwRule;
        lstRules.BeginUpdate();
        lstRules.Items.Clear();
        foreach (var r in rules) lstRules.Items.Add(r);
        if (cur != null)
            for (int i = 0; i < lstRules.Items.Count; i++)
                if (((FwRule)lstRules.Items[i]).Name == cur.Name) { lstRules.SelectedIndex = i; break; }
        if (lstRules.SelectedIndex < 0 && lstRules.Items.Count > 0) lstRules.SelectedIndex = 0;
        lstRules.EndUpdate();
        int on = rules.Count(r => r.Enabled);
        lblRulesStatus.Text = rules.Count == 0
            ? "Правил нет — создайте ярлык с ограничением на вкладке «Приложения»."
            : "Всего: " + rules.Count + "   ·   включено: " + on + "   ·   выключено: " + (rules.Count - on);
    }

    void DrawRule(object sender, DrawItemEventArgs e)
    {
        if (e.Index < 0) return;
        var r = (FwRule)lstRules.Items[e.Index];
        bool sel = (e.State & DrawItemState.Selected) != 0;
        bool hover = e.Index == hoverRule && !sel;
        using (var b = new SolidBrush(sel ? th.AccentDim : (hover ? th.SurfaceHover : th.Surface)))
            e.Graphics.FillRectangle(b, e.Bounds);
        if (sel)
            using (var bar = new SolidBrush(th.Accent))
                e.Graphics.FillRectangle(bar, e.Bounds.X, e.Bounds.Y, 3, e.Bounds.Height);

        Color sq = r.IsBlock ? th.Accent : th.Text;
        if (!r.Enabled) sq = th.Muted;
        using (var br = new SolidBrush(sq))
            e.Graphics.FillRectangle(br, e.Bounds.X + 10, e.Bounds.Y + 10, 13, 13);

        string prog = string.IsNullOrEmpty(r.Program) ? "?" : Path.GetFileName(r.Program);
        TextRenderer.DrawText(e.Graphics, prog + "   ·   " + r.Action, fSmallB,
            new Rectangle(e.Bounds.X + 30, e.Bounds.Y + 1, e.Bounds.Width - 36, 17),
            r.Enabled ? th.Text : th.Muted, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        string sub = (r.Enabled ? "вкл" : "выкл") + "   ·   " + r.InterfaceText + "   ·   " + r.Name;
        TextRenderer.DrawText(e.Graphics, sub, fSmall,
            new Rectangle(e.Bounds.X + 30, e.Bounds.Y + 17, e.Bounds.Width - 36, 16),
            th.Muted, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
    }

    void FillRuleEdit(FwRule r)
    {
        if (r == null)
        {
            txtRuleProgram.Text = ""; txtRuleIfaces.Text = "";
            cmbRuleAction.SelectedIndex = 0;
            cmbRuleVpn.SelectedIndex = 0;
            chkRuleEnabled.Checked = false;
            return;
        }
        txtRuleProgram.Text = r.Program ?? "";
        txtRuleIfaces.Text = r.InterfaceText;
        cmbRuleAction.SelectedItem = r.IsBlock ? "Block" : "Allow";
        cmbRuleVpn.SelectedIndex = 0;
        chkRuleEnabled.Checked = r.Enabled;
    }

    void ApplyRuleEdit()
    {
        var r = lstRules.SelectedItem as FwRule;
        if (r == null) { Warn("Сначала выберите правило в списке."); return; }
        string prog = txtRuleProgram.Text.Trim();
        if (!Program.IsExe(prog)) { Warn("Укажите существующий .exe."); return; }
        string action = cmbRuleAction.SelectedItem as string ?? "Block";
        string[] ifaces;
        string vpn = cmbRuleVpn.SelectedItem as string;
        if (!string.IsNullOrEmpty(vpn) && !vpn.StartsWith("—"))
            ifaces = new[] { vpn };
        else
            ifaces = txtRuleIfaces.Text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim()).Where(s => s.Length > 0).ToArray();
        if (ifaces.Length == 0) { Warn("Укажите хотя бы один сетевой адаптер."); return; }
        string res = Program.RunPs(Program.FirewallEditRuleBody(r, prog, action, ifaces, chkRuleEnabled.Checked));
        if (res == "OK") { LoadRules(); FillRuleEdit(lstRules.SelectedItem as FwRule); }
        else Warn("Не удалось изменить правило: " + res);
    }

    void ToggleSelectedRule(bool on)
    {
        var r = lstRules.SelectedItem as FwRule;
        if (r == null) { Warn("Сначала выберите правило в списке."); return; }
        string res = Program.RunPs(Program.FirewallEditRuleBody(r, r.Program, r.Action, r.Interfaces, on));
        if (res == "OK") LoadRules();
        else Warn("Не удалось переключить правило: " + res);
    }

    void DeleteRule()
    {
        var r = lstRules.SelectedItem as FwRule;
        if (r == null) { Warn("Сначала выберите правило в списке."); return; }
        if (MessageBox.Show(this, "Удалить правило «" + r.Name + "»?", Program.AppName,
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        string res = Program.RunPs(Program.FirewallDeleteRuleBody(r.Name));
        if (res == "OK") LoadRules();
        else Warn("Не удалось удалить правило: " + res);
    }

    // ---- первая вкладка: приложения ----

    List<FwRule> RulesFor(string t)
    {
        List<FwRule> list;
        return t != null && rulesByProgram.TryGetValue(t, out list) ? list : null;
    }

    void RefreshToggleButton()
    {
        if (btnToggleApp == null) return;
        var list = RulesFor(target);
        btnToggleApp.Enabled = list != null && list.Count > 0;
        btnToggleApp.Text = list != null && list.Any(r => r.Enabled) ? "Выкл." : "Вкл.";
    }

    void ToggleAppRestriction()
    {
        var list = RulesFor(target);
        if (list == null || list.Count == 0)
        {
            Warn("У выбранного приложения нет правил Тоннель FW.\n" +
                 "Создайте для него ярлык с включённым ограничением на этой вкладке.");
            return;
        }
        bool enable = !list.Any(r => r.Enabled);
        string res = Program.RunPs(Program.FirewallSetEnabledBody(target, enable));
        if (res == "OK") { LoadRules(); RefreshToggleButton(); }
        else Warn("Не удалось переключить ограничение: " + res);
    }

    void OpenAppFolder()
    {
        if (target == null) { Warn("Сначала выберите приложение."); return; }
        Program.OpenFolder(target);
    }

    void Warn(string m) { MessageBox.Show(this, m, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, string l);

    [DllImport("dwmapi.dll")]
    static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int value, int size);

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    static extern int SetWindowTheme(IntPtr h, string app, string idList);
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
