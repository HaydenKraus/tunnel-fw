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
[assembly: AssemblyVersion("3.0.0.0")]
[assembly: AssemblyFileVersion("3.0.0.0")]

public static class Program
{
    public const string AppName = "Тоннель FW";

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length == 2) return Gate(args[0], args[1]);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
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

// Цвета светлой и тёмной темы (по настройке Windows).
class Theme
{
    public Color Back, Surface, Text, Muted, Border, Accent, AccentHover, Select, Bad;
    public bool Dark;

    public static Theme Current()
    {
        object v = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1);
        bool dark = v is int && (int)v == 0;
        var t = new Theme { Dark = dark, Accent = Color.FromArgb(22, 163, 74), AccentHover = Color.FromArgb(21, 128, 61), Bad = Color.FromArgb(220, 38, 38) };
        if (dark)
        {
            t.Back = Color.FromArgb(32, 32, 32); t.Surface = Color.FromArgb(43, 43, 43); t.Text = Color.FromArgb(242, 242, 242);
            t.Muted = Color.FromArgb(160, 160, 160); t.Border = Color.FromArgb(64, 64, 64); t.Select = Color.FromArgb(28, 70, 45);
        }
        else
        {
            t.Back = Color.FromArgb(247, 247, 248); t.Surface = Color.White; t.Text = Color.FromArgb(24, 24, 27);
            t.Muted = Color.FromArgb(113, 113, 122); t.Border = Color.FromArgb(228, 228, 231); t.Select = Color.FromArgb(220, 252, 231);
        }
        return t;
    }
}

class MainForm : Form
{
    readonly Theme th = Theme.Current();
    readonly TextBox txtSearch = new TextBox(), txtUrl = new TextBox(), txtName = new TextBox();
    readonly ListBox lst = new ListBox();
    readonly ComboBox cmbVpn = new ComboBox();
    readonly CheckBox chkFirewall = new CheckBox();
    readonly PictureBox pic = new PictureBox();
    readonly Label lblStatus = new Label(), lblTarget = new Label();
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 1000 };
    readonly TabControl tabs = new TabControl();
    readonly TabPage pageApps = new TabPage("Приложения");
    readonly TabPage pageRules = new TabPage("Правила брандмауэра");
    readonly ListBox lstRules = new ListBox();
    readonly Label lblRulesStatus = new Label();
    readonly TextBox txtRuleProgram = new TextBox(), txtRuleIfaces = new TextBox();
    readonly ComboBox cmbRuleAction = new ComboBox(), cmbRuleVpn = new ComboBox();
    readonly CheckBox chkRuleEnabled = new CheckBox();
    Button btnToggleApp;

    List<FwRule> rules = new List<FwRule>();
    readonly Dictionary<string, List<FwRule>> rulesByProgram = new Dictionary<string, List<FwRule>>(StringComparer.OrdinalIgnoreCase);

    List<AppEntry> apps = new List<AppEntry>();
    readonly Dictionary<string, Bitmap> icons = new Dictionary<string, Bitmap>();
    Thread iconThread;
    DateTime lastLoad;
    string target;

    public MainForm()
    {
        Text = Program.AppName + " — приложения и правила брандмауэра (v3)";
        Font = new Font("Segoe UI", 10f);
        ClientSize = new Size(460, 704);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = th.Back;
        ForeColor = th.Text;
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

        Put(new Label { Text = Program.AppName, AutoSize = true, Font = new Font("Segoe UI Semibold", 18f) }, 18, 12);
        var sub = new Label
        {
            Text = "Запускает приложения только при включённом VPN. Создайте ярлык — без VPN программа не откроется. " +
                   "Включите ограничение через брандмауэр, чтобы программа не имела сети даже при прямом запуске .exe.",
            ForeColor = th.Muted, Font = new Font("Segoe UI", 9f)
        };
        sub.SetBounds(20, 50, 420, 48);
        Controls.Add(sub);

        lblStatus.SetBounds(20, 92, 420, 22);
        Controls.Add(lblStatus);

        Input(txtSearch, 20, 124, 376, "Поиск приложения");
        var btnRefresh = FlatButton("⟳", false);
        btnRefresh.SetBounds(404, 124, 36, 36);
        btnRefresh.Font = new Font("Segoe UI", 12f);
        new ToolTip().SetToolTip(btnRefresh, "Обновить список приложений");
        Controls.Add(btnRefresh);

        var listFrame = Frame(20, 168, 420, 232);
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
        lblTarget.SetBounds(50, 464, 248, 22);
        lblTarget.ForeColor = th.Muted;
        lblTarget.AutoEllipsis = true;
        lblTarget.Text = "Ничего не выбрано";
        Controls.Add(lblTarget);

        var btnFolder = FlatButton("Папка", false);
        btnFolder.SetBounds(304, 460, 70, 30);
        btnFolder.Font = new Font("Segoe UI", 9f);
        new ToolTip().SetToolTip(btnFolder, "Открыть папку выбранного приложения");
        btnFolder.Click += delegate { OpenAppFolder(); };
        Controls.Add(btnFolder);

        btnToggleApp = FlatButton("Вкл/Выкл", false);
        btnToggleApp.SetBounds(380, 460, 60, 30);
        btnToggleApp.Font = new Font("Segoe UI", 9f);
        new ToolTip().SetToolTip(btnToggleApp, "Включить или выключить ограничение брандмауэра для приложения");
        btnToggleApp.Click += delegate { ToggleAppRestriction(); };
        Controls.Add(btnToggleApp);

        Input(txtName, 20, 496, 420, "Название ярлыка");

        chkFirewall.SetBounds(20, 540, 282, 34);
        chkFirewall.Text = "Только через VPN (брандмауэр Windows)";
        chkFirewall.ForeColor = th.Text;
        chkFirewall.FlatStyle = FlatStyle.Flat;
        chkFirewall.Font = new Font("Segoe UI", 9f);
        chkFirewall.Checked = true;
        new ToolTip().SetToolTip(chkFirewall,
            "Создать правила брандмауэра: без VPN у программы нет сети, даже если запустить .exe напрямую. Понадобятся права администратора.");
        Controls.Add(chkFirewall);

        var btnFwRemove = FlatButton("Удалить правила", false);
        btnFwRemove.SetBounds(306, 540, 134, 30);
        btnFwRemove.Font = new Font("Segoe UI", 9f);
        new ToolTip().SetToolTip(btnFwRemove, "Удалить правила брандмауэра для выбранной программы");
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

        // ---- вкладки (версия 3): всё существующее содержимое становится первой вкладкой ----
        pageApps.BackColor = th.Back;
        var holder = new Panel { Dock = DockStyle.Fill, BackColor = th.Back };
        foreach (var c in Controls.Cast<Control>().ToList()) holder.Controls.Add(c);
        pageApps.Controls.Add(holder);

        BuildRulesPage();
        tabs.Dock = DockStyle.Fill;
        tabs.Controls.Add(pageApps);
        tabs.Controls.Add(pageRules);
        Controls.Add(tabs);
        tabs.SelectedIndexChanged += delegate
        {
            if (tabs.SelectedTab == pageRules) LoadRules();
            else RefreshToggleButton();
        };

        LoadRules();
        RefreshToggleButton();
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        if (th.Dark)
        {
            int on = 1;
            DwmSetWindowAttribute(Handle, 20, ref on, 4); // тёмный заголовок окна
            SetWindowTheme(lst.Handle, "DarkMode_Explorer", null);
            SetWindowTheme(cmbVpn.Handle, "DarkMode_CFD", null);
        }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
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
        var b = new Button { Text = text, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand, UseVisualStyleBackColor = false };
        b.BackColor = primary ? th.Accent : th.Surface;
        b.ForeColor = primary ? Color.White : th.Text;
        b.FlatAppearance.BorderColor = primary ? th.Accent : th.Border;
        b.FlatAppearance.BorderSize = primary ? 0 : 1;
        b.FlatAppearance.MouseOverBackColor = primary ? th.AccentHover : th.Select;
        b.FlatAppearance.MouseDownBackColor = primary ? th.AccentHover : th.Select;
        return b;
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
        lblStatus.Text = up ? "●  " + a + " подключён" : "●  " + a + " не подключён";
        lblStatus.ForeColor = up ? th.Accent : th.Bad;
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
        using (var b = new SolidBrush(selected ? th.Select : th.Surface)) e.Graphics.FillRectangle(b, e.Bounds);
        Bitmap ic;
        lock (icons) icons.TryGetValue(a.Target, out ic);
        if (ic != null)
        {
            e.Graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
            e.Graphics.DrawImage(ic, e.Bounds.X + 12, e.Bounds.Y + 7, 24, 24);
        }
        var r = new Rectangle(e.Bounds.X + 46, e.Bounds.Y, e.Bounds.Width - 52, e.Bounds.Height);
        TextRenderer.DrawText(e.Graphics, a.Name, lst.Font, r, th.Text,
            TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        var rr = RulesFor(a.Target);
        if (rr != null && rr.Count > 0)
        {
            bool anyOn = rr.Any(x => x.Enabled);
            using (var br = new SolidBrush(anyOn ? th.Accent : th.Bad))
                e.Graphics.FillEllipse(br, e.Bounds.Right - 17, e.Bounds.Y + 14, 10, 10);
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
        lstRules.SelectedIndexChanged += delegate { FillRuleEdit(lstRules.SelectedItem as FwRule); };

        var bRefresh = FlatButton("⟳", false); bRefresh.Font = new Font("Segoe UI", 12f);
        new ToolTip().SetToolTip(bRefresh, "Обновить список правил");
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
        new ToolTip().SetToolTip(bDir, "Открыть папку программы выбранного правила");
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

        chkRuleEnabled.Text = "Правило включено";
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
        rules = Program.ReadFwRules();
        rulesByProgram.Clear();
        foreach (var r in rules)
            if (!string.IsNullOrEmpty(r.Program))
            {
                List<FwRule> list;
                if (!rulesByProgram.TryGetValue(r.Program, out list)) rulesByProgram[r.Program] = list = new List<FwRule>();
                list.Add(r);
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
        using (var b = new SolidBrush(sel ? th.Select : th.Surface)) e.Graphics.FillRectangle(b, e.Bounds);
        using (var br = new SolidBrush(r.IsBlock ? th.Bad : th.Accent))
            e.Graphics.FillRectangle(br, e.Bounds.X + 8, e.Bounds.Y + 10, 13, 13);
        string prog = string.IsNullOrEmpty(r.Program) ? "?" : Path.GetFileName(r.Program);
        TextRenderer.DrawText(e.Graphics, prog + "   ·   " + r.Action, lstRules.Font,
            new Rectangle(e.Bounds.X + 28, e.Bounds.Y + 1, e.Bounds.Width - 34, 17),
            r.Enabled ? th.Text : th.Muted, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        string sub = (r.Enabled ? "вкл" : "ВЫКЛ") + "   ·   " + r.InterfaceText + "   ·   " + r.Name;
        TextRenderer.DrawText(e.Graphics, sub, new Font("Segoe UI", 8f),
            new Rectangle(e.Bounds.X + 28, e.Bounds.Y + 17, e.Bounds.Width - 34, 16),
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
