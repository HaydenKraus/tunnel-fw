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

[assembly: AssemblyTitle("Тоннель FW — приложения только через VPN (брандмауэр Windows)")]
[assembly: AssemblyDescription("Создаёт ярлыки и правила брандмауэра: приложение выходит в сеть только через VPN.")]
[assembly: AssemblyProduct("Тоннель FW")]
[assembly: AssemblyCopyright("")]
[assembly: AssemblyVersion("2.1.0.0")]
[assembly: AssemblyFileVersion("2.1.0.0")]

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

    List<AppEntry> apps = new List<AppEntry>();
    readonly Dictionary<string, Bitmap> icons = new Dictionary<string, Bitmap>();
    Thread iconThread;
    DateTime lastLoad;
    string target;

    public MainForm()
    {
        Text = Program.AppName + " — приложения только через VPN (брандмауэр)";
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
        lblTarget.SetBounds(50, 464, 390, 22);
        lblTarget.ForeColor = th.Muted;
        lblTarget.AutoEllipsis = true;
        lblTarget.Text = "Ничего не выбрано";
        Controls.Add(lblTarget);

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
            if (a != null) SetTarget(a.Target, a.Name);
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
                }
        };
        btnCreate.Click += delegate { Create(); };
        Shown += delegate { cmbVpn.Select(0, 0); txtSearch.Focus(); };
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
        list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase));
        if (list.Select(a => a.Target).SequenceEqual(apps.Select(a => a.Target))) return; // ничего не изменилось
        apps = list;
        Filter();
        LoadIconsAsync();
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
            MessageBox.Show(this, msg, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { Warn("Не удалось создать ярлык: " + ex.Message); }
    }

    void RemoveFirewall()
    {
        if (!Program.IsExe(target)) { Warn("Сначала выберите программу .exe через «Выбрать .exe…»."); return; }
        string res = Program.RunPs(Program.FirewallRemoveBody(target));
        MessageBox.Show(this, res == "OK"
                ? "Правила брандмауэра для «" + Path.GetFileName(target) + "» удалены."
                : "Не удалось удалить правила: " + res,
            Program.AppName, MessageBoxButtons.OK,
            res == "OK" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
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
