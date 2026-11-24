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


// Широкое desktop-окно: сайдбар, мастер-детейл приложений и таблица правил.
class MainForm : Form, IMessageFilter
{
    readonly Theme th = Theme.Current();
    readonly Font fSmall = new Font("Segoe UI", 8.5f);
    readonly Font fBody = new Font("Segoe UI", 9.5f);
    readonly Font fSection = new Font("Segoe UI Semibold", 8.5f);
    readonly Font fTitle = new Font("Segoe UI Semibold", 16f);
    readonly Font fBrand = new Font("Segoe UI Semibold", 14f);

    SideNav nav;
    AnimButton btnEffects;
    CursorOverlay overlay;
    readonly System.Windows.Forms.Timer clock = new System.Windows.Forms.Timer { Interval = 1000 };
    readonly Panel pageApps = new Panel(), pageRules = new Panel();

    ComboBox cmbVpn = new ComboBox();
    readonly Label lblStatus = new Label();

    TextBox txtSearch = new TextBox(), txtUrl = new TextBox();
    ListBox lst = new ListBox();
    AnimButton chipAll, chipRules, btnExe;

    PictureBox pic = new PictureBox();
    Label lblName = new Label(), lblPath = new Label(), lblRules = new Label();
    AnimButton btnFolder;
    ToggleSwitch chkRestrict, chkFirewall;
    TextBox txtName = new TextBox();
    AnimButton btnCreate, btnRemoveRules;

    ListView lv = new ListView();
    TextBox txtFilter = new TextBox();
    AnimButton btnOn, btnOff, btnDel, btnDir;
    TextBox txtRuleProgram = new TextBox(), txtRuleIfaces = new TextBox();
    ComboBox cmbRuleAction = new ComboBox(), cmbRuleVpn = new ComboBox();
    ToggleSwitch chkRuleEnabled;
    AnimButton btnApply, btnReset;
    readonly Label lblRuleCount = new Label();

    List<AppEntry> apps = new List<AppEntry>();
    readonly Dictionary<string, Bitmap> icons = new Dictionary<string, Bitmap>();
    Thread iconThread;
    DateTime lastLoad;
    string target;
    int hoverApp = -1, hoverRule = -1;
    List<FwRule> rules = new List<FwRule>();
    readonly Dictionary<string, List<FwRule>> rulesByProgram = new Dictionary<string, List<FwRule>>(StringComparer.OrdinalIgnoreCase);
    volatile bool rulesLoading;
    bool filterOnlyRules, suppressRestrict;

    public MainForm(bool startRules = false)
    {
        Text = Program.AppName + " — приложения и правила брандмауэра (v3.1)";
        Font = fBody;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(1120, 720);
        MinimumSize = new Size(980, 620);
        FormBorderStyle = FormBorderStyle.Sizable;
        MaximizeBox = true;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = th.Back;
        ForeColor = th.Text;
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

        Ui.InitCursors();
        Cursor = Ui.Arrow;

        BuildRulesPage();
        BuildAppsPage();
        var side = BuildSidebar();

        var content = new Panel { Dock = DockStyle.Fill, BackColor = th.Back };
        content.Controls.Add(pageApps);
        content.Controls.Add(pageRules);
        pageRules.Visible = false;

        Controls.Add(content);
        Controls.Add(side);

        nav.SelectedChanged += delegate { ShowPage(nav.SelectedIndex); };
        FillAdapters();
        cmbVpn.Text = cmbVpn.Items.Contains("AmneziaVPN") || !cmbVpn.Items.Cast<string>().Any() ? "AmneziaVPN" : GuessVpn();
        cmbVpn.DropDown += delegate { string t = cmbVpn.Text; FillAdapters(); cmbVpn.Text = t; };
        cmbVpn.TextChanged += delegate { UpdateStatus(); };
        UpdateStatus();

        clock.Tick += delegate { UpdateStatus(); };
        clock.Start();
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;

        LoadApps();
        LoadRules();
        ShowPage(0);
        if (startRules) nav.SelectedIndex = 1;
        RefreshToggleButton();
    }

    // ---------- каркас ----------

    Panel BuildSidebar()
    {
        var side = new Panel { Dock = DockStyle.Left, Width = 224, BackColor = Color.FromArgb(14, 14, 14) };
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, BackColor = side.BackColor };
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 78));
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 104));
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 136));
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));

        var brand = new Panel { Dock = DockStyle.Fill, BackColor = side.BackColor };
        var logo = new PictureBox { SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(34, 34), Location = new Point(18, 20) };
        try { logo.Image = Program.GetIcon(Application.ExecutablePath, 32); } catch { }
        brand.Controls.Add(logo);
        brand.Controls.Add(new Label { Text = "ТОННЕЛЬ FW", AutoSize = true, ForeColor = th.Text, Font = fBrand, Location = new Point(60, 16) });
        brand.Controls.Add(new Label { Text = "v" + Application.ProductVersion, AutoSize = true, ForeColor = th.Muted, Font = fSmall, Location = new Point(60, 43) });

        nav = new SideNav(th) { Titles = new[] { "Приложения", "Правила" }, Dock = DockStyle.Fill };

        var vpnCard = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface, Padding = new Padding(14, 10, 14, 10), Margin = new Padding(14, 6, 14, 6) };
        vpnCard.Paint += delegate(object s, PaintEventArgs e) { using (var pen = new Pen(th.Border)) e.Graphics.DrawRectangle(pen, 0, 0, vpnCard.Width - 1, vpnCard.Height - 1); };
        vpnCard.Controls.Add(lblStatus);
        vpnCard.Controls.Add(cmbVpn);
        vpnCard.Controls.Add(new Label { Text = "VPN-АДПТЕР", ForeColor = th.Muted, Font = fSection, Dock = DockStyle.Top, Height = 18 });
        lblStatus.Dock = DockStyle.Fill;
        lblStatus.Font = fSmall;
        lblStatus.ForeColor = th.Muted;
        lblStatus.TextAlign = ContentAlignment.MiddleLeft;
        cmbVpn.Dock = DockStyle.Top;
        cmbVpn.Height = 30;
        StyleCombo(cmbVpn);

        var fxWrap = new Panel { Dock = DockStyle.Fill, BackColor = side.BackColor, Padding = new Padding(14, 6, 14, 8) };
        btnEffects = Btn("Эффекты", false);
        btnEffects.Dock = DockStyle.Fill;
        btnEffects.Click += delegate { ToggleEffects(); };
        fxWrap.Controls.Add(btnEffects);

        t.Controls.Add(brand, 0, 0);
        t.Controls.Add(nav, 0, 1);
        t.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = side.BackColor }, 0, 2);
        t.Controls.Add(vpnCard, 0, 3);
        t.Controls.Add(fxWrap, 0, 4);
        side.Controls.Add(t);
        return side;
    }

    void BuildAppsPage()
    {
        pageApps.Dock = DockStyle.Fill;
        pageApps.Padding = new Padding(22, 18, 22, 18);
        pageApps.BackColor = th.Back;

        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = th.Back };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42f));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58f));
        pageApps.Controls.Add(grid);

        // ---- левая колонка ----
        var left = Card();
        left.Dock = DockStyle.Fill;
        left.Margin = new Padding(0, 0, 8, 0);
        grid.Controls.Add(left, 0, 0);

        var lt = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, BackColor = th.Surface, Padding = new Padding(16, 16, 16, 16) };
        lt.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        lt.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        lt.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        lt.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        lt.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        left.Controls.Add(lt);

        var searchRow = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface, Margin = new Padding(0, 0, 0, 8) };
        var refresh = Btn("⟳", false);
        refresh.Dock = DockStyle.Right;
        refresh.Width = 42;
        tip.SetToolTip(refresh, "Обновить список приложений");
        refresh.Click += delegate { LoadApps(); };
        var sf = Field(txtSearch, "Поиск приложения");
        sf.Dock = DockStyle.Fill;
        sf.Margin = new Padding(0, 0, 8, 0);
        searchRow.Controls.Add(sf);
        searchRow.Controls.Add(refresh);
        lt.Controls.Add(searchRow, 0, 0);

        var chips = new FlowLayoutPanel { Dock = DockStyle.Fill, BackColor = th.Surface, Margin = new Padding(0, 0, 0, 8), WrapContents = false };
        chipAll = Btn("● Все", false);
        chipAll.Width = 96; chipAll.Height = 30; chipAll.Margin = new Padding(0, 0, 8, 0);
        chipAll.Click += delegate { filterOnlyRules = false; StyleChips(); Filter(); };
        chipRules = Btn("С правилами", false);
        chipRules.Width = 132; chipRules.Height = 30;
        chipRules.Click += delegate { filterOnlyRules = true; StyleChips(); Filter(); };
        chips.Controls.Add(chipAll);
        chips.Controls.Add(chipRules);
        lt.Controls.Add(chips, 0, 1);

        var listWrap = Card();
        listWrap.Dock = DockStyle.Fill;
        listWrap.Margin = new Padding(0, 0, 0, 8);
        listWrap.Padding = new Padding(1);
        lst.BorderStyle = BorderStyle.None;
        lst.BackColor = th.Surface;
        lst.ForeColor = th.Text;
        lst.Font = fBody;
        lst.DrawMode = DrawMode.OwnerDrawFixed;
        lst.ItemHeight = 40;
        lst.IntegralHeight = false;
        lst.Dock = DockStyle.Fill;
        listWrap.Controls.Add(lst);
        lt.Controls.Add(listWrap, 0, 2);

        var exeRow = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface, Margin = new Padding(0, 0, 0, 6) };
        btnExe = Btn("Выбрать .exe…", false);
        btnExe.Dock = DockStyle.Left;
        btnExe.Width = 150;
        btnExe.Margin = new Padding(0, 0, 8, 0);
        btnExe.Click += delegate
        {
            using (var dlg = new OpenFileDialog { Filter = "Программы (*.exe)|*.exe" })
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    string desc = FileVersionInfo.GetVersionInfo(dlg.FileName).FileDescription;
                    SetTarget(dlg.FileName, string.IsNullOrWhiteSpace(desc) ? Path.GetFileNameWithoutExtension(dlg.FileName) : desc);
                }
        };
        exeRow.Controls.Add(btnExe);
        lt.Controls.Add(exeRow, 0, 3);

        var urlField = Field(txtUrl, "или ссылка https://…");
        urlField.Dock = DockStyle.Fill;
        urlField.Margin = new Padding(0, 0, 0, 0);
        lt.Controls.Add(urlField, 0, 4);

        // ---- правая колонка: детали ----
        var right = Card();
        right.Dock = DockStyle.Fill;
        right.Margin = new Padding(8, 0, 0, 0);
        grid.Controls.Add(right, 1, 0);

        var rt = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 11, BackColor = th.Surface, Padding = new Padding(20, 18, 20, 18) };
        int[] rows = { 84, 42, 12, 26, 46, 36, 0, 26, 44, 46, 56 };
        foreach (int h in rows) rt.RowStyles.Add(h == 0 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.Absolute, h));
        right.Controls.Add(rt);

        var head = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface, Margin = new Padding(0, 0, 0, 8) };
        pic.SizeMode = PictureBoxSizeMode.Zoom;
        pic.Size = new Size(64, 64);
        pic.Location = new Point(0, 4);
        head.Controls.Add(pic);
        lblName.AutoSize = false;
        lblName.Font = fTitle;
        lblName.ForeColor = th.Text;
        lblName.SetBounds(80, 2, 420, 30);
        lblName.Text = "Приложение не выбрано";
        lblPath.AutoSize = false;
        lblPath.Font = fSmall;
        lblPath.ForeColor = th.Muted;
        lblPath.SetBounds(80, 34, 420, 44);
        lblPath.Text = "Выберите приложение слева или укажите .exe";
        lblPath.AutoEllipsis = true;
        head.Controls.Add(lblName);
        head.Controls.Add(lblPath);
        rt.Controls.Add(head, 0, 0);

        var folderRow = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface, Margin = new Padding(0, 0, 0, 6) };
        btnFolder = Btn("Открыть папку", false);
        btnFolder.Dock = DockStyle.Left;
        btnFolder.Width = 150;
        btnFolder.Enabled = false;
        btnFolder.Click += delegate { if (target != null) Program.OpenFolder(target); };
        folderRow.Controls.Add(btnFolder);
        rt.Controls.Add(folderRow, 0, 1);

        rt.Controls.Add(Separator(), 0, 2);
        rt.Controls.Add(Section("ОГРАНИЧЕНИЕ БРАНДМАУЭРА"), 0, 3);

        chkRestrict = new ToggleSwitch(th) { Text = "Ограничение включено", Dock = DockStyle.Fill };
        chkRestrict.Enabled = false;
        chkRestrict.CheckedChanged += delegate { OnRestrictChanged(); };
        rt.Controls.Add(chkRestrict, 0, 4);

        lblRules.AutoSize = false;
        lblRules.Font = fSmall;
        lblRules.ForeColor = th.Muted;
        lblRules.Dock = DockStyle.Fill;
        lblRules.AutoEllipsis = true;
        lblRules.Text = "Правил нет";
        rt.Controls.Add(lblRules, 0, 5);

        rt.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = th.Surface }, 0, 6);
        rt.Controls.Add(Section("ЯРЛЫК"), 0, 7);

        var nameField = Field(txtName, "Название ярлыка");
        nameField.Dock = DockStyle.Fill;
        nameField.Margin = new Padding(0, 0, 0, 8);
        rt.Controls.Add(nameField, 0, 8);

        chkFirewall = new ToggleSwitch(th) { Text = "Только через VPN (брандмауэр)", Dock = DockStyle.Fill };
        chkFirewall.Checked = true;
        tip.SetToolTip(chkFirewall, "Без VPN у программы нет сети, даже если запустить .exe напрямую. Нужны права администратора.");
        rt.Controls.Add(chkFirewall, 0, 9);

        var actions = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface, Margin = new Padding(0, 6, 0, 0) };
        btnCreate = Btn("Создать ярлык", true);
        btnCreate.Dock = DockStyle.Left;
        btnCreate.Width = 210;
        btnCreate.Font = new Font("Segoe UI Semibold", 10f);
        btnCreate.Enabled = false;
        btnCreate.Click += delegate { Create(); };
        btnRemoveRules = Btn("Удалить правила", false);
        btnRemoveRules.Dock = DockStyle.Right;
        btnRemoveRules.Width = 170;
        btnRemoveRules.Enabled = false;
        btnRemoveRules.Click += delegate { RemoveFirewall(); };
        actions.Controls.Add(btnCreate);
        actions.Controls.Add(btnRemoveRules);
        rt.Controls.Add(actions, 0, 10);

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
            if (a != null) SetTarget(a.Target, a.Name);
        };
        txtUrl.TextChanged += delegate
        {
            string u = txtUrl.Text.Trim();
            Uri uri;
            if (Program.IsUrl(u)) SetTarget(u, Uri.TryCreate(u, UriKind.Absolute, out uri) ? uri.Host : u);
        };
        StyleChips();
    }

    void BuildRulesPage()
    {
        pageRules.Dock = DockStyle.Fill;
        pageRules.Padding = new Padding(22, 18, 22, 18);
        pageRules.BackColor = th.Back;

        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, BackColor = th.Back };
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        t.RowStyles.Add(new RowStyle(SizeType.Absolute, 250));
        pageRules.Controls.Add(t);

        var head = new Panel { Dock = DockStyle.Fill, BackColor = th.Back, Margin = new Padding(0, 0, 0, 6) };
        var title = new Label { Text = "Правила брандмауэра", AutoSize = true, Font = fTitle, ForeColor = th.Text, Location = new Point(0, 2) };
        head.Controls.Add(title);
        lblRuleCount.AutoSize = true;
        lblRuleCount.Font = fSmall;
        lblRuleCount.ForeColor = th.Muted;
        lblRuleCount.Location = new Point(0, 28);
        head.Controls.Add(lblRuleCount);

        var filterField = Field(txtFilter, "Фильтр по программе или имени");
        filterField.Dock = DockStyle.Right;
        filterField.Width = 280;
        filterField.Margin = new Padding(8, 2, 0, 2);
        head.Controls.Add(filterField);
        var refresh = Btn("⟳", false);
        refresh.Dock = DockStyle.Right;
        refresh.Width = 44;
        refresh.Click += delegate { LoadRules(); };
        head.Controls.Add(refresh);
        t.Controls.Add(head, 0, 0);

        var bar = new FlowLayoutPanel { Dock = DockStyle.Fill, BackColor = th.Back, Margin = new Padding(0, 0, 0, 8), WrapContents = false };
        btnOn = Btn("Включить", false); btnOn.Width = 110; btnOn.Margin = new Padding(0, 0, 8, 0); btnOn.Click += delegate { ToggleSelectedRule(true); };
        btnOff = Btn("Выключить", false); btnOff.Width = 110; btnOff.Margin = new Padding(0, 0, 8, 0); btnOff.Click += delegate { ToggleSelectedRule(false); };
        btnDel = Btn("Удалить", false); btnDel.Width = 110; btnDel.Margin = new Padding(0, 0, 8, 0); btnDel.Click += delegate { DeleteRule(); };
        btnDir = Btn("Папка", false); btnDir.Width = 110; btnDir.Click += delegate { var r = SelRule(); if (r != null) Program.OpenFolder(r.Program); };
        bar.Controls.Add(btnOn); bar.Controls.Add(btnOff); bar.Controls.Add(btnDel); bar.Controls.Add(btnDir);
        t.Controls.Add(bar, 0, 1);

        var tableCard = Card();
        tableCard.Dock = DockStyle.Fill;
        tableCard.Margin = new Padding(0, 0, 0, 8);
        tableCard.Padding = new Padding(1);
        lv.View = View.Details;
        lv.FullRowSelect = true;
        lv.HideSelection = false;
        lv.MultiSelect = false;
        lv.OwnerDraw = true;
        lv.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        lv.BorderStyle = BorderStyle.None;
        lv.BackColor = th.Surface;
        lv.ForeColor = th.Text;
        lv.Font = fBody;
        lv.Dock = DockStyle.Fill;
        lv.Columns.Add("Программа", 300);
        lv.Columns.Add("Действие", 110);
        lv.Columns.Add("Состояние", 120);
        lv.Columns.Add("Интерфейсы", 260);
        lv.Columns.Add("Имя правила", 200);
        tableCard.Controls.Add(lv);
        t.Controls.Add(tableCard, 0, 2);

        lv.DrawColumnHeader += DrawRuleHeader;
        lv.DrawItem += DrawRuleRow;
        lv.DrawSubItem += DrawRuleCell;
        lv.Resize += delegate { ResizeRuleColumns(); };
        lv.SelectedIndexChanged += delegate { FillRuleEdit(SelRule()); };
        lv.MouseMove += delegate
        {
            int i = lv.GetItemAt(8, lv.PointToClient(Cursor.Position).Y) == null ? -1 : lv.GetItemAt(8, lv.PointToClient(Cursor.Position).Y).Index;
            if (i != hoverRule) { hoverRule = i; lv.Invalidate(); }
        };
        lv.MouseLeave += delegate { if (hoverRule != -1) { hoverRule = -1; lv.Invalidate(); } };

        var edit = Card();
        edit.Dock = DockStyle.Fill;
        var et = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, BackColor = th.Surface, Padding = new Padding(16, 12, 16, 12) };
        et.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        et.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        et.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        et.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        et.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        edit.Controls.Add(et);

        et.Controls.Add(Section("РЕДАКТИРОВАНИЕ ПРАВИЛА"), 0, 0);

        var row1 = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface, Margin = new Padding(0, 0, 0, 6) };
        var browse = Btn("…", false);
        browse.Dock = DockStyle.Right;
        browse.Width = 44;
        browse.Click += delegate
        {
            using (var dlg = new OpenFileDialog { Filter = "Программы (*.exe)|*.exe" })
                if (dlg.ShowDialog(this) == DialogResult.OK) txtRuleProgram.Text = dlg.FileName;
        };
        var progField = Field(txtRuleProgram, @"Путь к .exe");
        progField.Dock = DockStyle.Fill;
        progField.Margin = new Padding(0, 0, 8, 0);
        row1.Controls.Add(progField);
        row1.Controls.Add(browse);
        et.Controls.Add(row1, 0, 1);

        var row2 = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface, Margin = new Padding(0, 0, 0, 6) };
        cmbRuleAction.DropDownStyle = ComboBoxStyle.DropDownList;
        cmbRuleAction.Items.AddRange(new object[] { "Block", "Allow" });
        StyleCombo(cmbRuleAction);
        cmbRuleAction.Dock = DockStyle.Left;
        cmbRuleAction.Width = 140;
        cmbRuleAction.Margin = new Padding(0, 0, 8, 0);
        FillAdaptersInto(cmbRuleVpn);
        StyleCombo(cmbRuleVpn);
        cmbRuleVpn.Dock = DockStyle.Left;
        cmbRuleVpn.Width = 220;
        cmbRuleVpn.Margin = new Padding(0, 0, 8, 0);
        chkRuleEnabled = new ToggleSwitch(th) { Text = "Включено", Dock = DockStyle.Fill };
        chkRuleEnabled.Checked = true;
        var actionLabel = new Label { Text = "Действие / VPN", AutoSize = false, Width = 120, Dock = DockStyle.Left, ForeColor = th.Muted, Font = fSmall, TextAlign = ContentAlignment.MiddleLeft };
        row2.Controls.Add(chkRuleEnabled);
        row2.Controls.Add(cmbRuleVpn);
        row2.Controls.Add(cmbRuleAction);
        row2.Controls.Add(actionLabel);
        et.Controls.Add(row2, 0, 2);

        var ifField = Field(txtRuleIfaces, "Интерфейсы через ; (пусто — не менять)");
        ifField.Dock = DockStyle.Fill;
        ifField.Margin = new Padding(0, 0, 0, 6);
        et.Controls.Add(ifField, 0, 3);

        var row4 = new Panel { Dock = DockStyle.Fill, BackColor = th.Surface };
        btnApply = Btn("Применить изменения", true);
        btnApply.Dock = DockStyle.Left;
        btnApply.Width = 220;
        btnApply.Margin = new Padding(0, 0, 8, 0);
        btnApply.Click += delegate { ApplyRuleEdit(); };
        btnReset = Btn("Сбросить", false);
        btnReset.Dock = DockStyle.Left;
        btnReset.Width = 140;
        btnReset.Click += delegate { FillRuleEdit(SelRule()); };
        var hint = new Label
        {
            Text = "Смена VPN-адаптера пересоздаёт оба правила пары. Смена пути .exe переносит правило на новую программу.",
            ForeColor = th.Muted, Font = fSmall, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft
        };
        row4.Controls.Add(hint);
        row4.Controls.Add(btnReset);
        row4.Controls.Add(btnApply);
        et.Controls.Add(row4, 0, 4);

        txtFilter.TextChanged += delegate { RefreshRulesList(); };
        ResizeRuleColumns();
    }

    // ---------- мелкие строители ----------

    Panel Card()
    {
        var p = new Panel { BackColor = th.Surface };
        p.Paint += delegate(object s, PaintEventArgs e) { using (var pen = new Pen(th.Border)) e.Graphics.DrawRectangle(pen, 0, 0, p.Width - 1, p.Height - 1); };
        return p;
    }

    Panel Separator() { return new Panel { Dock = DockStyle.Fill, BackColor = th.Border, Height = 1, Margin = new Padding(0, 4, 0, 4) }; }

    Label Section(string text)
    {
        return new Label { Text = text, AutoSize = false, Dock = DockStyle.Fill, ForeColor = th.Muted, Font = fSection, TextAlign = ContentAlignment.MiddleLeft };
    }

    AnimButton Btn(string text, bool primary)
    {
        return new AnimButton(th, primary) { Text = text, Font = fBody, Height = 34 };
    }

    readonly ToolTip tip = new ToolTip();

    void StyleCombo(ComboBox cb)
    {
        cb.FlatStyle = FlatStyle.Flat;
        cb.BackColor = th.Surface;
        cb.ForeColor = th.Text;
        cb.Font = fBody;
    }

    Panel Field(TextBox tb, string cue)
    {
        var p = new Panel { BackColor = th.Surface, Padding = new Padding(10, 8, 10, 8) };
        p.Paint += delegate(object s, PaintEventArgs e) { using (var pen = new Pen(th.Border)) e.Graphics.DrawRectangle(pen, 0, 0, p.Width - 1, p.Height - 1); };
        tb.BorderStyle = BorderStyle.None;
        tb.BackColor = th.Surface;
        tb.ForeColor = th.Text;
        tb.Font = fBody;
        tb.Dock = DockStyle.Fill;
        tb.GotFocus += delegate { p.BackColor = Color.FromArgb(27, 27, 27); tb.BackColor = Color.FromArgb(27, 27, 27); };
        tb.LostFocus += delegate { p.BackColor = th.Surface; tb.BackColor = th.Surface; };
        tb.HandleCreated += delegate { try { SendMessage(tb.Handle, 0x1501, (IntPtr)1, cue); } catch { } };
        p.Controls.Add(tb);
        return p;
    }

    // ---------- тема окна ----------

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        int on = 1;
        DwmSetWindowAttribute(Handle, 20, ref on, 4);
        DwmSetWindowAttribute(Handle, 19, ref on, 4);
        try
        {
            int caption = 0x000A0A0A, text = 0x00F2F2F2, border = 0x002E1DE1;
            DwmSetWindowAttribute(Handle, 35, ref caption, 4);
            DwmSetWindowAttribute(Handle, 36, ref text, 4);
            DwmSetWindowAttribute(Handle, 34, ref border, 4);
        }
        catch { }
        SetWindowTheme(lst.Handle, "DarkMode_Explorer", null);
        SetWindowTheme(lv.Handle, "DarkMode_Explorer", null);
        SetWindowTheme(cmbVpn.Handle, "DarkMode_CFD", null);
        SetWindowTheme(cmbRuleAction.Handle, "DarkMode_CFD", null);
        SetWindowTheme(cmbRuleVpn.Handle, "DarkMode_CFD", null);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        try
        {
            overlay = new CursorOverlay(th) { Owner = this };
            Application.AddMessageFilter(this);
            Move += delegate { overlay.Follow(ClientScreen(), Form.ActiveForm == this); };
            Resize += delegate { overlay.Follow(ClientScreen(), Form.ActiveForm == this); };
            Activated += delegate { overlay.Follow(ClientScreen(), Form.ActiveForm == this); };
            Deactivate += delegate { overlay.Stop(); };
        }
        catch { overlay = null; }
        txtSearch.Focus();
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
        try { Application.RemoveMessageFilter(this); } catch { }
        if (overlay != null) { try { overlay.Dispose(); } catch { } overlay = null; }
        base.OnFormClosed(e);
    }

    Rectangle ClientScreen() { return RectangleToScreen(ClientRectangle); }

    bool IMessageFilter.PreFilterMessage(ref Message m)
    {
        if (overlay == null || !Ui.Effects) return false;
        bool active = Form.ActiveForm == this;
        if (m.Msg == 0x200) { overlay.Follow(ClientScreen(), active); return false; }
        if (m.Msg == 0x201 && active && ClientScreen().Contains(Cursor.Position)) overlay.Pulse();
        return false;
    }

    void ToggleEffects()
    {
        Ui.Effects = !Ui.Effects;
        btnEffects.Text = Ui.Effects ? "Эффекты" : "Без эффектов";
        if (overlay == null) return;
        if (Ui.Effects) overlay.Follow(ClientScreen(), Form.ActiveForm == this);
        else overlay.Stop();
    }

    void OnNetworkChanged(object s, EventArgs e) { if (IsHandleCreated) BeginInvoke((Action)UpdateStatus); }

    void ShowPage(int index)
    {
        pageApps.Visible = index == 0;
        pageRules.Visible = index == 1;
        if (index == 1) { if (!rulesLoading) LoadRules(); }
        else RefreshToggleButton();
    }

    // ---------- VPN ----------

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
        if (a.Length == 0) { lblStatus.Text = "●  Укажите адаптер"; lblStatus.ForeColor = th.Muted; return; }
        bool up = Program.VpnUp(a);
        lblStatus.Text = up ? "●  " + a + "\nподключён" : "○  " + a + "\nне подключён";
        lblStatus.ForeColor = up ? th.Accent : th.Muted;
    }

    // ---------- приложения ----------

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
        catch { }
        AddRuleApps(list);
        list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase));
        if (list.Select(a => a.Target).SequenceEqual(apps.Select(a => a.Target))) return;
        apps = list;
        Filter();
        LoadIconsAsync();
    }

    void AddRuleApps(List<AppEntry> list)
    {
        foreach (var kv in rulesByProgram)
        {
            if (!kv.Key.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (list.Any(a => string.Equals(a.Target, kv.Key, StringComparison.OrdinalIgnoreCase))) continue;
            string name = "";
            try { name = FileVersionInfo.GetVersionInfo(kv.Key).FileDescription; } catch { }
            if (string.IsNullOrWhiteSpace(name)) name = Path.GetFileNameWithoutExtension(kv.Key);
            list.Add(new AppEntry { Name = name, Target = kv.Key });
        }
    }

    void Filter()
    {
        string q = txtSearch.Text.Trim();
        lst.BeginUpdate();
        lst.Items.Clear();
        foreach (var a in apps)
        {
            if (filterOnlyRules && RulesFor(a.Target) == null) continue;
            if (q.Length > 0 && a.Name.IndexOf(q, StringComparison.CurrentCultureIgnoreCase) < 0) continue;
            lst.Items.Add(a);
        }
        if (target != null)
            for (int i = 0; i < lst.Items.Count; i++)
                if (((AppEntry)lst.Items[i]).Target == target) { lst.SelectedIndex = i; break; }
        lst.EndUpdate();
    }

    void StyleChips()
    {
        if (chipAll == null) return;
        chipAll.Text = filterOnlyRules ? "Все" : "● Все";
        chipRules.Text = filterOnlyRules ? "● С правилами" : "С правилами";
    }

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
        using (var b = new SolidBrush(selected ? th.AccentDim : (hover ? th.SurfaceHover : th.Surface))) e.Graphics.FillRectangle(b, e.Bounds);
        if (selected)
            using (var bar = new SolidBrush(th.Accent)) e.Graphics.FillRectangle(bar, e.Bounds.X, e.Bounds.Y, 3, e.Bounds.Height);

        Bitmap ic;
        lock (icons) icons.TryGetValue(a.Target, out ic);
        if (ic != null)
        {
            e.Graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
            e.Graphics.DrawImage(ic, e.Bounds.X + 12, e.Bounds.Y + 8, 24, 24);
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
                using (var glow = new SolidBrush(Color.FromArgb(70, th.Accent))) e.Graphics.FillEllipse(glow, cx - 4, cy - 8, 16, 16);
                using (var dot = new SolidBrush(th.Accent)) e.Graphics.FillEllipse(dot, cx, cy - 4, 8, 8);
            }
            else using (var ring = new Pen(th.Muted, 1.4f)) e.Graphics.DrawEllipse(ring, cx, cy - 4, 8, 8);
        }
    }

    void SetTarget(string t, string name)
    {
        target = t;
        txtName.Text = name;
        lblName.Text = name;
        lblPath.Text = t.StartsWith("shell:AppsFolder\\") ? "Приложение Windows" : t;
        var old = pic.Image;
        try { pic.Image = Program.GetIcon(t, 64); } catch { pic.Image = null; }
        if (old != null) old.Dispose();
        UpdateDetail();
    }

    List<FwRule> RulesFor(string t)
    {
        List<FwRule> list;
        return t != null && rulesByProgram.TryGetValue(t, out list) ? list : null;
    }

    void RefreshToggleButton()
    {
        if (target == null) return;
        UpdateDetail();
    }

    void UpdateDetail()
    {
        bool has = target != null;
        btnFolder.Enabled = has;
        btnCreate.Enabled = has;
        btnRemoveRules.Enabled = has && RulesFor(target) != null;
        var list = has ? RulesFor(target) : null;
        bool on = list != null && list.Any(r => r.Enabled);
        suppressRestrict = true;
        chkRestrict.Checked = on;
        chkRestrict.Enabled = list != null && list.Count > 0;
        suppressRestrict = false;
        if (!has) { lblRules.Text = "Правил нет"; return; }
        lblRules.Text = list == null
            ? "Правил нет — включите ограничение и создайте ярлык."
            : string.Join("   ·   ", list.Select(r => (r.IsBlock ? "Block" : "Allow") + ": " + r.InterfaceText + (r.Enabled ? "" : " (выкл)")));
    }

    void OnRestrictChanged()
    {
        if (suppressRestrict) return;
        var list = RulesFor(target);
        if (list == null || list.Count == 0)
        {
            suppressRestrict = true; chkRestrict.Checked = false; suppressRestrict = false;
            Warn("У выбранного приложения нет правил Тоннель FW.\nСоздайте ярлык с ограничением справа.");
            return;
        }
        bool enable = chkRestrict.Checked;
        chkRestrict.Enabled = false;
        RunPsUi(Program.FirewallSetEnabledBody(target, enable), res =>
        {
            chkRestrict.Enabled = true;
            if (res != "OK") Warn("Не удалось переключить ограничение: " + res);
            LoadRules();
        });
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
                     "Для ссылок и приложений Windows выключите переключатель «Только через VPN (брандмауэр)».");
                return;
            }
            if (!Program.HasAdapter(vpn))
            {
                Warn("VPN-адаптер «" + vpn + "» не найден в системе.\nВыберите адаптер из списка.");
                return;
            }
        }

        try
        {
            string lnk = Program.CreateShortcut(txtName.Text.Trim(), target, vpn);
            string baseMsg = "Ярлык «" + Path.GetFileNameWithoutExtension(lnk) + "» создан на рабочем столе.";
            if (!fw)
            {
                ShowInfo(baseMsg);
                LoadRules();
                return;
            }
            btnCreate.Enabled = false;
            btnCreate.Text = "Настраиваю брандмауэр…";
            string[] others = Program.FirewallAliases(vpn);
            RunPsUi(Program.FirewallInstallBody(target, vpn, others), res =>
            {
                btnCreate.Enabled = true;
                btnCreate.Text = "Создать ярлык";
                ShowInfo(res == "OK"
                    ? baseMsg + "\n\nБрандмауэр настроен: доступ в сеть только через «" + vpn + "»."
                    : baseMsg + "\n\nНе удалось создать правила брандмауэра: " + res);
                LoadRules();
            });
        }
        catch (Exception ex) { Warn("Не удалось создать ярлык: " + ex.Message); }
    }

    void RemoveFirewall()
    {
        if (!Program.IsExe(target)) { Warn("Сначала выберите программу .exe."); return; }
        btnRemoveRules.Enabled = false;
        RunPsUi(Program.FirewallRemoveBody(target), res =>
        {
            btnRemoveRules.Enabled = true;
            ShowInfo(res == "OK" ? "Правила для «" + Path.GetFileName(target) + "» удалены." : "Не удалось удалить правила: " + res);
            LoadRules();
        });
    }

    // ---------- правила ----------

    void LoadRules()
    {
        if (rulesLoading) return;
        rulesLoading = true;
        lblRuleCount.Text = "Загрузка…";
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
        LoadApps();
        RefreshRulesList();
        UpdateDetail();
        Filter();
    }

    FwRule SelRule()
    {
        return lv.SelectedItems.Count > 0 ? lv.SelectedItems[0].Tag as FwRule : null;
    }

    void RefreshRulesList()
    {
        string selectedName = null;
        var cur = SelRule();
        if (cur != null) selectedName = cur.Name;
        string q = txtFilter.Text.Trim();

        lv.BeginUpdate();
        lv.Items.Clear();
        int shown = 0;
        foreach (var r in rules)
        {
            string prog = string.IsNullOrEmpty(r.Program) ? "" : Path.GetFileName(r.Program);
            if (q.Length > 0 && prog.IndexOf(q, StringComparison.CurrentCultureIgnoreCase) < 0 &&
                r.Name.IndexOf(q, StringComparison.CurrentCultureIgnoreCase) < 0) continue;
            var it = new ListViewItem(new[]
            {
                prog,
                r.Action,
                r.Enabled ? "включено" : "выключено",
                r.InterfaceText,
                r.Name
            });
            it.Tag = r;
            lv.Items.Add(it);
            if (selectedName != null && r.Name == selectedName) it.Selected = true;
            shown++;
        }
        lv.EndUpdate();
        if (lv.SelectedItems.Count == 0 && lv.Items.Count > 0) lv.Items[0].Selected = true;
        int on = rules.Count(r => r.Enabled);
        lblRuleCount.Text = rules.Count == 0
            ? "Правил нет — создайте ярлык на странице «Приложения»."
            : "Найдено " + shown + " из " + rules.Count + "   ·   включено " + on;
        ResizeRuleColumns();
    }

    void ResizeRuleColumns()
    {
        if (lv.Columns.Count < 5) return;
        int w = lv.ClientSize.Width - 24;
        if (w < 200) return;
        lv.Columns[0].Width = (int)(w * 0.32);
        lv.Columns[1].Width = (int)(w * 0.11);
        lv.Columns[2].Width = (int)(w * 0.12);
        lv.Columns[3].Width = (int)(w * 0.27);
        lv.Columns[4].Width = w - lv.Columns[0].Width - lv.Columns[1].Width - lv.Columns[2].Width - lv.Columns[3].Width - 2;
    }

    void DrawRuleHeader(object sender, DrawListViewColumnHeaderEventArgs e)
    {
        using (var b = new SolidBrush(th.Back)) e.Graphics.FillRectangle(b, e.Bounds);
        TextRenderer.DrawText(e.Graphics, e.Header.Text, fSmall,
            new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 10, e.Bounds.Height),
            th.Muted, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        using (var pen = new Pen(th.Border)) e.Graphics.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
    }

    void DrawRuleRow(object sender, DrawListViewItemEventArgs e)
    {
        bool sel = e.Item.Selected;
        bool hover = e.ItemIndex == hoverRule && !sel;
        using (var b = new SolidBrush(sel ? th.AccentDim : (hover ? th.SurfaceHover : th.Surface))) e.Graphics.FillRectangle(b, e.Bounds);
        if (sel)
            using (var bar = new SolidBrush(th.Accent)) e.Graphics.FillRectangle(bar, e.Bounds.X, e.Bounds.Y, 3, e.Bounds.Height);
    }

    void DrawRuleCell(object sender, DrawListViewSubItemEventArgs e)
    {
        if (e.Item.Selected) using (var b = new SolidBrush(th.AccentDim)) e.Graphics.FillRectangle(b, e.Bounds);
        var r = e.Item.Tag as FwRule;
        Color c = th.Text;
        string text = e.SubItem.Text;
        if (e.ColumnIndex == 1 && r != null) c = r.IsBlock ? th.Accent : th.Text;
        if (e.ColumnIndex == 2) c = (r != null && r.Enabled) ? th.Accent : th.Muted;
        if (r != null && !r.Enabled) c = th.Muted;
        TextRenderer.DrawText(e.Graphics, text, fBody,
            new Rectangle(e.Bounds.X + 10, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height),
            c, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
    }

    void FillAdaptersInto(ComboBox cb)
    {
        cb.Items.Clear();
        cb.Items.Add("— не менять —");
        foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            if (n.NetworkInterfaceType != NetworkInterfaceType.Loopback && !cb.Items.Contains(n.Name)) cb.Items.Add(n.Name);
        cb.SelectedIndex = 0;
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
        var r = SelRule();
        if (r == null) { Warn("Сначала выберите правило в таблице."); return; }
        string prog = txtRuleProgram.Text.Trim();
        if (!Program.IsExe(prog)) { Warn("Укажите существующий .exe."); return; }
        string vpn = cmbRuleVpn.SelectedItem as string;

        string body;
        if (!string.IsNullOrEmpty(vpn) && !vpn.StartsWith("—"))
        {
            if (!Program.HasAdapter(vpn)) { Warn("VPN-адаптер «" + vpn + "» не найден."); return; }
            var sb = new StringBuilder();
            if (!string.Equals(prog, r.Program, StringComparison.OrdinalIgnoreCase))
                sb.AppendLine(Program.FirewallRemoveBody(r.Program));
            sb.Append(Program.FirewallInstallBody(prog, vpn, Program.FirewallAliases(vpn)));
            body = sb.ToString();
        }
        else
        {
            string action = cmbRuleAction.SelectedItem as string ?? "Block";
            string[] ifaces = txtRuleIfaces.Text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim()).Where(s => s.Length > 0).ToArray();
            if (ifaces.Length == 0) { Warn("Укажите адаптеры или выберите VPN-адаптер."); return; }
            body = Program.FirewallEditRuleBody(r, prog, action, ifaces, chkRuleEnabled.Checked);
        }
        btnApply.Enabled = false;
        btnApply.Text = "Применяется…";
        RunPsUi(body, res =>
        {
            btnApply.Enabled = true;
            btnApply.Text = "Применить изменения";
            if (res != "OK") Warn("Не удалось изменить правило: " + res);
            LoadRules();
        });
    }

    void ToggleSelectedRule(bool on)
    {
        var r = SelRule();
        if (r == null) { Warn("Сначала выберите правило в таблице."); return; }
        RunPsUi(Program.FirewallEditRuleBody(r, r.Program, r.Action, r.Interfaces, on), res =>
        {
            if (res != "OK") Warn("Не удалось переключить правило: " + res);
            LoadRules();
        });
    }

    void DeleteRule()
    {
        var r = SelRule();
        if (r == null) { Warn("Сначала выберите правило в таблице."); return; }
        if (MessageBox.Show(this, "Удалить правило «" + r.Name + "»?", Program.AppName,
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        RunPsUi(Program.FirewallDeleteRuleBody(r.Name), res =>
        {
            if (res != "OK") Warn("Не удалось удалить правило: " + res);
            LoadRules();
        });
    }

    // ---------- общее ----------

    void RunPsUi(string body, Action<string> done)
    {
        ThreadPool.QueueUserWorkItem(delegate
        {
            string res = Program.RunPs(body);
            try
            {
                if (!IsDisposed && IsHandleCreated) BeginInvoke((Action)delegate { if (done != null) done(res); });
            }
            catch { }
        });
    }

    void Warn(string m) { MessageBox.Show(this, m, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    void ShowInfo(string m) { MessageBox.Show(this, m, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information); }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, string l);

    [DllImport("dwmapi.dll")]
    static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int value, int size);

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    static extern int SetWindowTheme(IntPtr h, string app, string idList);
}
