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


// Вертикальная навигация вместо телефонных вкладок.
class SideNav : Control
{
    readonly Theme th;
    public string[] Titles = new string[0];
    int selected, hoverIndex = -1;
    float barY, barTarget;
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 15 };
    Rectangle[] rects = new Rectangle[0];

    public SideNav(Theme theme)
    {
        th = theme;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = theme.Back;
        ForeColor = theme.Text;
        Font = new Font("Segoe UI Semibold", 11f);
        Cursor = Ui.Hand;
        Height = 96;
        timer.Tick += delegate
        {
            float d = barTarget - barY;
            if (Math.Abs(d) < 0.6f) { barY = barTarget; timer.Stop(); }
            else barY += d * 0.3f;
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
            barTarget = ItemTop(value);
            if (barY < 0) barY = barTarget;
            timer.Start();
            Invalidate();
            if (SelectedChanged != null) SelectedChanged(this, EventArgs.Empty);
        }
    }

    float ItemTop(int i) { return i * (Height / 2f); }

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
        for (int i = 0; i < rects.Length; i++) if (rects[i].Contains(x, y)) return i;
        return -1;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(th.Back);
        int h = Math.Max(1, Height / 2);
        rects = new Rectangle[Titles.Length];
        for (int i = 0; i < Titles.Length; i++)
        {
            var r = new Rectangle(0, i * h, Width, h);
            rects[i] = r;
            if (i == hoverIndex && i != selected)
                using (var b = new SolidBrush(th.SurfaceHover)) g.FillRectangle(b, r.X, r.Y + 4, r.Width, r.Height - 8);
            if (i == selected && barY >= 0)
                using (var b = new SolidBrush(th.Accent)) g.FillRectangle(b, 0, (int)barY + 6, 3, h - 12);
            var tr = new Rectangle(r.X + 16, r.Y, r.Width - 20, r.Height);
            TextRenderer.DrawText(g, Titles[i], Font, tr,
                i == selected ? th.Text : (i == hoverIndex ? Color.FromArgb(205, 205, 205) : th.Muted),
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
        }
    }
}

// Небольшой слой эффектов: 160x160 вокруг курсора вместо битмапа на всё окно.
class CursorOverlay : Form
{
    const int Box = 160;
    readonly Theme th;
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 22 };
    float ringR, ringA;
    bool ringOn, shown, dirty;
    Rectangle ownerRect;
    bool ownerActive;

    public CursorOverlay(Theme theme)
    {
        th = theme;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        BackColor = Color.Black;
        Size = new Size(Box, Box);
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

    public void Follow(Rectangle clientOnScreen, bool active)
    {
        ownerRect = clientOnScreen;
        ownerActive = active;
        if (!Ui.Effects || !active) { Stop(); return; }
        Point p = Cursor.Position;
        if (!ownerRect.Contains(p)) { Stop(); return; }
        var b = new Rectangle(p.X - Box / 2, p.Y - Box / 2, Box, Box);
        if (Bounds != b) { Bounds = b; dirty = true; }
        if (!shown) { Show(); shown = true; }
        if (!timer.Enabled) timer.Start();
        dirty = true;
    }

    public void Pulse()
    {
        if (!Ui.Effects || !ownerActive) return;
        ringOn = true; ringR = 6; ringA = 0.9f; dirty = true;
        if (!timer.Enabled) timer.Start();
    }

    public void Stop()
    {
        timer.Stop();
        if (shown) { Hide(); shown = false; }
    }

    void Frame()
    {
        if (!Ui.Effects || !ownerActive) { Stop(); return; }
        Point p = Cursor.Position;
        if (!ownerRect.Contains(p)) { Stop(); return; }
        var b = new Rectangle(p.X - Box / 2, p.Y - Box / 2, Box, Box);
        if (Bounds != b) { Bounds = b; dirty = true; }
        if (ringOn) { ringR += 6f; ringA -= 0.055f; if (ringA <= 0) ringOn = false; }
        if (!dirty && !ringOn) return;
        dirty = false;
        Render();
    }

    void Render()
    {
        try
        {
            using (var bmp = new Bitmap(Box, Box, PixelFormat.Format32bppPArgb))
            {
                using (var g = Graphics.FromImage(bmp))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.Clear(Color.Transparent);
                    int cx = Box / 2, cy = Box / 2;
                    for (int i = 3; i >= 1; i--)
                    {
                        int r = 5 + i * 5, a = 24 - i * 5;
                        using (var b = new SolidBrush(Color.FromArgb(a, th.Accent)))
                            g.FillEllipse(b, cx - r, cy - r, r * 2, r * 2);
                    }
                    if (ringOn)
                    {
                        int r = (int)ringR;
                        if (r < Box / 2 - 4)
                            using (var p = new Pen(Color.FromArgb((int)(150 * Math.Max(0, ringA)), th.Accent), 2f))
                                g.DrawEllipse(p, cx - r, cy - r, r * 2, r * 2);
                    }
                }
                Present(bmp);
            }
        }
        catch { Ui.Effects = false; Stop(); }
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
                Stop();
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
