using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Windows.Forms;

namespace ScreenLock
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            int timeoutSec = 0;
            int ti = Array.IndexOf(args, "--timeout");
            if (ti >= 0 && ti + 1 < args.Length) int.TryParse(args[ti + 1], out timeoutSec);

            bool created;
            using (var mtx = new Mutex(true, @"Local\ScreenLockTool_Badlyac", out created))
            {
                if (!created) return;

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                byte[] salt, hash;
                string pw = SetupDialog.Ask();
                if (pw == null) return;
                salt = Crypto.NewSalt();
                hash = Crypto.Hash(pw, salt);
                pw = null;

                try
                {
                    bool hookOk = KeyboardHook.Install();
                    LockSession.Run(salt, hash, timeoutSec, hookOk);
                }
                finally
                {
                    KeyboardHook.Uninstall();
                }
            }
        }
    }

    static class Crypto
    {
        public static byte[] NewSalt()
        {
            var s = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(s);
            return s;
        }

        public static byte[] Hash(string pw, byte[] salt)
        {
            using (var k = new Rfc2898DeriveBytes(pw, salt, 200000, HashAlgorithmName.SHA256))
                return k.GetBytes(32);
        }

        public static bool Equal(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }

    static class KeyboardHook
    {
        const int WH_KEYBOARD_LL = 13;
        const int VK_ESCAPE = 0x1B, VK_CONTROL = 0x11;
        const int VK_MENU = 0x12, VK_LMENU = 0xA4, VK_RMENU = 0xA5;
        const int VK_LWIN = 0x5B, VK_RWIN = 0x5C, VK_APPS = 0x5D;

        delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        struct KBDLLHOOKSTRUCT
        {
            public uint vkCode, scanCode, flags, time;
            public UIntPtr dwExtraInfo;
        }

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr SetWindowsHookEx(int id, HookProc proc, IntPtr hMod, uint threadId);
        [DllImport("user32.dll")]
        static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32.dll")]
        static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string name);
        [DllImport("user32.dll")]
        static extern short GetAsyncKeyState(int vKey);

        static HookProc _proc = Callback;
        static IntPtr _hook = IntPtr.Zero;

        public static bool Install()
        {
            if (_hook != IntPtr.Zero) return true;
            using (var p = Process.GetCurrentProcess())
                _hook = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(p.MainModule.ModuleName), 0);
            return _hook != IntPtr.Zero;
        }

        public static bool Reinstall()
        {
            Uninstall();
            return Install();
        }

        public static void Uninstall()
        {
            if (_hook != IntPtr.Zero) { UnhookWindowsHookEx(_hook); _hook = IntPtr.Zero; }
        }

        static IntPtr Callback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                var kb = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
                int vk = (int)kb.vkCode;

                bool block =
                    vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU ||
                    vk == VK_LWIN || vk == VK_RWIN || vk == VK_APPS ||
                    (vk == VK_ESCAPE && (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0);

                if (block) return (IntPtr)1;
            }
            return CallNextHookEx(_hook, nCode, wParam, lParam);
        }
    }

    static class TaskManagerGuard
    {
        const int IntervalMs = 100;
        const int DeniedTicksToWarn = 10;

        static readonly HashSet<string> Names = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "Taskmgr", "procexp", "procexp64", "ProcessHacker", "SystemInformer" };

        static readonly ManualResetEvent stop = new ManualResetEvent(false);
        static volatile bool accessDenied;

        public static bool AccessDenied { get { return accessDenied; } }

        public static void Start()
        {
            stop.Reset();
            new Thread(Loop) { IsBackground = true, Name = "TaskManagerGuard" }.Start();
        }

        public static void Stop()
        {
            stop.Set();
        }

        static void Loop()
        {
            int deniedTicks = 0;
            while (!stop.WaitOne(IntervalMs))
            {
                deniedTicks = KillAll() ? deniedTicks + 1 : 0;
                if (deniedTicks >= DeniedTicksToWarn) accessDenied = true;
            }
        }

        static bool KillAll()
        {
            bool denied = false;
            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    if (!Names.Contains(p.ProcessName)) continue;
                    try { p.Kill(); }
                    catch (System.ComponentModel.Win32Exception) { denied = true; }
                    catch (InvalidOperationException) { }
                }
            }
            return denied;
        }
    }

    static class Aurora
    {
        const int W = 192, H = 108;
        const float Aspect = (float)W / H;
        const float BaseR = 27, BaseG = 24, BaseB = 72;

        // R, G, B, 半徑, X 擺幅, Y 擺幅, X 週期(秒), Y 週期(秒), 相位
        static readonly float[][] Blobs =
        {
            new float[] {  79,  70, 229, 0.62f, 0.38f, 0.30f, 31, 43, 0.0f },
            new float[] { 124,  58, 237, 0.55f, 0.42f, 0.34f, 37, 29, 2.1f },
            new float[] {  37,  99, 235, 0.50f, 0.36f, 0.38f, 41, 34, 4.2f },
            new float[] { 192,  96, 184, 0.40f, 0.44f, 0.32f, 47, 38, 5.3f },
        };

        // 4x4 Bayer 抖動,消除深色漸層的色階
        static readonly float[] Dither =
        {
             0.5f/16,  8.5f/16,  2.5f/16, 10.5f/16,
            12.5f/16,  4.5f/16, 14.5f/16,  6.5f/16,
             3.5f/16, 11.5f/16,  1.5f/16,  9.5f/16,
            15.5f/16,  7.5f/16, 13.5f/16,  5.5f/16,
        };

        const int FrameMs = 50;

        static readonly float[] colors = new float[W * H * 3];
        static readonly ManualResetEvent stop = new ManualResetEvent(false);
        static Thread thread;

        // 繪圖全部在背景執行緒完成:鍵盤 hook 的回呼在 UI 執行緒上,不能被全螢幕繪圖卡住
        public static void Start(LockForm[] targets)
        {
            Render(0);
            foreach (var f in targets) f.ComposeFrame();

            stop.Reset();
            thread = new Thread(delegate () { Loop(targets); })
            {
                IsBackground = true,
                Name = "Aurora",
                Priority = ThreadPriority.BelowNormal,
            };
            thread.Start();
        }

        public static void Stop()
        {
            stop.Set();
            if (thread != null) thread.Join(1000);
        }

        static void Loop(LockForm[] targets)
        {
            var clock = Stopwatch.StartNew();
            while (true)
            {
                long begin = clock.ElapsedMilliseconds;
                try
                {
                    Render(clock.Elapsed.TotalSeconds);
                    foreach (var f in targets) f.ComposeFrame();
                }
                catch { } // 背景執行緒的例外會讓整個程式結束,等於直接解鎖

                int spent = (int)(clock.ElapsedMilliseconds - begin);
                if (stop.WaitOne(Math.Max(15, FrameMs - spent))) return;
            }
        }

        public static void Render(double seconds)
        {
            int n = Blobs.Length;
            var bx = new float[n];
            var by = new float[n];
            var inv = new float[n];
            for (int i = 0; i < n; i++)
            {
                float[] b = Blobs[i];
                bx[i] = (0.5f + b[4] * (float)Math.Sin(seconds * 2 * Math.PI / b[6] + b[8])) * Aspect;
                by[i] = 0.5f + b[5] * (float)Math.Sin(seconds * 2 * Math.PI / b[7] + b[8] * 1.7f);
                inv[i] = 1f / (b[3] * b[3]);
            }

            int p = 0;
            for (int y = 0; y < H; y++)
            {
                float fy = (float)y / H;
                for (int x = 0; x < W; x++)
                {
                    float fx = (float)x / W * Aspect;
                    float r = BaseR, g = BaseG, bl = BaseB;
                    for (int i = 0; i < n; i++)
                    {
                        float dx = fx - bx[i], dy = fy - by[i];
                        float q = 1f + (dx * dx + dy * dy) * inv[i];
                        float w = 0.9f / (q * q);
                        float[] c = Blobs[i];
                        r += (c[0] - r) * w;
                        g += (c[1] - g) * w;
                        bl += (c[2] - bl) * w;
                    }
                    colors[p++] = r;
                    colors[p++] = g;
                    colors[p++] = bl;
                }
            }
        }

        // 雙線性放大到目標尺寸(GDI+ 的 DrawImage 放大全螢幕要 70ms 以上)
        public static void Scale(Bitmap target)
        {
            int w = target.Width, h = target.Height;
            var x0 = new int[w];
            var fx = new float[w];
            for (int x = 0; x < w; x++)
            {
                float sx = Math.Max(0f, Math.Min(W - 1.001f, (x + 0.5f) * W / w - 0.5f));
                x0[x] = (int)sx * 3;
                fx[x] = sx - (int)sx;
            }

            var line = new float[W * 3];
            var row = new int[w];
            var data = target.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.WriteOnly, PixelFormat.Format32bppPArgb);
            try
            {
                for (int y = 0; y < h; y++)
                {
                    float sy = Math.Max(0f, Math.Min(H - 1.001f, (y + 0.5f) * H / h - 0.5f));
                    int top = (int)sy * W * 3, bottom = top + W * 3;
                    float fy = sy - (int)sy;
                    for (int i = 0; i < line.Length; i++)
                        line[i] = colors[top + i] + (colors[bottom + i] - colors[top + i]) * fy;

                    int dither = (y & 3) * 4;
                    for (int x = 0; x < w; x++)
                    {
                        int i = x0[x];
                        float f = fx[x], d = Dither[dither + (x & 3)];
                        int r = (int)(line[i] + (line[i + 3] - line[i]) * f + d);
                        int g = (int)(line[i + 1] + (line[i + 4] - line[i + 1]) * f + d);
                        int b = (int)(line[i + 2] + (line[i + 5] - line[i + 2]) * f + d);
                        row[x] = unchecked((int)0xFF000000) | r << 16 | g << 8 | b;
                    }
                    Marshal.Copy(row, 0, data.Scan0 + y * data.Stride, w);
                }
            }
            finally
            {
                target.UnlockBits(data);
            }
        }
    }

    class LockForm : Form
    {
        public static readonly Color FieldColor = Color.FromArgb(36, 32, 88);
        static readonly CultureInfo ZhTw = new CultureInfo("zh-TW");

        readonly bool hasCard;
        Bitmap overlay;
        Rectangle overlayRect;
        string overlayKey;

        readonly object frameLock = new object();
        Bitmap front, back;

        public LockForm(Rectangle bounds, bool hasCard)
        {
            this.hasCard = hasCard;
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            Bounds = bounds;
            BackColor = FieldColor;
            TopMost = true;
            ShowInTaskbar = false;
        }

        public float UiScale
        {
            get { return Math.Max(0.7f, Math.Min(1.6f, ClientSize.Height / 1080f)); }
        }

        Rectangle CardRect
        {
            get
            {
                float s = UiScale;
                int w = (int)(440 * s), h = (int)(176 * s);
                return new Rectangle((ClientSize.Width - w) / 2, ClientSize.Height / 2 + (int)(27 * s), w, h);
            }
        }

        public Rectangle FieldRect
        {
            get
            {
                float s = UiScale;
                Rectangle c = CardRect;
                int pad = (int)(28 * s);
                return new Rectangle(c.Left + pad, c.Top + (int)(56 * s), c.Width - pad * 2, (int)(46 * s));
            }
        }

        // 只有時間或訊息變動才重畫文字層
        void RefreshOverlay()
        {
            DateTime now = DateTime.Now;
            string key = ClientSize + "|" + now.ToString("yyyyMMddHHmm") + "|" + LockSession.Message;
            if (key == overlayKey) return;
            overlayKey = key;

            float s = UiScale;
            Rectangle card = CardRect;
            int top = card.Top - (int)(230 * s);
            int width = (int)(800 * s);
            overlayRect = new Rectangle((ClientSize.Width - width) / 2, top, width, card.Bottom + 2 - top);

            if (overlay != null) overlay.Dispose();
            overlay = new Bitmap(overlayRect.Width, overlayRect.Height, PixelFormat.Format32bppPArgb);

            using (var g = Graphics.FromImage(overlay))
            using (var center = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            using (var white = new SolidBrush(Color.White))
            using (var soft = new SolidBrush(Color.FromArgb(215, 255, 255, 255)))
            using (var timeFont = new Font("Segoe UI Light", 128 * s, GraphicsUnit.Pixel))
            using (var dateFont = new Font("Microsoft JhengHei UI", 28 * s, GraphicsUnit.Pixel))
            {
                g.TranslateTransform(-overlayRect.X, -overlayRect.Y);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAlias;

                g.DrawString(now.ToString("HH:mm"), timeFont, white,
                    new RectangleF(overlayRect.X, top, width, 150 * s), center);
                g.DrawString(now.ToString("M月d日 dddd", ZhTw), dateFont, soft,
                    new RectangleF(overlayRect.X, card.Top - 80 * s, width, 44 * s), center);

                if (hasCard) DrawCard(g, card, s, center, soft);
            }
        }

        void DrawCard(Graphics g, Rectangle card, float s, StringFormat center, Brush soft)
        {
            using (var path = RoundedRect(card, 20 * s))
            using (var fill = new SolidBrush(Color.FromArgb(38, 255, 255, 255)))
            using (var edge = new Pen(Color.FromArgb(70, 255, 255, 255), 1f))
            {
                g.FillPath(fill, path);
                g.DrawPath(edge, path);
            }

            Rectangle field = FieldRect;
            using (var path = RoundedRect(field, 12 * s))
            using (var fill = new SolidBrush(FieldColor))
                g.FillPath(fill, path);

            using (var hintFont = new Font("Microsoft JhengHei UI", 17 * s, GraphicsUnit.Pixel))
            using (var msgFont = new Font("Microsoft JhengHei UI", 16 * s, GraphicsUnit.Pixel))
            using (var msgBrush = new SolidBrush(Color.FromArgb(255, 214, 226)))
            {
                g.DrawString("輸入密碼解鎖", hintFont, soft,
                    new RectangleF(card.Left, card.Top + 18 * s, card.Width, 30 * s), center);
                g.DrawString(LockSession.Message, msgFont, msgBrush,
                    new RectangleF(card.Left + 12 * s, field.Bottom + 6 * s, card.Width - 24 * s, 56 * s), center);
            }
        }

        static GraphicsPath RoundedRect(Rectangle r, float radius)
        {
            float d = radius * 2;
            var p = new GraphicsPath();
            p.AddArc(r.Left, r.Top, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Top, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        public void ComposeFrame()
        {
            Size size = ClientSize;
            if (size.Width <= 0 || size.Height <= 0) return;

            if (back == null || back.Size != size)
            {
                if (back != null) back.Dispose();
                back = new Bitmap(size.Width, size.Height, PixelFormat.Format32bppPArgb);
            }

            Aurora.Scale(back);
            RefreshOverlay();
            using (var g = Graphics.FromImage(back))
                g.DrawImage(overlay, overlayRect);

            lock (frameLock)
            {
                Bitmap done = back;
                back = front;
                front = done;
            }
        }

        public void PresentFrame(Graphics g)
        {
            lock (frameLock)
            {
                if (front == null) { g.Clear(FieldColor); return; }
                g.CompositingMode = CompositingMode.SourceCopy;
                g.InterpolationMode = InterpolationMode.NearestNeighbor;
                g.DrawImage(front, new Rectangle(Point.Empty, front.Size));
            }
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            PresentFrame(e.Graphics);
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            Invalidate();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!LockSession.Unlocking) e.Cancel = true;
            base.OnFormClosing(e);
        }
    }

    static class LockSession
    {
        public static bool Unlocking;
        public static string Message = "";

        static readonly List<LockForm> forms = new List<LockForm>();
        static LockForm primary;
        static TextBox box;
        static byte[] _salt, _hash;
        static int fails;
        static DateTime lockedUntil = DateTime.MinValue;
        static bool guardWarned;

        public static void Run(byte[] salt, byte[] hash, int timeoutSec, bool hookOk)
        {
            _salt = salt; _hash = hash;

            Screen main = Screen.PrimaryScreen ?? Screen.AllScreens[0];
            foreach (var s in Screen.AllScreens)
            {
                var f = new LockForm(s.Bounds, s.Equals(main));
                forms.Add(f);
                if (s.Equals(main)) primary = f;
            }
            if (primary == null) primary = forms[0];

            Message = hookOk ? "" : "警告:鍵盤攔截未啟用,快捷鍵未被封鎖";

            box = new TextBox
            {
                UseSystemPasswordChar = true,
                BorderStyle = BorderStyle.None,
                BackColor = LockForm.FieldColor,
                ForeColor = Color.White,
                Font = new Font("Microsoft JhengHei UI", 20 * primary.UiScale, GraphicsUnit.Pixel),
            };
            primary.Controls.Add(box);

            Action layout = delegate
            {
                Rectangle field = primary.FieldRect;
                int pad = (int)(14 * primary.UiScale);
                box.Width = field.Width - pad * 2;
                box.Location = new Point(field.Left + pad, field.Top + (field.Height - box.Height) / 2);
            };
            primary.Shown += delegate { layout(); box.Focus(); };

            box.KeyDown += delegate (object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; TryUnlock(); }
            };

            DateTime started = DateTime.Now;
            var timer = new System.Windows.Forms.Timer { Interval = 300 };
            timer.Tick += delegate
            {
                if (Unlocking) return;
                foreach (var f in forms) { f.TopMost = true; f.BringToFront(); }
                primary.Activate();
                if (!box.Focused) box.Focus();

                if (TaskManagerGuard.AccessDenied && !guardWarned)
                {
                    guardWarned = true;
                    Message = "警告:工作管理員的權限較高,無法強制關閉";
                }

                if (timeoutSec > 0 && (DateTime.Now - started).TotalSeconds >= timeoutSec) Unlock();
            };
            timer.Start();

            Aurora.Start(forms.ToArray());
            var animation = new System.Windows.Forms.Timer { Interval = 50 };
            animation.Tick += delegate
            {
                if (Unlocking) return;
                foreach (var f in forms) f.Invalidate();
            };
            animation.Start();

            TaskManagerGuard.Start();

            foreach (var f in forms) if (f != primary) f.Show();
            Application.Run(primary);
        }

        static void TryUnlock()
        {
            if (DateTime.Now < lockedUntil) return;

            byte[] h = Crypto.Hash(box.Text, _salt);
            box.Clear();
            if (Crypto.Equal(h, _hash)) { Unlock(); return; }

            fails++;
            int delay = fails >= 3 ? Math.Min(5 * (1 << Math.Min(fails - 3, 6)), 300) : 0;
            lockedUntil = DateTime.Now.AddSeconds(delay);
            Message = delay > 0 ? "密碼錯誤,請 " + delay + " 秒後再試" : "密碼錯誤";
        }

        static void Unlock()
        {
            Unlocking = true;
            Aurora.Stop();
            TaskManagerGuard.Stop();
            KeyboardHook.Uninstall();
            foreach (var f in forms) if (f != primary) f.Close();
            primary.Close();
        }
    }

    static class SetupDialog
    {
        public static string Ask()
        {
            using (var f = new Form())
            {
                f.Text = "螢幕鎖 - 設定解鎖密碼";
                f.FormBorderStyle = FormBorderStyle.FixedDialog;
                f.StartPosition = FormStartPosition.CenterScreen;
                f.MaximizeBox = false; f.MinimizeBox = false;
                f.ClientSize = new Size(320, 150);
                f.Font = new Font("Microsoft JhengHei UI", 9f);

                var l1 = new Label { Text = "密碼", Left = 15, Top = 18, AutoSize = true };
                var t1 = new TextBox { Left = 90, Top = 15, Width = 210, UseSystemPasswordChar = true };
                var l2 = new Label { Text = "再輸入一次", Left = 15, Top = 53, AutoSize = true };
                var t2 = new TextBox { Left = 90, Top = 50, Width = 210, UseSystemPasswordChar = true };
                var ok = new Button { Text = "鎖定", Left = 130, Top = 100, Width = 80 };
                var cancel = new Button { Text = "取消", Left = 220, Top = 100, Width = 80, DialogResult = DialogResult.Cancel };
                f.AcceptButton = ok; f.CancelButton = cancel;
                f.Controls.AddRange(new Control[] { l1, t1, l2, t2, ok, cancel });

                string pw = null;
                ok.Click += delegate
                {
                    if (t1.Text.Length < 4) { MessageBox.Show("密碼至少 4 個字元"); return; }
                    if (t1.Text != t2.Text) { MessageBox.Show("兩次輸入不一致"); return; }
                    pw = t1.Text;
                    f.DialogResult = DialogResult.OK;
                };

                return f.ShowDialog() == DialogResult.OK ? pw : null;
            }
        }
    }
}