using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ScreenLock
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (Array.IndexOf(args, "--restore") >= 0)
            {
                PolicyGuard.Restore();
                return;
            }

            int timeoutSec = 0;
            int ti = Array.IndexOf(args, "--timeout");
            if (ti >= 0 && ti + 1 < args.Length) int.TryParse(args[ti + 1], out timeoutSec);

            bool created;
            using (var mtx = new Mutex(true, @"Local\ScreenLockTool_Badlyac", out created))
            {
                if (!created) return;

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                PolicyGuard.RestoreIfResidue();

                byte[] salt, hash;
                string pw = SetupDialog.Ask();
                if (pw == null) return;
                salt = Crypto.NewSalt();
                hash = Crypto.Hash(pw, salt);
                pw = null;

                bool policyOk = false;
                try
                {
                    policyOk = PolicyGuard.Apply();
                    KeyboardHook.Install();
                    LockSession.Run(salt, hash, timeoutSec, policyOk);
                }
                finally
                {
                    KeyboardHook.Uninstall();
                    PolicyGuard.Restore();
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

    static class PolicyGuard
    {
        const string SysKey = @"Software\Microsoft\Windows\CurrentVersion\Policies\System";
        const string ExpKey = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        const string OwnKey = @"Software\ScreenLockTool";

        static readonly string[][] Items =
        {
            [SysKey, "DisableTaskMgr" ],          // 工作管理員(含 Ctrl+Shift+Esc)
            [SysKey, "DisableLockWorkstation"],  // Win+L / 鎖定
            [SysKey, "DisableChangePassword"],   // 變更密碼
            [ExpKey, "NoLogoff"],                // 登出
            [ExpKey, "NoClose"],                 // 關機/重新啟動
        };

        public static bool Apply()
        {
            try
            {
                using (var own = Registry.CurrentUser.CreateSubKey(OwnKey))
                using (var bk = own.CreateSubKey("Backup"))
                {
                    for (int i = 0; i < Items.Length; i++)
                    {
                        using (var k = Registry.CurrentUser.CreateSubKey(Items[i][0]))
                        {
                            object old = k.GetValue(Items[i][1]);
                            if (old != null)
                                bk.SetValue(i.ToString(), old, k.GetValueKind(Items[i][1]));
                        }
                    }
                    own.SetValue("Active", 1, RegistryValueKind.DWord);
                }

                foreach (var it in Items)
                    using (var k = Registry.CurrentUser.CreateSubKey(it[0]))
                        k.SetValue(it[1], 1, RegistryValueKind.DWord);

                return true;
            }
            catch
            {
                Restore();
                return false;
            }
        }

        public static void Restore()
        {
            try
            {
                using (var own = Registry.CurrentUser.OpenSubKey(OwnKey))
                using (var bk = own == null ? null : own.OpenSubKey("Backup"))
                {
                    for (int i = 0; i < Items.Length; i++)
                    {
                        using (var k = Registry.CurrentUser.CreateSubKey(Items[i][0]))
                        {
                            object old = bk == null ? null : bk.GetValue(i.ToString());
                            if (old != null)
                                k.SetValue(Items[i][1], old, bk.GetValueKind(i.ToString()));
                            else
                                k.DeleteValue(Items[i][1], false);
                        }
                    }
                }
                Registry.CurrentUser.DeleteSubKeyTree(OwnKey, false);
            }
            catch { }
        }

        public static void RestoreIfResidue()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(OwnKey))
                    if (k != null && k.GetValue("Active") != null) Restore();
            }
            catch { }
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

        public static void Install()
        {
            if (_hook != IntPtr.Zero) return;
            using (var p = Process.GetCurrentProcess())
                _hook = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(p.MainModule.ModuleName), 0);
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

    class LockForm : Form
    {
        public LockForm(Rectangle bounds)
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            Bounds = bounds;
            BackColor = Color.Black;
            TopMost = true;
            ShowInTaskbar = false;
            DoubleBuffered = true;
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            if (ClientRectangle.Width <= 0 || ClientRectangle.Height <= 0) return;
            using (var br = new LinearGradientBrush(ClientRectangle,
                Color.FromArgb(37, 99, 235),
                Color.FromArgb(147, 51, 234),
                LinearGradientMode.ForwardDiagonal))
            {
                e.Graphics.FillRectangle(br, ClientRectangle);
            }
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

        static readonly List<Form> forms = new List<Form>();
        static Form primary;
        static TextBox box;
        static Label msg;
        static byte[] _salt, _hash;
        static int fails;
        static DateTime lockedUntil = DateTime.MinValue;

        public static void Run(byte[] salt, byte[] hash, int timeoutSec, bool policyOk)
        {
            _salt = salt; _hash = hash;

            foreach (var s in Screen.AllScreens)
            {
                var f = new LockForm(s.Bounds);
                forms.Add(f);
                if (s.Primary) primary = f;
            }
            if (primary == null) primary = forms[0];

            box = new TextBox
            {
                UseSystemPasswordChar = true,
                Width = 280,
                Font = new Font("Microsoft JhengHei UI", 14f),
            };
            msg = new Label
            {
                ForeColor = Color.White,
                BackColor = Color.Transparent,
                Font = new Font("Microsoft JhengHei UI", 11f),
                AutoSize = true,
                Text = policyOk ? "" : "警告:此電腦限制了登錄檔,Ctrl+Alt+Del 選單未被停用",
            };
            primary.Controls.Add(box);
            primary.Controls.Add(msg);

            Action layout = delegate
            {
                int cx = primary.ClientSize.Width / 2, cy = primary.ClientSize.Height / 2;
                box.Location = new Point(cx - box.Width / 2, cy - box.Height / 2);
                msg.Location = new Point(cx - msg.Width / 2, cy + box.Height / 2 + 15);
            };
            primary.Shown += delegate { layout(); box.Focus(); };
            msg.TextChanged += delegate { layout(); };

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

                if (timeoutSec > 0 && (DateTime.Now - started).TotalSeconds >= timeoutSec) Unlock();
            };
            timer.Start();

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
            msg.Text = delay > 0 ? "密碼錯誤,請 " + delay + " 秒後再試" : "密碼錯誤";
        }

        static void Unlock()
        {
            Unlocking = true;
            KeyboardHook.Uninstall();
            PolicyGuard.Restore();
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
