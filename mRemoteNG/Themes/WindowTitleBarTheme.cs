using System;
using System.Drawing;
using System.Runtime.Versioning;
using System.Windows.Forms;
using mRemoteNG.App;

namespace mRemoteNG.Themes
{
    /// <summary>
    /// Switches window title bars between the light and dark shell rendering, which the theming
    /// palette cannot reach: the caption is drawn by the desktop window manager, not by the app.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class WindowTitleBarTheme
    {
        // Documented as DWMWA_USE_IMMERSIVE_DARK_MODE. Windows 10 builds before 20H1 shipped it
        // under attribute 19; it settled on 20 from 20H1 onwards. Neither is honoured on older
        // builds, where DwmSetWindowAttribute simply fails and the caption stays light.
        private const int DwmwaUseImmersiveDarkModePre20H1 = 19;
        private const int DwmwaUseImmersiveDarkMode = 20;

        /// <summary>
        /// Applies the caption style matching the active theme.
        /// </summary>
        /// <remarks>
        /// Does nothing until the handle exists, since there is no window to address yet; callers
        /// should re-apply from HandleCreated for windows themed before they are shown.
        /// </remarks>
        public static void Apply(Form? form)
        {
            if (form == null || !form.IsHandleCreated) return;
            Apply(form.Handle, IsActiveThemeDark());
        }

        /// <summary>
        /// Applies the caption style to an arbitrary window handle.
        /// </summary>
        public static void Apply(IntPtr handle, bool dark)
        {
            if (handle == IntPtr.Zero) return;

            int useDarkMode = dark ? 1 : 0;
            try
            {
                // A non-zero HRESULT just means this build does not know the attribute, so try the
                // older ordinal before giving up. There is no reliable way to ask in advance.
                if (NativeMethods.DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkMode, ref useDarkMode, sizeof(int)) != 0)
                {
                    NativeMethods.DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkModePre20H1, ref useDarkMode, sizeof(int));
                }
            }
            catch (Exception)
            {
                // dwmapi.dll is unavailable (or the attribute is rejected). A light caption on a dark
                // theme is a cosmetic flaw and must never take the window down with it.
            }
        }

        /// <summary>
        /// Decides whether the active theme wants a dark caption, by measuring the theme's own
        /// dialog background rather than matching on theme names, so cloned and hand-edited themes
        /// are classified correctly.
        /// </summary>
        public static bool IsActiveThemeDark()
        {
            try
            {
                ThemeManager themeManager = ThemeManager.getInstance();
                if (!themeManager.ActiveAndExtended) return false;

                Color background = themeManager.ActiveTheme.ExtendedPalette.getColor("Dialog_Background");
                return IsDark(background);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Perceived brightness (ITU-R BT.601 luma), below the midpoint.
        /// </summary>
        private static bool IsDark(Color color)
        {
            // A missing palette key resolves to Color.Pink, which is light, so unthemed elements
            // fall out as light rather than being misread as dark.
            double luma = (0.299 * color.R) + (0.587 * color.G) + (0.114 * color.B);
            return luma < 128.0;
        }
    }
}
