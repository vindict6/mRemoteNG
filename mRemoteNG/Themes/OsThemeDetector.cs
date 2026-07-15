using System;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace mRemoteNG.Themes
{
    /// <summary>
    /// Reads the Windows app theme preference (Settings > Personalization > Colors > "Choose your default app mode").
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class OsThemeDetector
    {
        private const string PersonalizeKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
        private const string AppsUseLightThemeValue = "AppsUseLightTheme";

        /// <summary>
        /// True when Windows is set to dark app mode.
        /// </summary>
        /// <remarks>
        /// The value is absent on Windows versions that predate the setting, and on those the shell only ever
        /// rendered light, so a missing value is reported as light rather than as an error.
        /// </remarks>
        public static bool IsOsInDarkMode()
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(PersonalizeKey);
                // 0 = dark, 1 = light.
                return key?.GetValue(AppsUseLightThemeValue) is int appsUseLightTheme && appsUseLightTheme == 0;
            }
            catch (Exception)
            {
                // A theme preference is never worth failing startup over; fall back to light.
                return false;
            }
        }
    }
}
