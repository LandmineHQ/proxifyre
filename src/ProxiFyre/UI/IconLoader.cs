using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ProxiFyre;

internal static class IconLoader
{
    public static ImageSource? ExtractIcon(string path)
    {
        var iconHandle = IntPtr.Zero;
        try
        {
            iconHandle = ExtractAssociatedIcon(IntPtr.Zero, path, out _);
            if (iconHandle == IntPtr.Zero)
            {
                return null;
            }

            var source = Imaging.CreateBitmapSourceFromHIcon(
                iconHandle,
                Int32Rect.Empty,
                BitmapSizeOptions.FromWidthAndHeight(32, 32));
            source.Freeze();
            return source;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (iconHandle != IntPtr.Zero)
            {
                DestroyIcon(iconHandle);
            }
        }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr ExtractAssociatedIcon(IntPtr hInst, string pszIconPath, out ushort piIcon);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr hIcon);
}
