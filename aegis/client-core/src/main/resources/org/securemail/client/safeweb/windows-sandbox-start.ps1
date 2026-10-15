# Static trusted guest bootstrap. No host secrets or arbitrary command text.
# The only host mapping is C:\SafeWeb, the dedicated browser session bundle.
$ErrorActionPreference = 'Stop'
$runtime = $PSScriptRoot
$nonce = Split-Path -Leaf $runtime
$counter = 0
$owned = $null
function State([string]$value) {
    $script:counter++
    [IO.File]::WriteAllText((Join-Path $runtime 'state.txt'),
        ($value + ':' + $nonce + ':' + $script:counter), [Text.Encoding]::ASCII)
}
try {
    if ($nonce -cnotmatch '^[a-f0-9-]{36}$') { throw 'SESSION' }
    $urlFile = Join-Path $runtime 'url.b64'
    if ((Get-Item -LiteralPath $urlFile).Length -gt 6000) { throw 'URL' }
    $url = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String([IO.File]::ReadAllText($urlFile)))
    if ($url.Length -gt 4096 -or $url -match '[\x00-\x20\x7f-\xff"\\]') { throw 'URL' }
    $uri = $null
    if (-not [Uri]::TryCreate($url,[UriKind]::Absolute,[ref]$uri) -or $uri.UserInfo -or
        $uri.HostNameType -ne [UriHostNameType]::Dns -or $uri.Host -notmatch '\.' -or
        $uri.Host -match '(?i)(^|\.)localhost$' -or $uri.Port -eq 0) { throw 'URL' }
    $onion = $uri.Host -match '(?i)^(?:[a-z0-9-]+\.)*[a-z2-7]{56}\.onion$'
    if (($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $onion)) -or
        ($uri.Host.EndsWith('.onion') -and -not $onion)) { throw 'URL' }
    # Complete unmodified bundle, its own Tor and its stock profile stay together.
    $browser = 'C:\SafeWeb\Browser\firefox.exe'
    $profile = 'C:\SafeWeb\Browser\TorBrowser\Data\Browser\profile.default'
    if (-not (Test-Path -LiteralPath $browser -PathType Leaf) -or
        -not (Test-Path -LiteralPath $profile -PathType Container)) { throw 'BUNDLE' }
    # Download-directory preferences only: no proxy, WebRTC, JavaScript,
    # fingerprinting, security-slider, extension or sandbox changes.
    $prefs = Join-Path $profile 'user.js'
    $original = $(if (Test-Path -LiteralPath $prefs) {[IO.File]::ReadAllText($prefs)} else {''})
    $begin = '// AEGIS_DOWNLOAD_DIRECTORY_BEGIN'
    $end = '// AEGIS_DOWNLOAD_DIRECTORY_END'
    $original = [regex]::Replace($original,
        '(?s)\r?\n?// AEGIS_DOWNLOAD_DIRECTORY_BEGIN.*?// AEGIS_DOWNLOAD_DIRECTORY_END\r?\n?', '')
    [IO.Directory]::CreateDirectory('C:\SafeWeb\aegis-downloads') | Out-Null
    $downloadPrefs = @'
// AEGIS_DOWNLOAD_DIRECTORY_BEGIN
user_pref("browser.download.folderList", 2);
user_pref("browser.download.dir", "C:\\SafeWeb\\aegis-downloads");
user_pref("browser.download.useDownloadDir", true);
// AEGIS_DOWNLOAD_DIRECTORY_END
'@
    [IO.File]::WriteAllText($prefs,($original + "`r`n" + $downloadPrefs + "`r`n"),[Text.UTF8Encoding]::new($false))
    # Native Job Object contains the Firefox launcher and all descendant browser,
    # Tor and update processes. The root may exit while its children keep running.
    # No browser sandbox is disabled to make an external AppContainer work.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace AegisSafeWeb {
 public sealed class BrowserJob : IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct STARTUPINFO {
   public uint cb; public IntPtr reserved,desktop,title; public uint x,y,width,height,
    xChars,yChars,fill,flags; public ushort show,reservedSize; public IntPtr reserved2,
    stdin,stdout,stderr;
  }
  [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION {
   public IntPtr process,thread; public uint pid,tid;
  }
  [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMIT {
   public long processTime,jobTime;public uint flags;public UIntPtr minimum,maximum;
   public uint processes;public UIntPtr affinity;public uint priority,scheduling;
  }
  [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS {
   public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes;
  }
  [StructLayout(LayoutKind.Sequential)] struct EXTENDED_LIMIT {
   public BASIC_LIMIT basic;public IO_COUNTERS io;public UIntPtr processMemory,jobMemory,
    peakProcessMemory,peakJobMemory;
  }
  [StructLayout(LayoutKind.Sequential)] struct ACCOUNTING {
   public long user,kernel,periodUser,periodKernel; public uint faults,total,active,terminated;
  }
  [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  static extern IntPtr CreateJobObject(IntPtr security,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(
    IntPtr job,int type,ref EXTENDED_LIMIT value,uint length);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(
    IntPtr job,int type,out ACCOUNTING value,uint length,IntPtr resultLength);
  [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool CreateProcess(
    string app,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,
    bool inherit,uint flags,IntPtr environment,string cwd,ref STARTUPINFO start,out PROCESS_INFORMATION process);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  IntPtr job;
  static string Quote(string arg) {
   StringBuilder result=new StringBuilder("\"");int slashes=0;
   foreach(char c in arg) {
    if(c=='\\'){slashes++;continue;}
    result.Append('\\',c=='"'?slashes*2+1:slashes);slashes=0;result.Append(c);
   }
   result.Append('\\',slashes*2);result.Append('"');return result.ToString();
  }
  public BrowserJob(string app,string profile,string url) {
   job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new Win32Exception();
   try {
    EXTENDED_LIMIT limits=new EXTENDED_LIMIT();limits.basic.flags=0x2000;
    if(!SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(EXTENDED_LIMIT))))throw new Win32Exception();
    STARTUPINFO si=new STARTUPINFO();si.cb=(uint)Marshal.SizeOf(typeof(STARTUPINFO));
    PROCESS_INFORMATION pi;
    string command=Quote(app)+" -no-remote -profile "+Quote(profile)+" -new-window "+Quote(url);
    if(!CreateProcess(app,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,
       0x00000004|0x08000000,IntPtr.Zero,"C:\\SafeWeb",ref si,out pi))throw new Win32Exception();
    try {
     if(!AssignProcessToJobObject(job,pi.process)) {TerminateProcess(pi.process,1);throw new Win32Exception();}
     if(ResumeThread(pi.thread)==UInt32.MaxValue){TerminateProcess(pi.process,1);throw new Win32Exception();}
    } finally {CloseHandle(pi.thread);CloseHandle(pi.process);}
   } catch {Dispose();throw;}
  }
  public bool Running {
   get {ACCOUNTING accounting;if(job==IntPtr.Zero)return false;
    if(!QueryInformationJobObject(job,1,out accounting,(uint)Marshal.SizeOf(typeof(ACCOUNTING)),IntPtr.Zero))throw new Win32Exception();
    return accounting.active>0;}
  }
  public void Dispose(){if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}}
 }
}
'@
    $owned = [AegisSafeWeb.BrowserJob]::new($browser,$profile,$url)
    $lastLease = ''
    $leaseClock = [Diagnostics.Stopwatch]::StartNew()
    $started = [Diagnostics.Stopwatch]::StartNew()
    while ($owned.Running) {
        $stop = Join-Path $runtime 'stop.txt'
        if ((Test-Path -LiteralPath $stop) -and [IO.File]::ReadAllText($stop) -ceq $nonce) { break }
        try {
            $lease = [IO.File]::ReadAllText((Join-Path $runtime 'lease.txt'))
            if ($lease -cmatch ('^' + [regex]::Escape($nonce) + ':[0-9]{1,16}$') -and $lease -cne $lastLease) {
                $lastLease = $lease
                $leaseClock.Restart()
            }
        } catch { }
        if ($leaseClock.Elapsed.TotalSeconds -gt 15) { break }
        State 'PROCESS_CREATED'
        Start-Sleep -Milliseconds 1000
    }
    if ($started.Elapsed.TotalSeconds -lt 3) { State 'ERROR' } else { State 'CLOSED' }
} catch {
    # Exception details can include URLs, profile paths or browser output.
    # Only this fixed status is exposed to the host controller.
    try { State 'ERROR' } catch { }
} finally {
    if ($null -ne $owned) { $owned.Dispose() }
    # This runs inside the disposable guest, never on the host.
    & 'C:\Windows\System32\shutdown.exe' '/s' '/f' '/t' '0' | Out-Null
}
