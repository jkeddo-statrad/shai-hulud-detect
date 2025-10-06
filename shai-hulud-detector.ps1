<# 
Shai-Hulud NPM Supply Chain Attack Detection (PowerShell port)
- Faithful translation of the provided bash script with added progress, durability, and optional resume.
- Requires: PowerShell 7+ for parallel speedups (falls back to sequential on PS5).
- Exit codes: 0 = clean, 1 = high-risk found, 2 = medium-risk only.

Usage examples:
  pwsh -NoLogo -NoProfile -File .\shai-hulud-detector.ps1 -ScanDir 'C:\repo'
  pwsh -NoLogo -NoProfile -File .\shai-hulud-detector.ps1 -ScanDir 'C:\repo' -Paranoid -Parallelism 8 `
        -StatePath 'C:\temp\shai_state.json' -ProgressLog 'C:\temp\shai_progress.log'
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ScanDir,

  [switch]$Paranoid,

  [ValidateRange(1, 256)]
  [int]$Parallelism = [int]([Environment]::GetEnvironmentVariable('NUMBER_OF_PROCESSORS')),

  # Optional: progress & resume
  [string]$StatePath   = "$(Join-Path -Path (Get-Location) -ChildPath 'shai_hulud_state.json')",
  [string]$ProgressLog = "$(Join-Path -Path (Get-Location) -ChildPath 'shai_hulud_progress.log')"
)

# ---------- Config / Globals ----------
$script:IsPS7 = $PSVersionTable.PSVersion.Major -ge 7
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Temp files tracked for cleanup
$script:TempFiles = New-Object System.Collections.Generic.List[string]

# Findings
$script:WORKFLOW_FILES                = New-Object System.Collections.Generic.List[string]
$script:MALICIOUS_HASHES              = New-Object System.Collections.Generic.List[string]
$script:COMPROMISED_FOUND             = New-Object System.Collections.Generic.List[string]
$script:SUSPICIOUS_FOUND              = New-Object System.Collections.Generic.List[string]
$script:SUSPICIOUS_CONTENT            = New-Object System.Collections.Generic.List[string]
$script:CRYPTO_PATTERNS               = New-Object System.Collections.Generic.List[string]
$script:GIT_BRANCHES                  = New-Object System.Collections.Generic.List[string]
$script:POSTINSTALL_HOOKS             = New-Object System.Collections.Generic.List[string]
$script:TRUFFLEHOG_ACTIVITY           = New-Object System.Collections.Generic.List[string]
$script:SHAI_HULUD_REPOS              = New-Object System.Collections.Generic.List[string]
$script:NAMESPACE_WARNINGS            = New-Object System.Collections.Generic.List[string]
$script:LOW_RISK_FINDINGS             = New-Object System.Collections.Generic.List[string]
$script:INTEGRITY_ISSUES              = New-Object System.Collections.Generic.List[string]
$script:TYPOSQUATTING_WARNINGS        = New-Object System.Collections.Generic.List[string]
$script:NETWORK_EXFILTRATION_WARNINGS = New-Object System.Collections.Generic.List[string]
$script:LOCKFILE_SAFE_VERSIONS        = New-Object System.Collections.Generic.List[string]

# Known malicious file hashes (SHA-256)
$script:MALICIOUS_HASHLIST = @(
  'de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6',
  '81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3',
  '83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e',
  '4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db',
  'dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c',
  '46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09',
  'b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777',
  '86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b',
  'aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee'
)

# Known compromised namespaces
$script:COMPROMISED_NAMESPACES = @(
  '@crowdstrike','@art-ws','@ngx','@ctrl','@nativescript-community','@ahmedhfarag','@operato',
  '@teselagen','@things-factory','@hestjs','@nstudio','@basic-ui-components-stc',
  '@nexe','@thangved','@tnf-dev','@ui-ux-gang','@yoobic'
)

# Popular packages (for typosquatting heuristics)
$script:POPULAR_PACKAGES = @(
  'react','vue','angular','express','lodash','axios','typescript','webpack','babel','eslint',
  'jest','mocha','chalk','debug','commander','inquirer','yargs','request','moment','underscore',
  'jquery','bootstrap','socket.io','redis','mongoose','passport'
)

# Suspicious exfil domains
$script:SUSPICIOUS_DOMAINS = @(
  'pastebin.com','hastebin.com','ix.io','0x0.st','transfer.sh','file.io','anonfiles.com','mega.nz',
  'dropbox.com/s/','discord.com/api/webhooks','telegram.org','t.me','ngrok.io','localtunnel.me',
  'serveo.net','requestbin.com','webhook.site','beeceptor.com','pipedream.com','zapier.com/hooks'
)

# ---------- Utility: output, progress, logging ----------
function Write-Status {
  param([ValidateSet('Red','Yellow','Green','Blue','Cyan','Gray','White')] [string]$Color,
        [Parameter(Mandatory)][string]$Msg)
  Write-Host $Msg -ForegroundColor $Color
}

function Write-ProgressLog {
  param([string]$Line)
  if ([string]::IsNullOrWhiteSpace($ProgressLog)) { return }
  try {
    $ts = (Get-Date).ToString('s')
    Add-Content -Path $ProgressLog -Value "[$ts] $Line"
  } catch { }
}

# ---------- Sleep prevention (Windows) ----------
Add-Type -Namespace Native -Name Pwr -MemberDefinition @"
  [System.Runtime.InteropServices.DllImport("kernel32.dll")]
  public static extern uint SetThreadExecutionState(uint esFlags);
"@
# ES_CONTINUOUS(0x80000000) | ES_SYSTEM_REQUIRED(0x00000001) | ES_AWAYMODE_REQUIRED(0x00000040)
# FIX: Build unsigned flags without a single large expression (avoids signed coercion to -2147483648).
[uint32]$script:ES_CONTINUOUS        = [Convert]::ToUInt32('80000000',16)  # 0x80000000 as UInt32 (2147483648)
[uint32]$script:ES_SYSTEM_REQUIRED   = 0x1
[uint32]$script:ES_AWAYMODE_REQUIRED = 0x40
[uint32]$script:ES_FLAGS             = $script:ES_CONTINUOUS
$script:ES_FLAGS = $script:ES_FLAGS -bor $script:ES_SYSTEM_REQUIRED
$script:ES_FLAGS = $script:ES_FLAGS -bor $script:ES_AWAYMODE_REQUIRED
[Native.Pwr]::SetThreadExecutionState($script:ES_FLAGS) | Out-Null

# Ensure cleanup restores sleep + deletes temps
$script:ExitCode = 0
$script:OriginalEA = $ErrorActionPreference
$cleanup = {
  try {
    foreach ($t in $script:TempFiles) {
      if (Test-Path $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue }
    }
  } catch { }
  try {
    # Clear continuous requirement
    [Native.Pwr]::SetThreadExecutionState($script:ES_CONTINUOUS) | Out-Null
  } catch { }
  exit $script:ExitCode
}
Register-EngineEvent PowerShell.Exiting -Action $cleanup | Out-Null

# ---------- State (resume) ----------
$script:State = @{
  Version = 1
  FileHashes = @{}      # path -> @{ Lwt = ticks; Len = long; Sha256 = string }
  ContentScanned = @{}  # path -> @{ Lwt = ticks; Len = long }
}
if (Test-Path $StatePath) {
  try {
    $loaded = Get-Content -Raw -LiteralPath $StatePath | ConvertFrom-Json -AsHashtable
    if ($loaded -and $loaded.Version -ge 1) { $script:State = $loaded }
  } catch { }
}
function Save-State {
  try {
    ($script:State | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $StatePath -Encoding UTF8
  } catch { }
}

# ---------- Semver helpers ----------
function Parse-Semver {
  param([string]$v)
  # returns [pscustomobject] @{ Major; Minor; Patch; Special }
  if ([string]::IsNullOrWhiteSpace($v)) { return [pscustomobject]@{Major=0;Minor=0;Patch=0;Special='' } }
  $m = [regex]::Match($v, '([0-9]+)\.([0-9]+)\.([0-9]+)([0-9A-Za-z\-\.]*)')
  if ($m.Success) {
    return [pscustomobject]@{
      Major  = [int]$m.Groups[1].Value
      Minor  = [int]$m.Groups[2].Value
      Patch  = [int]$m.Groups[3].Value
      Special= $m.Groups[4].Value
    }
  }
  return [pscustomobject]@{Major=0;Minor=0;Patch=0;Special='' }
}

function Test-SemverMatch {
  param(
    [string]$TestSubject,  # concrete version like 1.2.3
    [string]$Pattern       # '^1.0.0' or '~1.1.0' or '1.2.3' or 'A || B'
  )
  if ($Pattern -eq '*') { return $true }
  $sub = Parse-Semver $TestSubject
  foreach ($p in ($Pattern -split '\|\|')) {
    $p = $p.Trim()
    if ($p -eq '*') { return $true }
    if ($p.StartsWith('^')) {
      $pp = Parse-Semver $p.Substring(1)
      if ($sub.Major -ne $pp.Major) { continue }
      if ($sub.Minor -lt $pp.Minor) { continue }
      if ($sub.Minor -eq $pp.Minor -and $sub.Patch -lt $pp.Patch) { continue }
      return $true
    } elseif ($p.StartsWith('~')) {
      $pp = Parse-Semver $p.Substring(1)
      if ($sub.Major -ne $pp.Major) { continue }
      if ($sub.Minor -ne $pp.Minor) { continue }
      if ($sub.Patch -lt $pp.Patch) { continue }
      return $true
    } else {
      $pp = Parse-Semver $p
      if ($sub.Major -eq $pp.Major -and $sub.Minor -eq $pp.Minor -and $sub.Patch -eq $pp.Patch -and $sub.Special -eq $pp.Special) {
        return $true
      }
    }
  }
  return $false
}

# ---------- Load compromised packages ----------
$script:COMPROMISED_PACKAGES = @() # array of "name:version"
function Load-CompromisedPackages {
  $scriptDir = Split-Path -Parent $PSCommandPath
  $packagesFile = Join-Path $scriptDir 'compromised-packages.txt'
  if (Test-Path $packagesFile) {
    $lines = Get-Content -LiteralPath $packagesFile -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
      $line = $line -replace "`r",''
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      if ($line -match '^\s*#') { continue }
      if ($line -match '^[A-Za-z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+') { $script:COMPROMISED_PACKAGES += $line }
    }
    Write-Status Blue "📦 Loaded $($COMPROMISED_PACKAGES.Count) compromised packages from $packagesFile"
  } else {
    Write-Status Yellow "⚠️  Warning: $packagesFile not found, using embedded fallback list"
    $script:COMPROMISED_PACKAGES = @(
      '@ctrl/tinycolor:4.1.0','@ctrl/tinycolor:4.1.1','@ctrl/tinycolor:4.1.2',
      '@ctrl/deluge:1.2.0','angulartics2:14.1.2','koa2-swagger-ui:5.11.1','koa2-swagger-ui:5.11.2'
    )
  }
}

# ---------- File helpers ----------
function Get-Files {
  param([string[]]$Include, [switch]$AsArray)
  try {
    $files = Get-ChildItem -LiteralPath $ScanDir -Recurse -File -ErrorAction SilentlyContinue `
      | Where-Object { $_.Name -like $Include[0] -or $Include[1..($Include.Count-1)] -contains $_.Name -or ($Include | Where-Object { $_ -like '*.*' } | ForEach-Object { $_ }) }
    if ($AsArray) { return @($files) } else { return $files }
  } catch { return @() }
}

function Get-MatchingFiles {
  param([string[]]$Extensions)
  try {
    return Get-ChildItem -LiteralPath $ScanDir -Recurse -File -ErrorAction SilentlyContinue `
      | Where-Object { $Extensions -contains $_.Extension.ToLower() }
  } catch { return @() }
}

# ---------- Checks ----------
function Check-WorkflowFiles {
  Write-Status Blue "🔍 Checking for malicious workflow files..."
  try {
    $hits = Get-ChildItem -LiteralPath $ScanDir -Recurse -Filter 'shai-hulud-workflow.yml' -File -ErrorAction SilentlyContinue
    foreach ($f in $hits) { $script:WORKFLOW_FILES.Add($f.FullName) }
  } catch { }
}

function Check-FileHashes {
  # target: *.js, *.ts, *.json
  $candidates = try {
    Get-ChildItem -LiteralPath $ScanDir -Recurse -File -Include *.js,*.ts,*.json -ErrorAction SilentlyContinue
  } catch { @() }
  $total = $candidates.Count
  Write-Status Blue "🔍 Checking $total files for known malicious content..."
  $i = 0
  $saveEvery = 500

  $processOne = {
    param($fi, $stateRef, $hashList)
    $path = $fi.FullName
    $lwt  = $fi.LastWriteTimeUtc.Ticks
    $len  = $fi.Length
    $key  = $path

    if ($stateRef.FileHashes.ContainsKey($key)) {
      $entry = $stateRef.FileHashes[$key]
      if ($entry.Lwt -eq $lwt -and $entry.Len -eq $len -and $entry.Sha256) {
        $sha = $entry.Sha256
      } else {
        $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.ToLower()
        $stateRef.FileHashes[$key] = @{ Lwt=$lwt; Len=$len; Sha256=$sha }
      }
    } else {
      $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.ToLower()
      $stateRef.FileHashes[$key] = @{ Lwt=$lwt; Len=$len; Sha256=$sha }
    }
    if ($hashList -contains $sha) { return "${path}:$sha" }
    return $null
  }

  # NOTE (Conservative Patch):
  # - Parallel scanning for hashes/content disabled for correctness. Previous implementation
  #   used invalid 'using' syntax and would not persist state mutations (serialization copies),
  #   risking resume inconsistencies or runtime errors. Sequential scanning ensures deterministic
  #   results and reliable state updates.
  foreach ($fi in $candidates) {
    try {
      $r = & $processOne $fi $script:State $script:MALICIOUS_HASHLIST
      if ($r) { $script:MALICIOUS_HASHES.Add($r) }
    } catch { }
    $i++
    if (($i % $saveEvery) -eq 0) { Save-State }
    if (($i % 200) -eq 0) {
      Write-Progress -Activity 'Hashing files' -Status "$i / $total" -PercentComplete ([int](100*$i/$total))
      Write-ProgressLog "Hashing: $i / $total"
    }
  }
  Write-Progress -Activity 'Hashing files' -Completed
  Save-State
}

function Get-LockfileVersion {
  param([string]$PackageName, [string]$PackageDir)
  # npm package-lock.json: try node_modules/<name> block
  $pl = Join-Path $PackageDir 'package-lock.json'
  if (Test-Path $pl) {
    try {
      $reader = [System.IO.StreamReader]::new($pl)
      $inBlock = $false; $brace = 0
      $target = '"node_modules/' + $PackageName + '"'
      while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        if (-not $inBlock -and $line -match [regex]::Escape($target)) { $inBlock = $true; $brace = 0 }
        if ($inBlock) {
          if ($line -match '\{') { $brace++ }
          if ($line -match '"version"\s*:\s*"([^"]+)"') { $reader.Close(); return $Matches[1] }
          if ($line -match '\}') { $brace--; if ($brace -le 0) { $inBlock = $false } }
        }
      }
      $reader.Close()
    } catch { }
    # fallback: very simple same-line format (older lockfiles)
    try {
      $m = Select-String -Path $pl -Pattern ('"'+[regex]::Escape($PackageName)+'"\s*:\s*"[0-9]') -SimpleMatch:$false -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($m) {
        $line = $m.Line
        if ($line -match ':\s*"([^"]+)"') { return $Matches[1] }
      }
    } catch { }
  }

  # yarn.lock
  $yl = Join-Path $PackageDir 'yarn.lock'
  if (Test-Path $yl) {
    try {
      # header like: "package@^1.2.3":
      $rxHeader = '^("?'+[regex]::Escape($PackageName)+'@[^"]+"?):\s*$'
      $rxVersion = '^\s*version\s+"([^"]+)"'
      $reader = [System.IO.StreamReader]::new($yl)
      $seen = $false
      while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        if (-not $seen -and $line -match $rxHeader) { $seen = $true; continue }
        if ($seen) {
          if ($line -match $rxVersion) { $reader.Close(); return $Matches[1] }
          if ($line.Trim().Length -eq 0) { $seen = $false } # next block
        }
      }
      $reader.Close()
    } catch { }
  }

  # pnpm-lock.yaml (simple transform: under 'packages:' entries like '  /name@1.2.3:')
  $pn = Join-Path $PackageDir 'pnpm-lock.yaml'
  if (Test-Path $pn) {
    try {
      $reader = [System.IO.StreamReader]::new($pn)
      $inPackages = $false
      while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()
        if (-not $inPackages) {
          if ($line -match '^\s*packages:\s*$') { $inPackages = $true }
          continue
        }
        # 2-space indent keys for entries
        if ($line -match '^\s{2}\/([^@]+)@([^:\s]+):') {
          $name = $Matches[1]; $ver = $Matches[2]
          if ($name -eq $PackageName) { $reader.Close(); return $ver }
        }
        # stop if new top-level
        if ($line -match '^[^\s]') { break }
      }
      $reader.Close()
    } catch { }
  }
  return ''
}

function Check-Packages {
  $pkgFiles = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -Filter 'package.json' -File -ErrorAction SilentlyContinue } catch { @() }
  $total = $pkgFiles.Count
  Write-Status Blue "🔍 Checking $total package.json files for compromised packages..."
  $i = 0
  foreach ($pf in $pkgFiles) {
    try {
      $json = Get-Content -Raw -LiteralPath $pf.FullName | ConvertFrom-Json
      $sections = @('dependencies','devDependencies','peerDependencies','optionalDependencies')
      foreach ($sec in $sections) {
        $deps = $json.$sec
        if (-not $deps) { continue }
        foreach ($kv in $deps.PSObject.Properties) {
          $pname = $kv.Name
          $pver  = [string]$kv.Value
          foreach ($mi in $COMPROMISED_PACKAGES) {
            $malName, $malVer = $mi.Split(':',2)
            if ($pname -ne $malName) { continue }
            if ($pver -eq $malVer) {
              $COMPROMISED_FOUND.Add("$($pf.FullName):$pname@$pver")
            } elseif (Test-SemverMatch -TestSubject $malVer -Pattern $pver) {
              $actual = Get-LockfileVersion -PackageName $pname -PackageDir (Split-Path -Parent $pf.FullName)
              if ($actual) {
                if ($actual -eq $malVer) {
                  $COMPROMISED_FOUND.Add("$($pf.FullName):$pname@$actual")
                } else {
                  $LOCKFILE_SAFE_VERSIONS.Add("$($pf.FullName):$pname@$pver (locked to $actual - safe)")
                }
              } else {
                $SUSPICIOUS_FOUND.Add("$($pf.FullName):$pname@$pver")
              }
            }
          }
        }
      }
      foreach ($ns in $COMPROMISED_NAMESPACES) {
        if ((Get-Content -Raw -LiteralPath $pf.FullName) -match ('"'+[regex]::Escape($ns)+'/')) {
          $NAMESPACE_WARNINGS.Add("$($pf.FullName):Contains packages from compromised namespace: $ns")
        }
      }
    } catch { }
    $i++
    if (($i % 50) -eq 0) {
      Write-Progress -Activity 'Scanning package.json' -Status "$i / $total" -PercentComplete ([int](100*$i/$total))
      Write-ProgressLog "Packages: $i / $total"
    }
  }
  Write-Progress -Activity 'Scanning package.json' -Completed
}

function Check-PostinstallHooks {
  Write-Status Blue "🔍 Checking for suspicious postinstall hooks..."
  $pkgFiles = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -Filter 'package.json' -File -ErrorAction SilentlyContinue } catch { @() }
  foreach ($pf in $pkgFiles) {
    try {
      $json = Get-Content -Raw -LiteralPath $pf.FullName | ConvertFrom-Json
      $scripts = $json.scripts
      if ($scripts -and $scripts.postinstall) {
        $cmd = [string]$scripts.postinstall
        if ($cmd -match 'curl|wget|node\s+-e|eval') {
          $POSTINSTALL_HOOKS.Add("$($pf.FullName):Suspicious postinstall: $cmd")
        }
      }
    } catch { }
  }
}

function Check-Content {
  Write-Status Blue "🔍 Checking for suspicious content patterns..."
  $files = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -File -Include *.js,*.ts,*.json,*.yml,*.yaml -ErrorAction SilentlyContinue } catch { @() }
  $total = $files.Count; $i = 0
  $doOne = {
    param($fi, $stateRef)
    $path = $fi.FullName
    $lwt  = $fi.LastWriteTimeUtc.Ticks
    $len  = $fi.Length
    $key  = $path
    # resume: skip if unchanged and already scanned
    if ($stateRef.ContentScanned.ContainsKey($key)) {
      $e = $stateRef.ContentScanned[$key]
      if ($e.Lwt -eq $lwt -and $e.Len -eq $len) { return @() }
    }
    $text = ''
    try { $text = Get-Content -Raw -LiteralPath $path -ErrorAction Stop } catch { return @() }
    $hits = New-Object System.Collections.Generic.List[string]
    if ($text -match 'webhook\.site') { $hits.Add("${path}:webhook.site reference") }
    if ($text -match 'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7') { $hits.Add("${path}:malicious webhook endpoint") }
    $stateRef.ContentScanned[$key] = @{ Lwt=$lwt; Len=$len }
    return $hits
  }

  # Parallel path removed (see header note).
  foreach ($fi in $files) {
    try {
      $arr = & $doOne $fi $script:State
      foreach ($hit in $arr) { $script:SUSPICIOUS_CONTENT.Add($hit) }
    } catch { }
    $i++
    if (($i % 200) -eq 0) {
      Write-Progress -Activity 'Content scan' -Status "$i / $total" -PercentComplete ([int](100*$i/$total))
      Write-ProgressLog "Content: $i / $total"
    }
  }
  Write-Progress -Activity 'Content scan' -Completed
  Save-State
}

function Check-CryptoTheftPatterns {
  Write-Status Blue "🔍 Checking for cryptocurrency theft patterns..."
  $files = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -File -Include *.js,*.ts,*.json -ErrorAction SilentlyContinue } catch { @() }
  foreach ($fi in $files) {
    try {
      $text = Get-Content -Raw -LiteralPath $fi.FullName -ErrorAction Stop
      if ($text -match '0x[a-fA-F0-9]{40}' -and $text -match '(ethereum|wallet|address|crypto)') {
        $CRYPTO_PATTERNS.Add("$($fi.FullName):Ethereum wallet address patterns detected")
      }
      if ($text -match 'XMLHttpRequest\.prototype\.send') {
        $framework = ($fi.FullName -like '*\react-native\Libraries\Network\*' -or $fi.FullName -like '*\next\dist\compiled\*')
        $alsoCrypto = ($text -match '0x[a-fA-F0-9]{40}|checkethereumw|runmask|webhook\.site|npmjs\.help')
        if ($framework -and $alsoCrypto) {
          $CRYPTO_PATTERNS.Add("$($fi.FullName):XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK")
        } elseif ($framework) {
          $CRYPTO_PATTERNS.Add("$($fi.FullName):XMLHttpRequest prototype modification detected in framework code - LOW RISK")
        } elseif ($alsoCrypto) {
          $CRYPTO_PATTERNS.Add("$($fi.FullName):XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK")
        } else {
          $CRYPTO_PATTERNS.Add("$($fi.FullName):XMLHttpRequest prototype modification detected - MEDIUM RISK")
        }
      }
      if ($text -match 'checkethereumw|runmask|newdlocal|_0x19ca67') {
        $CRYPTO_PATTERNS.Add("$($fi.FullName):Known crypto theft function names detected")
      }
      if ($text -match '0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976|1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx|TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67') {
        $CRYPTO_PATTERNS.Add("$($fi.FullName):Known attacker wallet address detected - HIGH RISK")
      }
      if ($text -match 'npmjs\.help') { $CRYPTO_PATTERNS.Add("$($fi.FullName):Phishing domain npmjs.help detected") }
      if ($text -match 'javascript-obfuscator') { $CRYPTO_PATTERNS.Add("$($fi.FullName):JavaScript obfuscation detected") }
      if ($text -match 'ethereum.*0x[a-fA-F0-9]{40}' -or $text -match 'bitcoin.*[13][a-km-zA-HJ-NP-Z1-9]') {
        $CRYPTO_PATTERNS.Add("$($fi.FullName):Cryptocurrency regex patterns detected")
      }
    } catch { }
  }
}

function Check-GitBranches {
  Write-Status Blue "🔍 Checking for suspicious git branches..."
  $gitDirs = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -Directory -Filter '.git' -ErrorAction SilentlyContinue } catch { @() }
  foreach ($gd in $gitDirs) {
    try {
      $repo = Split-Path -Parent $gd.FullName
      $heads = Join-Path $gd.FullName 'refs\heads'
      if (Test-Path $heads) {
        $files = Get-ChildItem -LiteralPath $heads -Recurse -File -Filter '*shai-hulud*' -ErrorAction SilentlyContinue
        foreach ($bf in $files) {
          $hash = (Get-Content -LiteralPath $bf.FullName -ErrorAction SilentlyContinue | Select-Object -First 1)
          if ($hash) {
            $script:GIT_BRANCHES.Add("${repo}:Branch '$($bf.BaseName)' (commit: $($hash.Substring(0,[Math]::Min(8,$hash.Length)))...)")
          }
        }
      }
    } catch { }
  }
}

function Check-ShaiHuludRepos {
  Write-Status Blue "🔍 Checking for Shai-Hulud repositories and migration patterns..."
  $gitDirs = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -Directory -Filter '.git' -ErrorAction SilentlyContinue } catch { @() }
  foreach ($gd in $gitDirs) {
    try {
      $repo = Split-Path -Parent $gd.FullName
      $name = Split-Path -Leaf $repo
      if ($name -match '(?i)shai-hulud') { $SHAI_HULUD_REPOS.Add("${repo}:Repository name contains 'Shai-Hulud'") }
      if ($name -like '*-migration') { $SHAI_HULUD_REPOS.Add("${repo}:Repository name contains migration pattern") }
      $cfg = Join-Path $gd.FullName 'config'
      if (Test-Path $cfg) {
        $cfgText = Get-Content -Raw -LiteralPath $cfg -ErrorAction SilentlyContinue
        if ($cfgText -match '(?i)shai-hulud') { $SHAI_HULUD_REPOS.Add("${repo}:Git remote contains 'Shai-Hulud'") }
      }
      $dataJson = Join-Path $repo 'data.json'
      if (Test-Path $dataJson) {
        $head = Get-Content -LiteralPath $dataJson -TotalCount 5 -ErrorAction SilentlyContinue | Out-String
        if ($head -match 'eyJ' -and $head -match '==') {
          $SHAI_HULUD_REPOS.Add("${repo}:Contains suspicious data.json (possible base64-encoded credentials)")
        }
      }
    } catch { }
  }
}

function Check-PackageIntegrity {
  Write-Status Blue "🔍 Checking package lock files for integrity issues..."
  $locks = try {
    Get-ChildItem -LiteralPath $ScanDir -Recurse -File -Include 'package-lock.json','yarn.lock','pnpm-lock.yaml' -ErrorAction SilentlyContinue
  } catch { @() }

  foreach ($lf in $locks) {
    $org = $lf.FullName
    try {
      foreach ($pi in $COMPROMISED_PACKAGES) {
        $name, $malv = $pi.Split(':',2)
        $found = Get-LockfileVersion -PackageName $name -PackageDir (Split-Path -Parent $org)
        if ($found -and $found -eq $malv) {
          $INTEGRITY_ISSUES.Add("${org}:Compromised package in lockfile: $name@$malv")
        }
      }
      # check @ctrl recent modification
      $hasCtrl = $false
      try {
        $snippet = (Get-Content -LiteralPath $org -TotalCount 200 -ErrorAction SilentlyContinue) -join "`n"
        if ($snippet -match '@ctrl') { $hasCtrl = $true }
      } catch { }
      if ($hasCtrl) {
        $ageSec = [int]((Get-Date) - (Get-Item -LiteralPath $org).LastWriteTime).TotalSeconds
        if ($ageSec -lt 2592000) {
          $INTEGRITY_ISSUES.Add("${org}:Recently modified lockfile contains @ctrl packages (potential worm activity)")
        }
      }
    } catch { }
  }
}

function Check-TrufflehogActivity {
  Write-Status Blue "🔍 Checking for Trufflehog activity and secret scanning..."
  try {
    $bins = Get-ChildItem -LiteralPath $ScanDir -Recurse -File -Filter '*trufflehog*' -ErrorAction SilentlyContinue
    foreach ($b in $bins) { $TRUFFLEHOG_ACTIVITY.Add("$($b.FullName):HIGH:Trufflehog binary found") }
  } catch { }

  $files = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -File -Include *.js,*.py,*.sh,*.json -ErrorAction SilentlyContinue } catch { @() }
  foreach ($fi in $files) {
    try {
      $text = Get-Content -Raw -LiteralPath $fi.FullName -ErrorAction Stop
      $context = if ($fi.FullName -match '\\node_modules\\') {'node_modules'}
                 elseif ($fi.Name -match '\.d\.ts$') {'type_definitions'}
                 elseif ($fi.FullName -match '(\\dist\\|\\build\\|\\public\\)') {'build_output'}
                 elseif ($fi.Name -match 'config') {'configuration'}
                 else {'source_code'}

      if ($text -match 'trufflehog') {
        switch ($context) {
          'documentation' { }
          'node_modules' { $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):MEDIUM:Contains trufflehog references in $context") }
          'type_definitions' { $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):MEDIUM:Contains trufflehog references in $context") }
          'build_output' { $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):MEDIUM:Contains trufflehog references in $context") }
          default {
            if ($text -match 'subprocess' -and $text -match 'curl') {
              $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):HIGH:Suspicious trufflehog execution pattern")
            } else {
              $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):MEDIUM:Contains trufflehog references in source code")
            }
          }
        }
      }

      if ($text -match 'AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN') {
        switch ($context) {
          'type_definitions' { }
          'documentation' { }
          'node_modules' { $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):LOW:Credential patterns in node_modules") }
          'configuration' { $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):MEDIUM:Credential patterns in configuration") }
          default {
            if ($text -match 'webhook\.site|curl|https\.request') {
              $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):HIGH:Credential patterns with potential exfiltration")
            } else {
              $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):MEDIUM:Contains credential scanning patterns")
            }
          }
        }
      }

      if ($text -match 'process\.env|os\.environ|getenv') {
        switch ($context) {
          'type_definitions' { }
          'documentation' { }
          'node_modules' { $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):LOW:Environment variable access in $context") }
          'build_output' { $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):LOW:Environment variable access in $context") }
          'configuration' { }
          default {
            if ($text -match 'webhook\.site' -and $text -match 'exfiltrat') {
              $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):HIGH:Environment scanning with exfiltration")
            } elseif ($text -match 'scan|harvest|steal') {
              $TRUFFLEHOG_ACTIVITY.Add("$($fi.FullName):MEDIUM:Potentially suspicious environment variable access")
            }
          }
        }
      }
    } catch { }
  }
}

function Check-Typosquatting {
  if (-not $Paranoid) { return }
  $pkgFiles = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -Filter 'package.json' -File -ErrorAction SilentlyContinue } catch { @() }
  foreach ($pf in $pkgFiles) {
    try {
      $json = Get-Content -Raw -LiteralPath $pf.FullName | ConvertFrom-Json
      $sections = @('dependencies','devDependencies','peerDependencies','optionalDependencies')
      $names = New-Object System.Collections.Generic.HashSet[string]
      foreach ($sec in $sections) {
        $deps = $json.$sec
        if ($deps) { foreach ($p in $deps.PSObject.Properties) { [void]$names.Add($p.Name) } }
      }
      foreach ($name in $names) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        # Unicode / non-ASCII
        if ($name -notmatch '^[a-zA-Z0-9@\/\.\_\-]+$') {
          $TYPOSQUATTING_WARNINGS.Add("$($pf.FullName):Potential Unicode/homoglyph characters in package: $name")
        }
        # simple confusables
        $pairs = @('rn:m','vv:w','cl:d','ii:i','nn:n','oo:o')
        foreach ($p in $pairs) {
          $from,$to = $p.Split(':',2)
          if ($name -match [regex]::Escape($from)) {
            $TYPOSQUATTING_WARNINGS.Add("$($pf.FullName):Potential typosquatting pattern '$from' in package: $name")
            break
          }
        }
        # near popular by one char
        foreach ($pop in $POPULAR_PACKAGES) {
          if ($name -eq $pop) { continue }
          if ($name.Length -eq $pop.Length -and $name.Length -gt 4) {
            $diff = 0; for($k=0;$k -lt $name.Length;$k++){ if($name[$k] -ne $pop[$k]){ $diff++ } }
            if ($diff -eq 1) { $TYPOSQUATTING_WARNINGS.Add("$($pf.FullName):Potential typosquatting of '$pop': $name (1 character difference)"); break }
          } elseif ($name.Length -eq ($pop.Length-1)) {
            # missing char
            for($k=0;$k -le $pop.Length;$k++){
              $test = $pop.Remove($k,1)
              if ($test -eq $name) { $TYPOSQUATTING_WARNINGS.Add("$($pf.FullName):Potential typosquatting of '$pop': $name (missing character)"); break }
            }
          } elseif ($name.Length -eq ($pop.Length+1)) {
            # extra char
            for($k=0;$k -le $name.Length;$k++){
              $test = $name.Remove($k,1)
              if ($test -eq $pop) { $TYPOSQUATTING_WARNINGS.Add("$($pf.FullName):Potential typosquatting of '$pop': $name (extra character)"); break }
            }
          }
        }
        # namespace similarity
        if ($name.StartsWith('@')) {
          $ns = $name.Split('/')[0]
          foreach ($sus in @('@types','@angular','@typescript','@react','@vue','@babel')) {
            if ($ns -ne $sus -and $ns.TrimStart('@') -like "*$($sus.TrimStart('@'))*") {
              $TYPOSQUATTING_WARNINGS.Add("$($pf.FullName):Suspicious namespace variation: $ns (similar to $sus)")
            }
          }
        }
      }
    } catch { }
  }
}

function Check-NetworkExfiltration {
  if (-not $Paranoid) { return }
  $files = try { Get-ChildItem -LiteralPath $ScanDir -Recurse -File -Include *.js,*.ts,*.json,*.mjs -ErrorAction SilentlyContinue } catch { @() }
  foreach ($fi in $files) {
    try {
      # skip vendor/lockfiles
      if ($fi.FullName -match '\\vendor\\' -or $fi.FullName -match '\\node_modules\\' -or $fi.Name -in @('package-lock.json','yarn.lock')) { continue }
      $text = Get-Content -Raw -LiteralPath $fi.FullName -ErrorAction Stop
      # hardcoded IPs (skip 127.0.0.1/0.0.0.0)
      $ips = [regex]::Matches($text,'\b(?:\d{1,3}\.){3}\d{1,3}\b') | ForEach-Object { $_.Value } | Select-Object -Unique
      foreach ($ip in $ips) {
        if ($ip -ne '127.0.0.1' -and $ip -ne '0.0.0.0') {
          $NETWORK_EXFILTRATION_WARNINGS.Add("$($fi.FullName):Hardcoded IP addresses found: $ip")
        }
      }
      # suspicious domains
      foreach ($d in $SUSPICIOUS_DOMAINS) {
        # Simplified, safer boundary-based detection (case-insensitive)
        if ($text -match "(?i)\b$([regex]::Escape($d))\b") {
          $NETWORK_EXFILTRATION_WARNINGS.Add("$($fi.FullName):Suspicious domain found: $d")
        }
      }
      # base64 decode/encode near network calls
      if ($text -match 'atob\(|base64.*decode') { $NETWORK_EXFILTRATION_WARNINGS.Add("$($fi.FullName):Base64 decoding detected") }
      if ($text -match 'btoa\(' -and $text -match '(fetch|XMLHttpRequest|axios)' -and $text -notmatch 'Authorization:|Basic |Bearer ') {
        $NETWORK_EXFILTRATION_WARNINGS.Add("$($fi.FullName):Suspicious base64 encoding near network operation")
      }
      if ($text -match 'dns-query|application/dns-message') { $NETWORK_EXFILTRATION_WARNINGS.Add("$($fi.FullName):DNS-over-HTTPS pattern detected") }
      $ws = [regex]::Matches($text,'wss?://[^\s"\'']+') | ForEach-Object { $_.Value } | Select-Object -Unique
      foreach ($w in $ws) {
        if ($w -notmatch 'localhost|127\.0\.0\.1') {
          $NETWORK_EXFILTRATION_WARNINGS.Add("$($fi.FullName):WebSocket connection to external endpoint: $w")
        }
      }
      if ($text -match 'X-Exfiltrate|X-Data-Export|X-Credential') { $NETWORK_EXFILTRATION_WARNINGS.Add("$($fi.FullName):Suspicious HTTP headers detected") }
    } catch { }
  }
}

# ---------- Reporting ----------
function Show-Report {
  param([bool]$ParanoidMode)
  Write-Host ''
  Write-Status Blue "=============================================="
  if ($ParanoidMode) { Write-Status Blue "  SHAI-HULUD + PARANOID SECURITY REPORT" }
  else { Write-Status Blue "      SHAI-HULUD DETECTION REPORT" }
  Write-Status Blue "=============================================="
  Write-Host ''

  $high = 0; $medium = 0

  if ($WORKFLOW_FILES.Count -gt 0) {
    Write-Status Red "🚨 HIGH RISK: Malicious workflow files detected:"
    foreach ($f in $WORKFLOW_FILES) { Write-Host "   - $f"; $high++ }
  }

  if ($MALICIOUS_HASHES.Count -gt 0) {
    Write-Status Red "🚨 HIGH RISK: Files with known malicious hashes:"
    foreach ($e in $MALICIOUS_HASHES) {
      $file,$hash = $e.Split(':',2)
      Write-Host "   - $file"
      Write-Host "     Hash: $hash"
      $high++
    }
  }

  if ($COMPROMISED_FOUND.Count -gt 0) {
    Write-Status Red "🚨 HIGH RISK: Compromised package versions detected:"
    foreach ($e in $COMPROMISED_FOUND) {
      $file,$info = $e.Split(':',2)
      Write-Host "   - Package: $info"
      Write-Host "     Found in: $file"
      $high++
    }
    Write-Host "   NOTE: Update/remove these packages immediately."
    Write-Host ''
  }

  if ($SUSPICIOUS_FOUND.Count -gt 0) {
    Write-Status Yellow "⚠️  MEDIUM RISK: Suspicious package versions detected:"
    foreach ($e in $SUSPICIOUS_FOUND) {
      $file,$info = $e.Split(':',2)
      Write-Host "   - Package: $info"
      Write-Host "     Found in: $file"
      $medium++
    }
    Write-Host "   NOTE: Manual review required."
    Write-Host ''
  }

  if ($LOCKFILE_SAFE_VERSIONS.Count -gt 0) {
    Write-Status Blue "ℹ️  LOW RISK: Packages with safe lockfile versions:"
    foreach ($e in $LOCKFILE_SAFE_VERSIONS) {
      $file,$info = $e.Split(':',2)
      Write-Host "   - Package: $info"
      Write-Host "     Found in: $file"
    }
    Write-Host "   NOTE: Range could match compromised versions, but lockfile pins safe ones."
    Write-Host ''
  }

  if ($SUSPICIOUS_CONTENT.Count -gt 0) {
    Write-Status Yellow "⚠️  MEDIUM RISK: Suspicious content patterns:"
    foreach ($e in $SUSPICIOUS_CONTENT) {
      $file,$pat = $e.Split(':',2)
      Write-Host "   - Pattern: $pat"
      Write-Host "     Found in: $file"
      $medium++
    }
    Write-Host ''
  }

  if ($CRYPTO_PATTERNS.Count -gt 0) {
    $hi = @(); $mi = @(); $lo = @()
    foreach ($e in $CRYPTO_PATTERNS) {
      if ($e -match 'HIGH RISK|Known attacker wallet') { $hi += $e }
      elseif ($e -match 'LOW RISK') { $lo += $e } else { $mi += $e }
    }
    if ($hi.Count -gt 0) {
      Write-Status Red "🚨 HIGH RISK: Cryptocurrency theft patterns detected:"
      foreach ($x in $hi) { Write-Host "   - $x"; $high++ }
      Write-Host ''
    }
    if ($mi.Count -gt 0) {
      Write-Status Yellow "⚠️  MEDIUM RISK: Potential cryptocurrency manipulation patterns:"
      foreach ($x in $mi) { Write-Host "   - $x"; $medium++ }
      Write-Host ''
    }
    foreach ($x in $lo) { $LOW_RISK_FINDINGS.Add("Crypto pattern: $x") }
  }

  if ($GIT_BRANCHES.Count -gt 0) {
    Write-Status Yellow "⚠️  MEDIUM RISK: Suspicious git branches:"
    foreach ($e in $GIT_BRANCHES) {
      $repo,$info = $e.Split(':',2)
      Write-Host "   - Repository: $repo"
      Write-Host "     $info"
      $medium++
    }
    Write-Host ''
  }

  if ($POSTINSTALL_HOOKS.Count -gt 0) {
    Write-Status Red "🚨 HIGH RISK: Suspicious postinstall hooks detected:"
    foreach ($e in $POSTINSTALL_HOOKS) {
      $file,$info = $e.Split(':',2)
      Write-Host "   - Hook: $info"
      Write-Host "     Found in: $file"
      $high++
    }
    Write-Host ''
  }

  # Trufflehog
  $thH = @(); $thM = @(); $thL = @()
  foreach ($e in $TRUFFLEHOG_ACTIVITY) {
    $parts = $e.Split(':',3)
    $path = $parts[0]; $risk = $parts[1]; $info = $parts[2]
    switch ($risk) {
      'HIGH'   { $thH += "${path}:$info" }
      'MEDIUM' { $thM += "${path}:$info" }
      'LOW'    { $thL += "${path}:$info" }
    }
  }
  if ($thH.Count -gt 0) {
    Write-Status Red "🚨 HIGH RISK: Trufflehog/secret scanning activity detected:"
    foreach ($x in $thH) { Write-Host "   - $x"; $high++ }
    Write-Host ''
  }
  if ($thM.Count -gt 0) {
    Write-Status Yellow "⚠️  MEDIUM RISK: Potentially suspicious secret scanning patterns:"
    foreach ($x in $thM) { Write-Host "   - $x"; $medium++ }
    Write-Host ''
  }
  foreach ($x in $thL) { $LOW_RISK_FINDINGS.Add("Trufflehog pattern: $x") }

  if ($SHAI_HULUD_REPOS.Count -gt 0) {
    Write-Status Red "🚨 HIGH RISK: Shai-Hulud repositories detected:"
    foreach ($e in $SHAI_HULUD_REPOS) { Write-Host "   - $e"; $high++ }
    Write-Host ''
  }

  foreach ($e in $NAMESPACE_WARNINGS) { $LOW_RISK_FINDINGS.Add("Namespace warning: $($e.Split(':',2)[1]) (found in $(Split-Path -Leaf $e.Split(':',2)[0]))") }

  if ($INTEGRITY_ISSUES.Count -gt 0) {
    Write-Status Yellow "⚠️  MEDIUM RISK: Package integrity issues detected:"
    foreach ($e in $INTEGRITY_ISSUES) { Write-Host "   - $e"; $medium++ }
    Write-Host ''
  }

  if ($ParanoidMode -and $TYPOSQUATTING_WARNINGS.Count -gt 0) {
    Write-Status Yellow "⚠️  MEDIUM RISK (PARANOID): Potential typosquatting/homoglyph attacks:"
    $show = [Math]::Min(5,$TYPOSQUATTING_WARNINGS.Count)
    for ($k=0;$k -lt $show;$k++){ Write-Host "   - $($TYPOSQUATTING_WARNINGS[$k])"; $medium++ }
    if ($TYPOSQUATTING_WARNINGS.Count -gt 5) {
      Write-Host "   - ... and $($TYPOSQUATTING_WARNINGS.Count - 5) more (truncated)"
    }
    Write-Host ''
  }

  if ($ParanoidMode -and $NETWORK_EXFILTRATION_WARNINGS.Count -gt 0) {
    Write-Status Yellow "⚠️  MEDIUM RISK (PARANOID): Network exfiltration patterns detected:"
    $show = [Math]::Min(5,$NETWORK_EXFILTRATION_WARNINGS.Count)
    for ($k=0;$k -lt $show;$k++){ Write-Host "   - $($NETWORK_EXFILTRATION_WARNINGS[$k])"; $medium++ }
    if ($NETWORK_EXFILTRATION_WARNINGS.Count -gt 5) {
      Write-Host "   - ... and $($NETWORK_EXFILTRATION_WARNINGS.Count - 5) more (truncated)"
    }
    Write-Host ''
  }

  $totalIssues = $high + $medium
  Write-Status Blue "=============================================="
  if ($totalIssues -eq 0) {
    Write-Status Green "✅ No indicators of Shai-Hulud compromise detected."
    if ($LOW_RISK_FINDINGS.Count -gt 0) {
      Write-Host ''
      Write-Status Blue "ℹ️  LOW RISK FINDINGS (informational):"
      foreach ($f in $LOW_RISK_FINDINGS) { Write-Host "   - $f" }
    }
    $script:ExitCode = 0
  } else {
    Write-Status Red    "🔍 SUMMARY:"
    Write-Status Red    "   High Risk Issues: $high"
    Write-Status Yellow "   Medium Risk Issues: $medium"
    if ($LOW_RISK_FINDINGS.Count -gt 0) { Write-Status Blue "   Low Risk (informational): $($LOW_RISK_FINDINGS.Count)" }
    Write-Status Blue   "   Total Critical Issues: $totalIssues"
    if ($high -gt 0) { $script:ExitCode = 1 } else { $script:ExitCode = 2 }
  }
  Write-Status Blue "=============================================="
}

# ---------- Main ----------
try {
  if (-not (Test-Path $ScanDir -PathType Container)) {
    Write-Status Red "Error: Directory '$ScanDir' does not exist."; $script:ExitCode = 1; & $cleanup
  }
  $ScanDir = (Resolve-Path -LiteralPath $ScanDir).Path
  Load-CompromisedPackages

  Write-Status Green "Starting Shai-Hulud detection scan..."
  if ($Paranoid) { Write-Status Blue "Scanning directory: $ScanDir (paranoid mode enabled)" }
  else { Write-Status Blue "Scanning directory: $ScanDir" }
  Write-Host ''

  Check-WorkflowFiles
  Check-FileHashes
  Check-Packages
  Check-PostinstallHooks
  Check-Content
  Check-CryptoTheftPatterns
  Check-TrufflehogActivity
  Check-GitBranches
  Check-ShaiHuludRepos
  Check-PackageIntegrity

  if ($Paranoid) {
    Write-Status Blue "🔍+ Checking for typosquatting and homoglyph attacks..."
    Check-Typosquatting
    Write-Status Blue "🔍+ Checking for network exfiltration patterns..."
    Check-NetworkExfiltration
  }

  Show-Report -ParanoidMode:$Paranoid
} catch {
  Write-Status Red ("Fatal error: " + $_.Exception.Message)
  $script:ExitCode = 1
} finally {
  Save-State
  & $cleanup
}