<# 
.SYNOPSIS
  Descriptografa/decodifica um .7z em memória e executa o arquivo interno passando argumentos.

.DESCRIPTION
  - Requer 7z.exe (7-Zip) no PATH (ou informe -SevenZipPath).
  - Lê o conteúdo para memória via "7z e -so".
  - Executa .ps1 em memória.
  - Executa .exe/.bat/.cmd gravando em TEMP com ACL restrita e removendo o arquivo logo após iniciar o processo.

.PARAMETER Archive
  Caminho do arquivo .7z

.PARAMETER SevenZipPath
  Caminho completo para o 7z.exe/7za.exe (opcional). Se não informado, tenta localizar no PATH e locais comuns.

.PARAMETER Password
  Senha do .7z, se houver (opcional)

.PARAMETER Entry
  Caminho do arquivo dentro do .7z a executar. Se omitido, o script tenta escolher automaticamente.

.PARAMETER Sha256
  (Opcional) SHA-256 esperado do payload interno (integridade/anti-tamper).

.PARAMETER HideWindow
  (Opcional) Se definido, cria o processo sem janela (ex.: ferramentas de console).

.PARAMETER NoWait
  (Opcional) Se definido, não espera o término do processo interno. O código de saída do wrapper será 0.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true, Position=0)]
  [string]$Archive,

  [Parameter(Mandatory=$false)]
  [string]$SevenZipPath,   # <= NOVO (opção A/B)

  [Parameter(Mandatory=$false)]
  [string]$Password,

  [Parameter(Mandatory=$false)]
  [string]$Entry,

  [Parameter(Mandatory=$false)]
  [string]$Sha256,

  [switch]$HideWindow,
  [switch]$NoWait,

  # tudo após "--" vira argumento pro programa interno
  [Parameter(ValueFromRemainingArguments=$true)]
  [string[]]$Args
)

# -- utilidades ---------------------------------------------------------------

function Find-SevenZip {
  param([string]$OverridePath)

  if ($OverridePath) {
    if (Test-Path -LiteralPath $OverridePath) { return $OverridePath }
    throw "7z.exe especificado não existe: $OverridePath"
  }

  $cmd = Get-Command 7z.exe, 7za.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($cmd) { return $cmd.Path }

  $candidatos = @(
    "$env:ProgramFiles\7-Zip\7z.exe",
    "$env:ProgramFiles(x86)\7-Zip\7z.exe"
  )
  foreach ($p in $candidatos) { if (Test-Path -LiteralPath $p) { return $p } }

  throw "7z.exe não encontrado. Use -SevenZipPath ou adicione o 7-Zip ao PATH."
}

function Invoke-7z {
  param(
    [string]$SevenZipPath,
    [string[]]$Arguments
  )
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $SevenZipPath
  $psi.Arguments = ($Arguments -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $null = $p.Start()
  $ms = New-Object System.IO.MemoryStream
  $p.StandardOutput.BaseStream.CopyTo($ms)   # bytes quando usamos -so
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  [pscustomobject]@{
    ExitCode = $p.ExitCode
    StdErr   = $stderr
    Bytes    = $ms.ToArray()
  }
}

function List-7zEntries {
  param(
    [string]$SevenZipPath,
    [string]$ArchivePath,  # **usar caminho absoluto**
    [string]$Password
  )
  $args = @('l','-slt','-ba')
  if ($Password) { $args += "-p$Password" }
  $args += @("""$ArchivePath""")

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $SevenZipPath
  $psi.Arguments = ($args -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $null = $p.Start()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  if ($p.ExitCode -ne 0) { throw "Falha ao listar 7z:`n$err" }

  $entries = @()
  $current = @{}
  foreach ($line in ($out -split "`r?`n")) {
    if ($line -match '^\s*$') {
      if ($current.Count -gt 0) { 
        if ($current.Path -and ($current.Attributes -notmatch '\bD\b')) { $entries += $current.Path }
        $current = @{}
      }
      continue
    }
    if ($line -match '^(?<k>[^=]+)=(?<v>.*)$') { $current[$Matches.k.Trim()] = $Matches.v.Trim() }
  }
  if ($current.Count -gt 0 -and $current.Path -and ($current.Attributes -notmatch '\bD\b')) { $entries += $current.Path }
  return $entries
}

function Choose-Entry {
  param([string[]]$Entries)
  if (-not $Entries -or $Entries.Count -eq 0) { throw "O arquivo 7z não contém arquivos." }
  if ($Entries.Count -eq 1) { return $Entries[0] }
  $roots = $Entries | Where-Object { -not ($_ -match '[\\/]' ) }
  $candidates = if ($roots) { $roots } else { $Entries }
  $preferred = @('.ps1','.exe','.bat','.cmd','.py','.sh','.bin','.out')
  foreach ($ext in $preferred) {
    $hit = $candidates | Where-Object { $_.ToLower().EndsWith($ext) } | Select-Object -First 1
    if ($hit) { return $hit }
  }
  return ($candidates | Sort-Object Length | Select-Object -First 1)
}

function Is-Ps1 {
  param([string]$Name,[byte[]]$Bytes)
  if ($Name.ToLower().EndsWith('.ps1')) { return $true }
  $lim = [Math]::Min(64,$Bytes.Length)
  if ($lim -le 0) { return $false }
  $head = [System.Text.Encoding]::ASCII.GetString($Bytes[0..($lim-1)])
  return ($head -like '#!*powershell*' -or $head -like '#!*pwsh*')
}

function Is-WindowsExe {
  param([string]$Name,[byte[]]$Bytes)
  if ($Name.ToLower().EndsWith('.exe')) { return $true }
  if ($Bytes.Length -lt 0x40) { return $false }
  if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { return $false } # 'MZ'
  $off = [BitConverter]::ToInt32($Bytes,0x3C)
  if ($off -lt 0 -or ($off + 4) -gt $Bytes.Length) { return $false }
  return ($Bytes[$off] -eq 0x50 -and $Bytes[$off+1] -eq 0x45 -and $Bytes[$off+2] -eq 0x00 -and $Bytes[$off+3] -eq 0x00) # 'PE\0\0'
}

function Get-TextFromBytes { param([byte[]]$Bytes) try { [System.Text.Encoding]::UTF8.GetString($Bytes) } catch { [System.Text.Encoding]::Default.GetString($Bytes) } }

function Get-Sha256Hex {
  param([byte[]]$Bytes)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") }) -join '' } finally { $sha.Dispose() }
}

function Set-StrictAcl {
  param([string]$Path)
  $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl = New-Object System.Security.AccessControl.FileSecurity
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $user,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $acl.SetOwner($user)
  $acl.SetAccessRuleProtection($true,$false)
  $null = $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
}

# -- fluxo principal ----------------------------------------------------------

try {
  # Opção C: resolver o caminho do .7z para ABSOLUTO
  $ArchiveFull = $null
  try {
    $ArchiveFull = (Resolve-Path -LiteralPath $Archive).Path
  } catch {
    throw "Arquivo não encontrado: $Archive"
  }

  $SevenZip = Find-SevenZip -OverridePath $SevenZipPath

  if (-not $Entry) {
    $entries = List-7zEntries -SevenZipPath $SevenZip -ArchivePath $ArchiveFull -Password $Password
    $Entry = Choose-Entry -Entries $entries
  }

  Write-Verbose "Usando 7z: $SevenZip"
  Write-Verbose "Arquivo: $ArchiveFull"
  Write-Verbose "Entrada escolhida: $Entry"

  # extrai um único item para stdout (usa caminho ABSOLUTO)
  $args7 = @('e','-y','-so')
  if ($Password) { $args7 += "-p$Password" }
  $args7 += @("""$ArchiveFull""","""$Entry""")

  $res = Invoke-7z -SevenZipPath $SevenZip -Arguments $args7
  if ($res.ExitCode -ne 0 -or -not $res.Bytes -or $res.Bytes.Length -eq 0) {
    if ($res.StdErr) { Write-Error $res.StdErr }
    throw "Falha ao extrair a entrada '$Entry' do arquivo '$ArchiveFull'. Código: $($res.ExitCode)"
  }

  $blob = $res.Bytes

  if ($Sha256) {
    $calc = (Get-Sha256Hex -Bytes $blob)
    if ($calc.ToLower() -ne $Sha256.ToLower()) {
      throw "SHA-256 não confere. Esperado=$Sha256 Calculado=$calc"
    }
  }

  if (Is-Ps1 -Name $Entry -Bytes $blob) {
    $code = Get-TextFromBytes -Bytes $blob
    $sb   = [ScriptBlock]::Create($code)
    & $sb @Args
    exit $LASTEXITCODE
  }
  elseif (Is-WindowsExe -Name $Entry -Bytes $blob) {
    $tmpName = "memexec_{0}.exe" -f ([System.Guid]::NewGuid().ToString('N'))
    $tmpPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $tmpName)
    [System.IO.File]::WriteAllBytes($tmpPath, $blob)
    try {
      Set-StrictAcl -Path $tmpPath
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName = $tmpPath
      $psi.Arguments = ($Args -join ' ')
      $psi.UseShellExecute = $false
      $psi.CreateNoWindow = $HideWindow.IsPresent
      $psi.WindowStyle = if ($HideWindow) { [System.Diagnostics.ProcessWindowStyle]::Hidden } else { [System.Diagnostics.ProcessWindowStyle]::Normal }
      $proc = [System.Diagnostics.Process]::Start($psi)
      try { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue } catch {}
      if ($NoWait) { exit 0 }
      $proc.WaitForExit()
      exit $proc.ExitCode
    }
    finally {
      try { if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue } } catch {}
    }
  }
  else {
    $ext = [System.IO.Path]::GetExtension($Entry)
    if (-not $ext) { $ext = '.bin' }
    $tmpPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ("memexec_{0}{1}" -f ([System.Guid]::NewGuid().ToString('N')), $ext))
    [System.IO.File]::WriteAllBytes($tmpPath, $blob)
    try {
      Set-StrictAcl -Path $tmpPath
      if ($ext -in @('.cmd','.bat')) {
        $p = Start-Process -FilePath "cmd.exe" -ArgumentList @('/c', "`"$tmpPath`"") -PassThru -WindowStyle ($(if ($HideWindow){'Hidden'} else {'Normal'}))
      }
      elseif ($ext -eq '.py') {
        $py = (Get-Command python, py -ErrorAction SilentlyContinue | Select-Object -First 1).Path
        if (-not $py) { throw "Python não encontrado para executar o script .py interno." }
        $p = Start-Process -FilePath $py -ArgumentList @("`"$tmpPath`"") + $Args -PassThru -WindowStyle ($(if ($HideWindow){'Hidden'} else {'Normal'}))
      }
      else {
        $p = Start-Process -FilePath $tmpPath -ArgumentList $Args -PassThru -WindowStyle ($(if ($HideWindow){'Hidden'} else {'Normal'}))
      }
      try { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue } catch {}
      if ($NoWait) { exit 0 }
      $p.WaitForExit()
      exit $p.ExitCode
    }
    finally {
      try { if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue } } catch {}
    }
  }

}
catch {
  Write-Error $_.Exception.Message
  exit 2
}
