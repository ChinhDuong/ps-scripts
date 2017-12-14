#
# AutoBuildUtility.psm1
#
#Requires -Version 2.0
<# 
 .Synopsis
  Copies a remote file/folder to a local destination

 .Description
  Utility function for copying remote files locally. It leverages windows net use to map a share folder and supports network credentials for mounting the share.

 .Parameter Source
  The path to the file/folder to copy. It could be a network share or a local file path.

 .Parameter Destination
  The path to the destination folder. This path should be local to the machine executing the script. If not specified the item(s) will be copy to the temp folder

 .Parameter SourceCredential
  Used if the source is a network share for authentication.

 .Parameter Directory
  Specifies if the source is a directory or a file

 .Example
   # Copy a remote file
   Copy-RemoteItemLocally "\\otherpc\sharedfolder\myfile.doc" "C:\Mydocs\" (Get-Credential)

   # Copy a remote directory
   Copy-RemoteItemLocally "\\otherpc\sharedfolder\subfolder" "C:\Mydocs\" (Get-Credential) -Directory
#>


function Format-AnsiColor {
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [AllowEmptyString()]
    [string]
    $Message,

    [Parameter()]
    [ValidateSet(
      'normal display'
      ,'bold'
      ,'underline (mono only)'
      ,'blink on'
      ,'reverse video on'
      ,'nondisplayed (invisible)'
    )]
    [Alias('attribute')]
    [string]
    $Style,

    [Parameter()]
    [ValidateSet(
      'black'
      ,'red'
      ,'green'
      ,'yellow'
      ,'blue'
      ,'magenta'
      ,'cyan'
      ,'white'
    )]
    [Alias('fg')]
    [string]
    $ForegroundColor,

    [Parameter()]
    [ValidateSet(
      'black'
      ,'red'
      ,'green'
      ,'yellow'
      ,'blue'
      ,'magenta'
      ,'cyan'
      ,'white'
    )]
    [Alias('bg')]
    [string]
    $BackgroundColor
  )

  begin {
    $e = [char]27

    $attrib = @{
      'normal display' = 0
      'bold' = 1
      'underline (mono only)' = 4
      'blink on' = 5
      'reverse video on' = 7
      'nondisplayed (invisible)' = 8
    }

    $fore = @{
      black = 30
      red = 31
      green = 32
      yellow = 33
      blue = 34
      magenta = 35
      cyan = 36
      white = 37
    }

    $back = @{
      black = 40
      red = 41
      green = 42
      yellow = 43
      blue = 44
      magenta = 45
      cyan = 46
      white = 47
    }
  }

  process {
    $formats = @()
    if ($Style) {
      $formats += $attrib[$Style]
    }
    if ($ForegroundColor) {
      $formats += $fore[$ForegroundColor]
    }
    if ($BackgroundColor) {
      $formats += $back[$BackgroundColor]
    }
    if ($formats) {
      $formatter = "$e[$($formats -join ';')m"
    }

    "$formatter$_"
  }
}

function Copy-RemoteItemLocally () {
  [CmdletBinding(SupportsShouldProcess = $False)]
  param(
    [Parameter(Mandatory = $true,position = 0)]
    [string]$Source,

    [Parameter(Mandatory = $false,position = 1)]
    [string]$Destination,

    [Parameter(Mandatory = $false,position = 2)]
    [pscredential]$SourceCredential,

    [switch]$Directory
  )
  # Get temp file/folder if Destination is not providered 
  if (!$Destination) {
    $Destination = $env:TEMP
    if (!$Directory) {
      $Destination = (Join-Path $Destination -ChildPath (Split-Path -Path $Source -Leaf))
    }
  }

  # Check the flag for networkshare
  $networkShare = $false
  try {
    if (($Source.StartsWith("\\")) -and (!(Test-Path $Source -ErrorAction SilentlyContinue))) {
      $networkShare = $true
    }
  } catch [System.UnauthorizedAccessException]{
    $networkShare = $true
  }
  # Go parent directory path for file copy 
  $sourceDir = $Source
  $destinationDir = $Destination
  if (!$Directory) {
    $sourceDir = (Split-Path ($Source))
    $destinationDir = (Split-Path ($destinationDir))
  }

  # Mapping networkshare drive
  if ($networkShare) {
    Write-Verbose "Network Share detected, need to map"
    Use-NetworkShare -SharePath $sourceDir -SharePathCredential $SourceCredential -Ensure "Present" | Out-Null
  }

  try {
    if (!$Directory) {
      Write-Verbose ("Copy File $Source $Destination")
      if (!(Test-Path ($destinationDir))) {
        New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
      }
      Copy-Item $Source $Destination -Force | Out-Null
    } else {
      Write-Verbose ("Copy Directory $Source $Destination")
      if (!(Test-Path ($destinationDir))) {
        New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
      }
      Get-ChildItem $sourceDir | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $destinationDir -Force -Container -Recurse | Out-Null
      }
    }
  } catch {
    $ErrorMessage = $_.Exception.Message
    Write-Error "An error occurred while copying files: $Source to $Destination \n Error Message: $ErrorMessage"
  } finally {
    if ($networkShare) {
      try {
        Use-NetworkShare -SharePath $sourceDir -SharePathCredential $SourceCredential -Ensure "Absent" | Out-Null
      } catch {
        Write-Warning "Unable to disconnect share: $Source"
      }
    }
  }

  return $Destination
}

function Get-ExecutableType
{
<#
    .Synopsis
       Determines whether an executable file is 16-bit, 32-bit or 64-bit.
    .DESCRIPTION
       Attempts to read the MS-DOS and PE headers from an executable file to determine its type.
       The command returns one of four strings (assuming no errors are encountered while reading the
       file):
       "Unknown", "16-bit", "32-bit", or "64-bit"
    .PARAMETER Path
       Path to the file which is to be checked.
    .EXAMPLE
       Get-ExecutableType -Path C:\Windows\System32\more.com
    .INPUTS
       None.  This command does not accept pipeline input.
    .OUTPUTS
       String
    .LINK
        http://msdn.microsoft.com/en-us/magazine/cc301805.aspx
    #>

  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]
    $Path
  )

  try
  {
    try
    {
      $stream = New-Object System.IO.FileStream (
        $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path),
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
      )
    }
    catch
    {
      throw "Error opening file $Path for Read: $($_.Exception.Message)"
    }

    $exeType = 'Unknown'

    if ([System.IO.Path]::GetExtension($Path) -eq '.COM')
    {
      # 16-bit .COM files may not have an MS-DOS header.  We'll assume that any .COM file with no header
      # is a 16-bit executable, even though it may technically be a non-executable file that has been
      # given a .COM extension for some reason.

      $exeType = '16-bit'
    }

    $bytes = New-Object byte[] (4)

    if ($stream.Length -ge 64 -and
      $stream.Read($bytes,0,2) -eq 2 -and
      $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
    {
      $exeType = '16-bit'

      if ($stream.Seek(0x3C,[System.IO.SeekOrigin]::Begin) -eq 0x3C -and
        $stream.Read($bytes,0,4) -eq 4)
      {
        if (-not [System.BitConverter]::IsLittleEndian) { [array]::Reverse($bytes,0,4) }
        $peHeaderOffset = [System.BitConverter]::ToUInt32($bytes,0)

        if ($stream.Length -ge $peHeaderOffset + 6 -and
          $stream.Seek($peHeaderOffset,[System.IO.SeekOrigin]::Begin) -eq $peHeaderOffset -and
          $stream.Read($bytes,0,4) -eq 4 -and
          $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0)
        {
          $exeType = 'Unknown'

          if ($stream.Read($bytes,0,2) -eq 2)
          {
            if (-not [System.BitConverter]::IsLittleEndian) { [array]::Reverse($bytes,0,2) }
            $machineType = [System.BitConverter]::ToUInt16($bytes,0)

            switch ($machineType)
            {
              0x014C { $exeType = '32-bit' }
              0x0200 { $exeType = '64-bit' }
              0x8664 { $exeType = '64-bit' }
            }
          }
        }
      }
    }

    return $exeType
  }
  catch
  {
    throw
  }
  finally
  {
    if ($null -ne $stream) { $stream.Dispose() }
  }

}

function RemoveReadOnlyInFile {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $filePath
  )
  $file = Get-Item $filePath

  if ($file.IsReadOnly -eq $true)
  {
    $file.IsReadOnly = $false
  }
}

function SetVersion {
  [CmdletBinding()]
  param(
    [string]$filePath
  )
  Write-Host "---------Begin SetVersion----------------------------------- "
  Write-Host "Current Directory:"
  Write-Host (Get-Location)

  Write-Host "filePath:"
  Write-Host ($filePath)

  RemoveReadOnlyInFile $filePath
  [string]$fileContent = Get-Content $filePath
  #get current version
  [string]$currentVersionText = [regex]::match($fileContent,'(?<=\[assembly: AssemblyVersion\(")\d+\.\d+\.\d+\.\d+(?="\))').Groups[0].Value
  Write-Host "Curent Version $($currentVersionText)"

  if (![string]::IsNullOrEmpty($currentVersionText)) {
    $currentVersion = [version]$currentVersionText
    $newVersion = [version][string]::Format("{0}.{1}.{2}.{3}",$currentVersion.Major
      ,$currentVersion.Minor,$currentVersion.Build,$currentVersion.Revision + 1)

    (Get-Content $filePath) |
    ForEach-Object { $_ -replace $currentVersionText,$newVersion.ToString() } |
    Out-File $filePath
    Write-Host "End Setting Version $($filePath)"
  }
  Write-Host "---------End SetVersion----------------------------------- "
}

function RemoveItemIfExist {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $filePath
  )
  $isFileExist = Test-Path $filePath
  if ($isFileExist) {
    Remove-Item $filePath
  }
}

function CreateAipWithNewVersion {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $version,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $aipFolder,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $aipFileName,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $bcoFile
  )
  Write-Host "---------Begin CreateAipWithNewVersion----------------------------------- "
  Write-Host "Current Directory:"
  Write-Host (Get-Location)

  Write-Host "version:"
  Write-Host ($version)

  Write-Host "aipFolder"
  Write-Host ($aipFolder)

  Write-Host "aipFileName:"
  Write-Host ($aipFileName)

  Write-Host "bcoFile:"
  Write-Host ($bcoFile)

  if (![string]::IsNullOrEmpty($aipFileName)) {
    # get latest file
    $aipFile = Get-ChildItem "$($aipFolder)\$($aipFileName)*.aip" | Sort { $_.LastWriteTime } | Select-Object -Last 1
    Write-Host "latest file:"
    Write-Host ($aipFile)
    if (![string]::IsNullOrEmpty($aipFile)) {
      Write-Host "Latest aipFile:"
      Write-Host ($aipFile)
      $aipFileNew = ""
      $type = Get-ExecutableType -Path $bcoFile
      Write-Host "type:"
      Write-Host ($type)
      if ($type -eq "32-bit")
      {
        $aipFileNew = "$($aipFolder)\$($aipFileName)_$($version)_x86.aip"

      }
      elseif ($type -eq "64-bit")
      {
        $aipFileNew = "$($aipFolder)\$($aipFileName)_$($version)_x64.aip"

      }
      if (![string]::IsNullOrEmpty($aipFileNew)) {
        RemoveItemIfExist $aipFileNew
        Copy-Item $aipFile $aipFileNew -Force
      }
    }
    Write-Host "End CreateAipWithNewVersion $($aipFileNew)"
    return $aipFileNew
  }
}

function SetVersionAndBuildAip {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $aicmd,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $aipFile,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $version
  )
  Write-Host "---------Begin SetVersionAndBuildAip----------------------------------- "
  Write-Host "Current Directory:"
  Write-Host (Get-Location)

  Write-Host "aicmd:"
  Write-Host ($aicmd)

  Write-Host "aipFile:"
  Write-Host ($aipFile)

  Write-Host "version:"
  Write-Host ($version)

  $setVersionCmd = "$($aicmd) /edit $($aipFile) /SetVersion $($version) -noprodcode"
  $buildCmd = "$($aicmd) /build $($aipFile) "

  & $aicmd /edit $aipFile /SetVersion $version -noprodcode
  if ($? -eq $false) {
    exit 1
  }
  & $aicmd /build $aipFile
  if ($? -eq $false)
  {
    exit 1
  }
  Write-Host "---------End SetVersionAndBuildAip----------------------------------- "

}

function AddFileAndFolderToAip {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $aicmd,
    #[parameter (Mandatory=$true)] 
    #[ValidateNotNullOrEmpty()]
    #$aipFolder,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $appFolder,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $apiFilePath,
    $folderExclude = @( "NonObfuscatedAssemblyBackup","Confused","Release","Debug"),
    $fileExclude = @( "*.pdb","bco_log")
  )

  Write-Host "---------Begin AddFileAndFolderToAip----------------------------------- "
  Write-Host "Current Directory:"
  Write-Host (Get-Location)

  Write-Host "aicmd:"
  Write-Host ($aicmd)

  Write-Host "appFolder:"
  Write-Host ($appFolder)

  Write-Host "apiFilePath:"
  Write-Host ($apiFilePath)

  $directories = Get-ChildItem -Path $appFolder -Directory | Where-Object { $folderExclude -notcontains $_.Name }
  #$directories = Get-ChildItem -Path $appFolder -Directory -Exclude $folderExclude
  $files = Get-ChildItem -Path "$($appFolder)\*" -File -Exclude $fileExclude

  Write-Host "Add files ....."
  foreach ($f in $files) {
    $addFile = """$($aicmd)"" /edit ""$($pwd)\$($apiFilePath)"" /AddFile APPDIR ""$($f.FullName)"" "
    Write-Host $f.FullName
    & $aicmd /edit "$apiFilePath" /AddFile APPDIR $f.FullName
  }
  Write-Host "Add folders ....."
  foreach ($d in $directories) {
    Write-Host $d.FullName
    $dir_name = $d.Name
    $dir_fullName = $d.FullName
    & $aicmd /edit "$apiFilePath" /DelFolder APPDIR\$dir_name
    & $aicmd /edit "$apiFilePath" /AddFolder APPDIR $dir_fullName
  }
  Write-Host "---------End AddFileAndFolderToAip----------------------------------- "
}

function DeployBuild {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $pscmd,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $remotePcName,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $userName,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $password,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $deployScript,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $filePackage
  )
  Write-Host "---------Begin DeployBuild----------------------------------- "
  Write-Host "Current Directory:"
  Write-Host (Get-Location)

  Write-Host "pscmd:"
  Write-Host ($pscmd)

  Write-Host "remotePcName:"
  Write-Host ($remotePcName)

  Write-Host "userName:"
  Write-Host ($userName)

  Write-Host "deployScript:"
  Write-Host ($deployScript)

  Write-Host "filePackage:"
  Write-Host ($filePackage)

  ReplaceTextInFile $deployScript $deployScript '(?<=FILE_PACKAGE=).*\.(?:msi|exe)'

  & $pscmd $remotePcName -u $userName -p $password -c $deployScript C:\Temp\install.bat

  Write-Host "---------End DeployBuild----------------------------------- "
}
function ReplaceTextInFile {
  param(
    $filePath,$outPut,$pattern,$newValue
  )
  Write-Host "---------Begin ReplaceTextInFile----------------------------------- "
  Write-Host "Current Directory:"
  Write-Host (Get-Location)

  Write-Host "filePath:"
  Write-Host ($filePath)

  Write-Host "outPut:"
  Write-Host ($outPut)

  Write-Host "pattern:"
  Write-Host ($pattern)

  [string]$fileContent = Get-Content $filePath
  #get current version
  [string]$oldFilePackage = [regex]::match($fileContent,$pattern).Groups[0].Value
  (Get-Content $filePath) |
  ForEach-Object { $_ -replace $oldFilePackage,$newValue } |
  Out-File $outPut
}

#region Internal Tools
[hashtable]$ErrorCategory = @{ 0x80070057 = "InvalidArgument";
  0x800703EC = "InvalidData";
  0x80070490 = "ObjectNotFound";
  0x80070520 = "SecurityError";
  0x8007089A = "SecurityError" }

function Get-CredType
{
  param
  (
    [Parameter(Mandatory = $true)][ValidateSet("GENERIC",
      "DOMAIN_PASSWORD",
      "DOMAIN_CERTIFICATE",
      "DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE",
      "DOMAIN_EXTENDED",
      "MAXIMUM",
      "MAXIMUM_EX")] [string]$CredType
  )

  switch ($CredType)
  {
    "GENERIC" { return [PsUtils.CredMan+CRED_TYPE]::GENERIC }
    "DOMAIN_PASSWORD" { return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_PASSWORD }
    "DOMAIN_CERTIFICATE" { return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_CERTIFICATE }
    "DOMAIN_VISIBLE_PASSWORD" { return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_VISIBLE_PASSWORD }
    "GENERIC_CERTIFICATE" { return [PsUtils.CredMan+CRED_TYPE]::GENERIC_CERTIFICATE }
    "DOMAIN_EXTENDED" { return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_EXTENDED }
    "MAXIMUM" { return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM }
    "MAXIMUM_EX" { return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM_EX }
  }
}

function Get-CredPersist
{
  param
  (
    [Parameter(Mandatory = $true)][ValidateSet("SESSION",
      "LOCAL_MACHINE",
      "ENTERPRISE")] [string]$CredPersist
  )

  switch ($CredPersist)
  {
    "SESSION" { return [PsUtils.CredMan+CRED_PERSIST]::SESSION }
    "LOCAL_MACHINE" { return [PsUtils.CredMan+CRED_PERSIST]::LOCAL_MACHINE }
    "ENTERPRISE" { return [PsUtils.CredMan+CRED_PERSIST]::ENTERPRISE }
  }
}
#endregion

#region Dot-Sourced API
function Del-Creds
{
<#
.Synopsis
  Deletes the specified credentials

.Description
  Calls Win32 CredDeleteW via [PsUtils.CredMan]::CredDelete

.INPUTS
  See function-level notes

.OUTPUTS
  0 or non-0 according to action success
  [Management.Automation.ErrorRecord] if error encountered

.PARAMETER Target
  Specifies the URI for which the credentials are associated
  
.PARAMETER CredType
  Specifies the desired credentials type; defaults to 
  "CRED_TYPE_GENERIC"
#>

  param
  (
    [Parameter(Mandatory = $true)][ValidateLength(1,32767)] [string]$Target,
    [Parameter(Mandatory = $false)][ValidateSet("GENERIC",
      "DOMAIN_PASSWORD",
      "DOMAIN_CERTIFICATE",
      "DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE",
      "DOMAIN_EXTENDED",
      "MAXIMUM",
      "MAXIMUM_EX")] [string]$CredType = "GENERIC"
  )

  [int]$Results = 0
  try
  {
    $Results = [PsUtils.CredMan]::CredDelete($Target,$(Get-CredType $CredType))
  }
  catch
  {
    return $_
  }
  if (0 -ne $Results)
  {
    [string]$Msg = "Failed to delete credentials store for target '$Target'"
    [Management.ManagementException]$MgmtException = New-Object Management.ManagementException ($Msg)
    [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord ($MgmtException,$Results.ToString("X"),$ErrorCategory[$Results],$null)
    return $ErrRcd
  }
  return $Results
}

function Enum-Creds
{
<#
.Synopsis
  Enumerates stored credentials for operating user

.Description
  Calls Win32 CredEnumerateW via [PsUtils.CredMan]::CredEnum

.INPUTS
  

.OUTPUTS
  [PsUtils.CredMan+Credential[]] if successful
  [Management.Automation.ErrorRecord] if unsuccessful or error encountered

.PARAMETER Filter
  Specifies the filter to be applied to the query
  Defaults to [String]::Empty
  
#>

  param
  (
    [Parameter(Mandatory = $false)][AllowEmptyString()] [string]$Filter = [string]::Empty
  )

  [PsUtils.CredMan+Credential[]]$Creds = [array]::CreateInstance([PsUtils.CredMan+Credential],0)
  [int]$Results = 0
  try
  {
    $Results = [PsUtils.CredMan]::CredEnum($Filter,[ref]$Creds)
  }
  catch
  {
    return $_
  }
  switch ($Results)
  {
    0 { break }
    0x80070490 { break } #ERROR_NOT_FOUND
    default
    {
      [string]$Msg = "Failed to enumerate credentials store for user '$Env:UserName'"
      [Management.ManagementException]$MgmtException = New-Object Management.ManagementException ($Msg)
      [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord ($MgmtException,$Results.ToString("X"),$ErrorCategory[$Results],$null)
      return $ErrRcd
    }
  }
  return $Creds
}

function Read-Creds
{
<#
.Synopsis
  Reads specified credentials for operating user

.Description
  Calls Win32 CredReadW via [PsUtils.CredMan]::CredRead

.INPUTS

.OUTPUTS
  [PsUtils.CredMan+Credential] if successful
  [Management.Automation.ErrorRecord] if unsuccessful or error encountered

.PARAMETER Target
  Specifies the URI for which the credentials are associated
  If not provided, the username is used as the target
  
.PARAMETER CredType
  Specifies the desired credentials type; defaults to 
  "CRED_TYPE_GENERIC"
#>

  param
  (
    [Parameter(Mandatory = $true)][ValidateLength(1,32767)] [string]$Target,
    [Parameter(Mandatory = $false)][ValidateSet("GENERIC",
      "DOMAIN_PASSWORD",
      "DOMAIN_CERTIFICATE",
      "DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE",
      "DOMAIN_EXTENDED",
      "MAXIMUM",
      "MAXIMUM_EX")] [string]$CredType = "GENERIC"
  )

  if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
  {
    [string]$Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
    [Management.ManagementException]$MgmtException = New-Object Management.ManagementException ($Msg)
    [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord ($MgmtException,666,'LimitsExceeded',$null)
    return $ErrRcd
  }
  [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
  [int]$Results = 0
  try
  {
    $Results = [PsUtils.CredMan]::CredRead($Target,$(Get-CredType $CredType),[ref]$Cred)
  }
  catch
  {
    return $_
  }

  switch ($Results)
  {
    0 { break }
    0x80070490 { return $null } #ERROR_NOT_FOUND
    default
    {
      [string]$Msg = "Error reading credentials for target '$Target' from '$Env:UserName' credentials store"
      [Management.ManagementException]$MgmtException = New-Object Management.ManagementException ($Msg)
      [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord ($MgmtException,$Results.ToString("X"),$ErrorCategory[$Results],$null)
      return $ErrRcd
    }
  }
  return $Cred
}

function Write-Creds
{
<#
.Synopsis
  Saves or updates specified credentials for operating user

.Description
  Calls Win32 CredWriteW via [PsUtils.CredMan]::CredWrite

.INPUTS

.OUTPUTS
  [Boolean] true if successful
  [Management.Automation.ErrorRecord] if unsuccessful or error encountered

.PARAMETER Target
  Specifies the URI for which the credentials are associated
  If not provided, the username is used as the target
  
.PARAMETER UserName
  Specifies the name of credential to be read
  
.PARAMETER Password
  Specifies the password of credential to be read
  
.PARAMETER Comment
  Allows the caller to specify the comment associated with 
  these credentials
  
.PARAMETER CredType
  Specifies the desired credentials type; defaults to 
  "CRED_TYPE_GENERIC"

.PARAMETER CredPersist
  Specifies the desired credentials storage type;
  defaults to "CRED_PERSIST_ENTERPRISE"
#>

  param
  (
    [Parameter(Mandatory = $false)][ValidateLength(0,32676)] [string]$Target,
    [Parameter(Mandatory = $true)][ValidateLength(1,512)] [string]$UserName,
    [Parameter(Mandatory = $true)][ValidateLength(1,512)] [string]$Password,
    [Parameter(Mandatory = $false)][ValidateLength(0,256)] [string]$Comment = [string]::Empty,
    [Parameter(Mandatory = $false)][ValidateSet("GENERIC",
      "DOMAIN_PASSWORD",
      "DOMAIN_CERTIFICATE",
      "DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE",
      "DOMAIN_EXTENDED",
      "MAXIMUM",
      "MAXIMUM_EX")] [string]$CredType = "GENERIC",
    [Parameter(Mandatory = $false)][ValidateSet("SESSION",
      "LOCAL_MACHINE",
      "ENTERPRISE")] [string]$CredPersist = "ENTERPRISE"
  )

  if ([string]::IsNullOrEmpty($Target))
  {
    $Target = $UserName
  }
  if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
  {
    [string]$Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
    [Management.ManagementException]$MgmtException = New-Object Management.ManagementException ($Msg)
    [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord ($MgmtException,666,'LimitsExceeded',$null)
    return $ErrRcd
  }
  if ([string]::IsNullOrEmpty($Comment))
  {
    $Comment = [string]::Format("Last edited by {0}\{1} on {2}",
      $Env:UserDomain,
      $Env:UserName,
      $Env:ComputerName)
  }
  [string]$DomainName = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
  [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
  switch ($Target -eq $UserName -and
    ("CRED_TYPE_DOMAIN_PASSWORD" -eq $CredType -or
      "CRED_TYPE_DOMAIN_CERTIFICATE" -eq $CredType))
  {
    $true { $Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::USERNAME_TARGET }
    $false { $Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::None }
  }
  $Cred.Type = Get-CredType $CredType
  $Cred.TargetName = $Target
  $Cred.UserName = $UserName
  $Cred.AttributeCount = 0
  $Cred.Persist = Get-CredPersist $CredPersist
  $Cred.CredentialBlobSize = [Text.Encoding]::Unicode.GetBytes($Password).Length
  $Cred.CredentialBlob = $Password
  $Cred.Comment = $Comment

  [int]$Results = 0
  try
  {
    $Results = [PsUtils.CredMan]::CredWrite($Cred)
  }
  catch
  {
    return $_
  }

  if (0 -ne $Results)
  {
    [string]$Msg = "Failed to write to credentials store for target '$Target' using '$UserName', '$Password', '$Comment'"
    [Management.ManagementException]$MgmtException = New-Object Management.ManagementException ($Msg)
    [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord ($MgmtException,$Results.ToString("X"),$ErrorCategory[$Results],$null)
    return $ErrRcd
  }
  return $Results
}

#endregion

#region Cmd-Line functionality
function CredManMain
{
  #region Adding credentials
  if ($AddCred)
  {
    if ([string]::IsNullOrEmpty($User) -or
      [string]::IsNullOrEmpty($Pass))
    {
      Write-Host "You must supply a user name and password (target URI is optional)."
      return
    }
    # may be [Int32] or [Management.Automation.ErrorRecord]
    [object]$Results = Write-Creds $Target $User $Pass $Comment $CredType $CredPersist
    if (0 -eq $Results)
    {
      [object]$Cred = Read-Creds $Target $CredType
      if ($null -eq $Cred)
      {
        Write-Host "Credentials for '$Target', '$User' was not found."
        return
      }
      if ($Cred -is [Management.Automation.ErrorRecord])
      {
        return $Cred
      }
      [string]$CredStr = @"
Successfully wrote or updated credentials as:
  UserName  : $($Cred.UserName)  
  Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
  Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC
  Comment   : $($Cred.Comment)
"@
      Write-Host $CredStr
      return
    }
    # will be a [Management.Automation.ErrorRecord]
    return $Results
  }
  #endregion	

  #region Removing credentials
  if ($DelCred)
  {
    if (-not $Target)
    {
      Write-Host "You must supply a target URI."
      return
    }
    # may be [Int32] or [Management.Automation.ErrorRecord]
    [object]$Results = Del-Creds $Target $CredType
    if (0 -eq $Results)
    {
      Write-Host "Successfully deleted credentials for '$Target'"
      return
    }
    # will be a [Management.Automation.ErrorRecord]
    return $Results
  }
  #endregion

  #region Reading selected credential
  if ($GetCred)
  {
    if (-not $Target)
    {
      Write-Host "You must supply a target URI."
      return
    }
    # may be [PsUtils.CredMan+Credential] or [Management.Automation.ErrorRecord]
    [object]$Cred = Read-Creds $Target $CredType
    if ($null -eq $Cred)
    {
      Write-Host "Credential for '$Target' as '$CredType' type was not found."
      return
    }
    if ($Cred -is [Management.Automation.ErrorRecord])
    {
      return $Cred
    }
    [string]$CredStr = @"
Found credentials as:
  UserName  : $($Cred.UserName)  
  Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
  Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC
  Comment   : $($Cred.Comment)
"@
    Write-Host $CredStr
    return $Cred
  }
  #endregion

  #region Reading all credentials
  if ($ShoCred)
  {
    # may be [PsUtils.CredMan+Credential[]] or [Management.Automation.ErrorRecord]
    [object]$Creds = Enum-Creds
    if ($Creds -split [array] -and 0 -eq $Creds.Length)
    {
      Write-Host "No Credentials found for $($Env:UserName)"
      return
    }
    if ($Creds -is [Management.Automation.ErrorRecord])
    {
      return $Creds
    }
    foreach ($Cred in $Creds)
    {
      [string]$CredStr = @"
			
UserName  : $($Cred.UserName)
Target    : $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
Updated   : $([String]::Format("{0:yyyy-MM-dd HH:mm:ss}", $Cred.LastWritten.ToUniversalTime())) UTC
Comment   : $($Cred.Comment)
"@
      if ($All)
      {
        $CredStr = @"
$CredStr
Alias     : $($Cred.TargetAlias)
AttribCnt : $($Cred.AttributeCount)
Attribs   : $($Cred.Attributes)
Flags     : $($Cred.Flags)
Pwd Size  : $($Cred.CredentialBlobSize)
Storage   : $($Cred.Persist)
Type      : $($Cred.Type)
"@
      }
      Write-Host $CredStr
    }
    return
  }
  #endregion

  #region Run basic diagnostics
  if ($RunTests)
  {
    [PsUtils.CredMan]::Main()
  }
  #endregion
}
#endregion
function CredMan {

  param
  (
    [Parameter(Mandatory = $false)] [switch]$AddCred,
    [Parameter(Mandatory = $false)] [switch]$DelCred,
    [Parameter(Mandatory = $false)] [switch]$GetCred,
    [Parameter(Mandatory = $false)] [switch]$ShoCred,
    [Parameter(Mandatory = $false)] [switch]$RunTests,
    [Parameter(Mandatory = $false)][ValidateLength(1,32767) <# CRED_MAX_GENERIC_TARGET_NAME_LENGTH #>] [string]$Target,
    [Parameter(Mandatory = $false)][ValidateLength(1,512) <# CRED_MAX_USERNAME_LENGTH #>] [string]$User,
    [Parameter(Mandatory = $false)][ValidateLength(1,512) <# CRED_MAX_CREDENTIAL_BLOB_SIZE #>] [string]$Pass,
    [Parameter(Mandatory = $false)][ValidateLength(1,256) <# CRED_MAX_STRING_LENGTH #>] [string]$Comment,
    [Parameter(Mandatory = $false)] [switch]$All,
    [Parameter(Mandatory = $false)][ValidateSet("GENERIC",
      "DOMAIN_PASSWORD",
      "DOMAIN_CERTIFICATE",
      "DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE",
      "DOMAIN_EXTENDED",
      "MAXIMUM",
      "MAXIMUM_EX")] [string]$CredType = "GENERIC",
    [Parameter(Mandatory = $false)][ValidateSet("SESSION",
      "LOCAL_MACHINE",
      "ENTERPRISE")] [string]$CredPersist = "ENTERPRISE"
  )

  #region Pinvoke
  #region Inline C#
  [string]$PsCredmanUtils = @"
using System;
using System.Runtime.InteropServices;

namespace PsUtils
{
    public class CredMan
    {
        #region Imports
        // DllImport derives from System.Runtime.InteropServices
        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
        private static extern bool CredDeleteW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode)]
        private static extern bool CredEnumerateW([In] string Filter, [In] int Flags, out int Count, out IntPtr CredentialPtr);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
        private static extern void CredFree([In] IntPtr cred);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
        private static extern bool CredReadW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag, out IntPtr CredentialPtr);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
        private static extern bool CredWriteW([In] ref Credential userCredential, [In] UInt32 flags);
        #endregion

        #region Fields
        public enum CRED_FLAGS : uint
        {
            NONE = 0x0,
            PROMPT_NOW = 0x2,
            USERNAME_TARGET = 0x4
        }

        public enum CRED_ERRORS : uint
        {
            ERROR_SUCCESS = 0x0,
            ERROR_INVALID_PARAMETER = 0x80070057,
            ERROR_INVALID_FLAGS = 0x800703EC,
            ERROR_NOT_FOUND = 0x80070490,
            ERROR_NO_SUCH_LOGON_SESSION = 0x80070520,
            ERROR_BAD_USERNAME = 0x8007089A
        }

        public enum CRED_PERSIST : uint
        {
            SESSION = 1,
            LOCAL_MACHINE = 2,
            ENTERPRISE = 3
        }

        public enum CRED_TYPE : uint
        {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            GENERIC_CERTIFICATE = 5,
            DOMAIN_EXTENDED = 6,
            MAXIMUM = 7,      // Maximum supported cred type
            MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct Credential
        {
            public CRED_FLAGS Flags;
            public CRED_TYPE Type;
            public string TargetName;
            public string Comment;
            public DateTime LastWritten;
            public UInt32 CredentialBlobSize;
            public string CredentialBlob;
            public CRED_PERSIST Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NativeCredential
        {
            public CRED_FLAGS Flags;
            public CRED_TYPE Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public UInt32 CredentialBlobSize;
            public IntPtr CredentialBlob;
            public UInt32 Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }
        #endregion

        #region Child Class
        private class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
        {
            public CriticalCredentialHandle(IntPtr preexistingHandle)
            {
                SetHandle(preexistingHandle);
            }

            private Credential XlateNativeCred(IntPtr pCred)
            {
                NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(pCred, typeof(NativeCredential));
                Credential cred = new Credential();
                cred.Type = ncred.Type;
                cred.Flags = ncred.Flags;
                cred.Persist = (CRED_PERSIST)ncred.Persist;

                long LastWritten = ncred.LastWritten.dwHighDateTime;
                LastWritten = (LastWritten << 32) + ncred.LastWritten.dwLowDateTime;
                cred.LastWritten = DateTime.FromFileTime(LastWritten);

                cred.UserName = Marshal.PtrToStringUni(ncred.UserName);
                cred.TargetName = Marshal.PtrToStringUni(ncred.TargetName);
                cred.TargetAlias = Marshal.PtrToStringUni(ncred.TargetAlias);
                cred.Comment = Marshal.PtrToStringUni(ncred.Comment);
                cred.CredentialBlobSize = ncred.CredentialBlobSize;
                if (0 < ncred.CredentialBlobSize)
                {
                    cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob, (int)ncred.CredentialBlobSize / 2);
                }
                return cred;
            }

            public Credential GetCredential()
            {
                if (IsInvalid)
                {
                    throw new InvalidOperationException("Invalid CriticalHandle!");
                }
                Credential cred = XlateNativeCred(handle);
                return cred;
            }

            public Credential[] GetCredentials(int count)
            {
                if (IsInvalid)
                {
                    throw new InvalidOperationException("Invalid CriticalHandle!");
                }
                Credential[] Credentials = new Credential[count];
                IntPtr pTemp = IntPtr.Zero;
                for (int inx = 0; inx < count; inx++)
                {
                    pTemp = Marshal.ReadIntPtr(handle, inx * IntPtr.Size);
                    Credential cred = XlateNativeCred(pTemp);
                    Credentials[inx] = cred;
                }
                return Credentials;
            }

            override protected bool ReleaseHandle()
            {
                if (IsInvalid)
                {
                    return false;
                }
                CredFree(handle);
                SetHandleAsInvalid();
                return true;
            }
        }
        #endregion

        #region Custom API
        public static int CredDelete(string target, CRED_TYPE type)
        {
            if (!CredDeleteW(target, type, 0))
            {
                return Marshal.GetHRForLastWin32Error();
            }
            return 0;
        }

        public static int CredEnum(string Filter, out Credential[] Credentials)
        {
            int count = 0;
            int Flags = 0x0;
            if (string.IsNullOrEmpty(Filter) ||
                "*" == Filter)
            {
                Filter = null;
                if (6 <= Environment.OSVersion.Version.Major)
                {
                    Flags = 0x1; //CRED_ENUMERATE_ALL_CREDENTIALS; only valid is OS >= Vista
                }
            }
            IntPtr pCredentials = IntPtr.Zero;
            if (!CredEnumerateW(Filter, Flags, out count, out pCredentials))
            {
                Credentials = null;
                return Marshal.GetHRForLastWin32Error(); 
            }
            CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredentials);
            Credentials = CredHandle.GetCredentials(count);
            return 0;
        }

        public static int CredRead(string target, CRED_TYPE type, out Credential Credential)
        {
            IntPtr pCredential = IntPtr.Zero;
            Credential = new Credential();
            if (!CredReadW(target, type, 0, out pCredential))
            {
                return Marshal.GetHRForLastWin32Error();
            }
            CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredential);
            Credential = CredHandle.GetCredential();
            return 0;
        }

        public static int CredWrite(Credential userCredential)
        {
            if (!CredWriteW(ref userCredential, 0))
            {
                return Marshal.GetHRForLastWin32Error();
            }
            return 0;
        }

        #endregion

        private static int AddCred()
        {
            Credential Cred = new Credential();
            string Password = "Password";
            Cred.Flags = 0;
            Cred.Type = CRED_TYPE.GENERIC;
            Cred.TargetName = "Target";
            Cred.UserName = "UserName";
            Cred.AttributeCount = 0;
            Cred.Persist = CRED_PERSIST.ENTERPRISE;
            Cred.CredentialBlobSize = (uint)Password.Length;
            Cred.CredentialBlob = Password;
            Cred.Comment = "Comment";
            return CredWrite(Cred);
        }

        private static bool CheckError(string TestName, CRED_ERRORS Rtn)
        {
            switch(Rtn)
            {
                case CRED_ERRORS.ERROR_SUCCESS:
                    Console.WriteLine(string.Format("'{0}' worked", TestName));
                    return true;
                case CRED_ERRORS.ERROR_INVALID_FLAGS:
                case CRED_ERRORS.ERROR_INVALID_PARAMETER:
                case CRED_ERRORS.ERROR_NO_SUCH_LOGON_SESSION:
                case CRED_ERRORS.ERROR_NOT_FOUND:
                case CRED_ERRORS.ERROR_BAD_USERNAME:
                    Console.WriteLine(string.Format("'{0}' failed; {1}.", TestName, Rtn));
                    break;
                default:
                    Console.WriteLine(string.Format("'{0}' failed; 0x{1}.", TestName, Rtn.ToString("X")));
                    break;
            }
            return false;
        }

        /*
         * Note: the Main() function is primarily for debugging and testing in a Visual 
         * Studio session.  Although it will work from PowerShell, it's not very useful.
         */
        public static void Main()
        {
            Credential[] Creds = null;
            Credential Cred = new Credential();
            int Rtn = 0;

            Console.WriteLine("Testing CredWrite()");
            Rtn = AddCred();
            if (!CheckError("CredWrite", (CRED_ERRORS)Rtn))
            {
                return;
            }
            Console.WriteLine("Testing CredEnum()");
            Rtn = CredEnum(null, out Creds);
            if (!CheckError("CredEnum", (CRED_ERRORS)Rtn))
            {
                return;
            }
            Console.WriteLine("Testing CredRead()");
            Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
            if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
            {
                return;
            }
            Console.WriteLine("Testing CredDelete()");
            Rtn = CredDelete("Target", CRED_TYPE.GENERIC);
            if (!CheckError("CredDelete", (CRED_ERRORS)Rtn))
            {
                return;
            }
            Console.WriteLine("Testing CredRead() again");
            Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
            if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
            {
                Console.WriteLine("if the error is 'ERROR_NOT_FOUND', this result is OK.");
            }
        }
    }
}
"@
  #endregion

  $PsCredMan = $null
  try
  {
    $PsCredMan = [PsUtils.CredMan]
  }
  catch
  {
    #only remove the error we generate
    $Error.RemoveAt($Error.Count - 1)
  }
  if ($null -eq $PsCredMan)
  {
    Add-Type $PsCredmanUtils
  }
  #endregion
  CredManMain
}
#Export-ModuleMember -Function C
#Export-ModuleMember -Functions 'SetVersion'
#Export-ModuleMember -Functions 'SetVersionAndBuildAip'
#Export-ModuleMember -Functions 'CreateAipWithNewVersion'
#Export-ModuleMember -Functions 'DeployBuild'
#Export-ModuleMember -Functions 'AddFileAndFolderToAip'
