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
[OutputType([String])]
param(
    [Parameter(
        Mandatory = $true,
        ValueFromPipeline = $true
    )]
    [AllowEmptyString()]
    [String]
    $Message ,

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
    [String]
    $Style ,

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
    [String]
    $ForegroundColor ,

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
    [String]
    $BackgroundColor
)

    Begin {
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

    Process {
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


function Copy-RemoteItemLocally(){
    [CmdletBinding(SupportsShouldProcess=$False)]
    Param (
        [Parameter(Mandatory=$true,position=0)]
        [String] $Source,
        
        [Parameter(Mandatory=$false,position=1)]
        [String] $Destination,
        
        [Parameter(Mandatory=$false,position=2)]
        [PSCredential] $SourceCredential,
        
        [switch] $Directory
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
    } catch [System.UnauthorizedAccessException] {
        $networkShare = $true
    }
    # Go parent directory path for file copy 
    $sourceDir = $Source
    $destinationDir = $Destination
    if(!$Directory){
    	$sourceDir = (Split-Path($Source))
    	$destinationDir = (Split-Path($destinationDir))
    }
    
    # Mapping networkshare drive
    if($networkShare){
    Write-Verbose "Network Share detected, need to map"
    Use-NetworkShare -SharePath $sourceDir -SharePathCredential $SourceCredential -Ensure "Present" | Out-Null
    }
    
    try {
    	if (!$Directory) {
			Write-Verbose ("Copy File $Source $Destination")
			if(!(Test-Path($destinationDir))){
			New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
			}
        				Copy-Item $Source $Destination -Force | Out-Null
					} else {
        				Write-Verbose ("Copy Directory $Source $Destination")
        				if (!(Test-Path($destinationDir))) {
			New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
			}
    	Get-ChildItem $sourceDir | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination  $destinationDir -Force -Container -Recurse | Out-Null
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
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]
        $Path
    )

    try
    {
        try
        {
            $stream = New-Object System.IO.FileStream(
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

        $bytes = New-Object byte[](4)

        if ($stream.Length -ge 64 -and
            $stream.Read($bytes, 0, 2) -eq 2 -and
            $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
        {
            $exeType = '16-bit'

            if ($stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) -eq 0x3C -and
                $stream.Read($bytes, 0, 4) -eq 4)
            {
                if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 4) }
                $peHeaderOffset = [System.BitConverter]::ToUInt32($bytes, 0)

                if ($stream.Length -ge $peHeaderOffset + 6 -and
                    $stream.Seek($peHeaderOffset, [System.IO.SeekOrigin]::Begin) -eq $peHeaderOffset -and
                    $stream.Read($bytes, 0, 4) -eq 4 -and
                    $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0)
                {
                    $exeType = 'Unknown'

                    if ($stream.Read($bytes, 0, 2) -eq 2)
                    {
                        if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 2) }
                        $machineType = [System.BitConverter]::ToUInt16($bytes, 0)

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

function RemoveReadOnlyInFile{
	param(
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$filePath
	)
	$file = Get-Item $filePath

	if ($file.IsReadOnly -eq $true)  
	{  
		$file.IsReadOnly = $false   
	}  
}

function SetVersion{
    [CmdletBinding()]
    param(
        [string] $filePath
    )
	Write-Host "---------Begin SetVersion----------------------------------- "
	Write-Host "Current Directory:"
	Write-Host (Get-Location)

	Write-Host "filePath:"
	Write-Host ($filePath)	

	RemoveReadOnlyInFile $filePath
    [string] $fileContent = Get-Content $filePath
	#get current version
    [string] $currentVersionText = [regex]::match($fileContent,'(?<=\[assembly: AssemblyVersion\(")\d+\.\d+\.\d+\.\d+(?="\))').Groups[0].Value
    Write-Host "Curent Version $($currentVersionText)"

    if(![string]::IsNullOrEmpty($currentVersionText)){
        $currentVersion = [version]$currentVersionText
        $newVersion = [version][string]::Format("{0}.{1}.{2}.{3}",$currentVersion.Major
            ,$currentVersion.Minor,$currentVersion.Build,$currentVersion.Revision+1)
        
        (Get-Content $filePath) | 
        Foreach-Object {$_ -replace $currentVersionText,$newVersion.ToString()}  | 
        Out-File $filePath        
		 Write-Host "End Setting Version $($filePath)"
    }
    Write-Host "---------End SetVersion----------------------------------- "
}

function RemoveItemIfExist{
	param(
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$filePath
	)
	$isFileExist = Test-Path $filePath
	if($isFileExist){
		Remove-Item $filePath
	}
}

function CreateAipWithNewVersion{
	param( 
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$version,
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$aipFolder,
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$aipFileName,
		[parameter (Mandatory=$true)] 
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
	
	if (![string]::IsNullOrEmpty($aipFileName)){
		# get latest file
		$aipFile = Get-ChildItem "$($aipFolder)\$($aipFileName)*.aip" | Sort {$_.LastWriteTime} | select -last 1
		Write-Host "latest file:"
		Write-Host ($aipFile)
		if (![string]::IsNullOrEmpty($aipFile)){
			Write-Host "Latest aipFile:"
			Write-Host ($aipFile)
			$aipFileNew = ""
			$type = Get-ExecutableType -Path $bcoFile
			Write-Host "type:"
			Write-Host ($type)
			If ($type -eq "32-bit")
			{				
				$aipFileNew = "$($aipFolder)\$($aipFileName)_$($version)_x86.aip"
				
			}
			elseIf ($type -eq"64-bit")	
			{
				$aipFileNew = "$($aipFolder)\$($aipFileName)_$($version)_x64.aip"
				
			}
			if(![string]::IsNullOrEmpty($aipFileNew)){
				RemoveItemIfExist $aipFileNew
				Copy-Item $aipFile $aipFileNew -force
			}
		}
		Write-Host "End CreateAipWithNewVersion $($aipFileNew)"
		return $aipFileNew
	}		
}

function SetVersionAndBuildAip{
	param( 
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$aicmd,
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$aipFile,
		[parameter (Mandatory=$true)] 
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
	& $aicmd /build $aipFile 
	Write-Host "---------End SetVersionAndBuildAip----------------------------------- "

}

function AddFileAndFolderToAip{
	param(
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$aicmd,
		#[parameter (Mandatory=$true)] 
		#[ValidateNotNullOrEmpty()]
		#$aipFolder,
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$appFolder,
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$apiFilePath,
		$folderExclude = @("NonObfuscatedAssemblyBackup","Confused","Release","Debug"),
		$fileExclude =  @("*.pdb","bco_log")
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

	$directories = Get-ChildItem -Path $appFolder -Directory -Exclude $folderExclude
	$files = Get-ChildItem -Path "$($appFolder)\*" -File -Exclude $fileExclude
	
	Write-Host "Add files ....."
	foreach ($f in $files){
		$addFile = """$($aicmd)"" /edit ""$($pwd)\$($apiFilePath)"" /AddFile APPDIR ""$($f.FullName)"" "
		Write-Host  $f.FullName
		&$aicmd /edit "$apiFilePath" /AddFile APPDIR $f.FullName
	}
	Write-Host "Add folders ....."
	foreach ($d in $directories) {				
		Write-Host  $d.FullName
		$dir_name = $d.Name
		$dir_fullName = $d.FullName
		&$aicmd /edit "$apiFilePath" /DelFolder APPDIR\$dir_name
		&$aicmd /edit "$apiFilePath" /AddFolder APPDIR $dir_fullName		
	}
	Write-Host "---------End AddFileAndFolderToAip----------------------------------- "
}

#function CopyToFolder{
#	param(
#		[parameter (Mandatory=$true)] 
#		[ValidateNotNullOrEmpty()]
#		$aipFileNew,		
#		[parameter (Mandatory=$true)] 
#		[ValidateNotNullOrEmpty()]
#		$bcoInstallerFolder		
#	)
#	Write-Host "---------Begin CopyToFolder----------------------------------- "
#	Write-Host "Current Directory:"
#	Write-Host (Get-Location)
	
#	Write-Host "aipFileNew:"
#	Write-Host ($aipFileNew)

#	Write-Host "bcoInstallerFolder:"
#	Write-Host ($bcoInstallerFolder)

#	$file = Get-Item $aipFileNew
#	$dir_path = "$($file.Directory)\$($file.BaseName)-SetupFiles\"
#	$isExist = Test-Path $dir_path,$bcoInstallerFolder
#	if($isExist[0] -eq $true -and $isExist[1] -eq $true){
#		Copy-Item "$dir_path\*" -Recurse -Destination $bcoInstallerFolder
#		#Copy-RemoteItemLocally 
#	}
#	Write-Host "---------End CopyToFolder----------------------------------- "
#}
#Export-ModuleMember -Function Get-ExecutableType