#
# Script.ps1
#
param(
	$bcoFolder = "C:\Users\dev1\Source\Workspaces\VBM_BCO\VBM.BCO"
)

[string] $_vs14IdeDirectory= "C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\"
[string] $scriptDirectory = "C:\Users\dev1\Source\Workspaces\VBM_BCO\VBM.BCO"

function ImportModulesForThisScript
{
	[CmdletBinding()]
	param()
	$ScriptDirectory = $PSScriptRoot
	$module = Join-Path -Path $ScriptDirectory -ChildPath "..\Utility\Utility.psm1"
	Import-Module $module -Force
}

function GetLatestCode
{
    [CmdletBinding()]
	param()
    $_fileTf= Join-Path -Path $_vs14IdeDirectory -ChildPath "TF.exe"
    $userName = "chinhdq"
    $password = Get-Content D:\pass.txt |ConvertTo-SecureString
    &$_fileTf get /overwrite /recursive /login:globalfactories\chinh.dq,$password
    Write-Host "Getting latest code is completed"
}

function SetVersion{
    [CmdletBinding()]
    param(
        
    )
    $fileVersion = Join-Path -Path $scriptDirectory -ChildPath "SharedAssemblyInfo.cs"
    [string] $fileVersionContent = Get-Content $fileVersion
    [string] $currentVersionText = [regex]::match($fileVersionContent,'(?<=\[assembly: AssemblyVersion\(")\d+\.\d+\.\d+\.\d+(?="\))').Groups[0].Value
    
    if(![string]::IsNullOrEmpty($currentVersionText)){
        $currentVersion = [version]$currentVersionText
        $newVersion = [version][string]::Format("{0}.{1}.{2}.{3}",$currentVersion.Major
            ,$currentVersion.Minor,$currentVersion.Build,$currentVersion.Revision+1)
        
        (Get-Content $fileVersion) | 
        Foreach-Object {$_ -replace $currentVersionText,$newVersion.ToString()}  | 
        Out-File $fileVersion
        
    }
    
}
function BuildBco
{
    [CmdletBinding()]
	param(
        [string] $configuration,
		[string] $platform
    )
    $_fileDevenv = Join-Path -Path $_vs14IdeDirectory -ChildPath "devenv.exe"
    $fileSolution = Join-Path -Path $scriptDirectory -ChildPath "VBM_BCO.sln"
    $fileProject = Join-Path -Path $scriptDirectory -ChildPath "VBM_BCO\VBM.BCO.csproj"

    $timestamp = Get-Date -Format yyyyMMddTHHmmssffffZ 
	$buildConfiguration = "$configuration|$platform"
    $fileLogName = "build.$configuration.$platform.$timestamp.txt"
    $fileLog = Join-Path -Path $scriptDirectory -ChildPath $fileLogName

    $fsw = New-Object IO.FileSystemWatcher $scriptDirectory, $fileLogName -Property @{IncludeSubdirectories = $false;NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'}
    Register-ObjectEvent $fsw Changed -SourceIdentifier FileChanged -Action { 

        Unregister-Event FileChanged
        $resultBuildText = (Get-Content $fileLog)[-1..-2]
        $fail = [regex]::match($fileContent,'\d+(?=\sfailed)').Groups[0].Value
        
    } 
    
    &$_fileDevenv $fileSolution /Build $buildConfiguration  /out $fileLog
    Write-Host "Building bco $buildConfiguration...."
}

$scriptDirectory = $bcoFolder
Clear-Host
# $ScriptDirectory = $PSScriptRoot
Set-Location $scriptDirectory
#GetLatestCode
SetVersion
#BuildBco "ObfuscatedRelease" "x64"
#BuildBco "ObfuscatedRelease" "Any Cpu"


