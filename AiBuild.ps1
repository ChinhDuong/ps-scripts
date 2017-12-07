
#
# AiBuild.ps1
#
param(		
	[parameter (Mandatory=$true)] 
	[ValidateNotNullOrEmpty()]
	$aipFolder,
	[parameter (Mandatory=$true)] 
	[ValidateNotNullOrEmpty()]
	$appFolder,
	
	$moduleFolder=$env:MODULE_FOLDER ,	
	$aipFileName=$env:AIP_FILE_NAME ,
	$aicmd=$env:AICMD,	
	$OutputFolder=$env:OUTPUT_FOLDER ,		
	$isAdd=$env:IS_ADD,
	$appFileExe=$env:APP_FILE_EXE,
	$isCopy=$env:IS_COPY


)

function ImportModules {
	param(
		$moduleFolder = ".\"
	)
	$module = Join-Path -Path $moduleFolder -ChildPath "AutoBuildUtility.psm1"
	Import-Module $module -Force
}

function CopyToFolder{
	param(
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$moduleFolder,
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$aipFileNew,
		[parameter (Mandatory=$true)] 
		[ValidateNotNullOrEmpty()]
		$bcoInstallerFolder
	)
	Write-Host "---------Begin CopyToFolder----------------------------------- "
	Write-Host "Current Directory:"
	Write-Host (Get-Location)
	
	Write-Host "moduleFolder:"
	Write-Host ($moduleFolder)

	Write-Host "aipFileNew:"
	Write-Host ($aipFileNew)

	Write-Host "bcoInstallerFolder:"
	Write-Host ($bcoInstallerFolder)

	Write-Host "appFileExe:"
	Write-Host ($appFileExe)
		
	$file = Get-Item $aipFileNew
	$dir_path = "$($file.Directory)\$($file.BaseName)-SetupFiles"
	Copy-Item "$dir_path\*" -Destination $bcoInstallerFolder 
	
	Write-Host "---------End CopyToFolder----------------------------------- "

	
}
Write-Host "isAdd:"
Write-Host ($isAdd)
$bcoFile = "$($appFolder)\$($appFileExe)"

ImportModules $moduleFolder
$IsFileExist = Test-Path $bcoFile
If ($IsFileExist -eq $true ){
	$version = (Get-Item $bcoFile).VersionInfo.FileVersion
	$aipFileNew = CreateAipWithNewVersion $version $aipFolder $aipFileName $bcoFile	

	if ($isAdd -eq 1) {
		AddFileAndFolderToAip $aicmd $appFolder $aipFileNew
	}else{
		Write-Host "---------AddFileAndFolderToAip is ignored----------------------------------- "
	}
	
	SetVersionAndBuildAip $aicmd $aipFileNew $version
	
	if ($isCopy -eq 1) {
		CopyToFolder $moduleFolder $aipFileNew $OutputFolder 
	}else{
		Write-Host "---------CopyToFolder is ignored----------------------------------- " 
	}
	
}
