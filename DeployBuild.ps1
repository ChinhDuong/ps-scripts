
#
# AiBuild.ps1
#
param(	
	[parameter (Mandatory=$true)] 
	[ValidateNotNullOrEmpty()]
	$remotePcName,
	$deployScript=$env:DEPLOY_SCRIPT,
	$pscmd=$env:PSCMD,	
	$moduleFolder=$env:MODULE_FOLDER 
	
)

function ImportModules {
	param(
		$moduleFolder = ".\"
	)
	$module = Join-Path -Path $moduleFolder -ChildPath "AutoBuildUtility.psm1"
	Import-Module $module -Force
}
Write-Host "remotePcName:"
Write-Host ($remotePcName)

$cred = .\CredMan.ps1 -GetCred $remotePcName
$filePackage = $env:FILE_PACKAGE
ImportModules $moduleFolder
DeployBuild $pscmd $remotePcName $cred.UserName $cred.CredentialBlob $deployScript $filePackage