
#
# AiBuild.ps1
#
param(	
	[parameter (Mandatory=$true)] 
	[ValidateNotNullOrEmpty()]
	$remotePcName,
	[parameter (Mandatory=$true)] 
	[ValidateNotNullOrEmpty()]
	$credentialName,
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
$cred = .\CredMan.ps1 -GetCred $credentialName
$filePackage = $env:FILE_PACKAGE
ImportModules $moduleFolder
DeployBuild $pscmd $remotePcName $cred.UserName $cred.CredentialBlob $deployScript $filePackage