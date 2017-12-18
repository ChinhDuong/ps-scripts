
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
	Import-Module $module -Force -Verbose
}
ImportModules $moduleFolder

Write-Host "remotePcName:"
Write-Host ($remotePcName)
#try{
#	$cred = Select-Cred -GetCred $remotePcName
#	$filePackage = $env:FILE_PACKAGE
#	if([string]::IsNullOrEmpty($filePackage) -and $env:IS_COPY -eq 1){
#		Install-Build $pscmd $remotePcName $cred.UserName $cred.CredentialBlob $deployScript $filePackage
#	}
#	else{
#		Write-Host "Not deploy package on $remotePcName"
#	}
#}
#catch {
#	exit 1
#}

$cred = Select-Cred -GetCred $remotePcName
	$filePackage = $env:FILE_PACKAGE
	if(!([string]::IsNullOrEmpty($filePackage)) -and $env:IS_COPY -eq 1){
		Install-Build $pscmd $remotePcName $cred.UserName $cred.CredentialBlob $deployScript $filePackage
	}
	else{
		Write-Host "Not deploy package on $remotePcName"
	}
