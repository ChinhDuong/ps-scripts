#
# SetBcoVersion.ps1
# Set version for bco build
#
. .\Common.ps1
function Update-Version{
	param(	
	$moduleFolder=$env:MODULE_FOLDER ,
	$fileVersion=$env:ASSEMBLYINFO
	)
	Write-Host "Current Directory"
	Write-Host (Get-Location)

	Write-Host "moduleFolder:"
	Write-Host $moduleFolder
	Import-Modules $moduleFolder
	try {
		Set-Version $fileVersion
	}
	catch {
		exit 1
	}
}

