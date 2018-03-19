#
# SetBcoVersion.ps1
# Set version for bco build
#
function Increase-Version{
	param(	
	$moduleFolder=$env:MODULE_FOLDER ,
	$fileVersion=$env:ASSEMBLYINFO
	)
	Write-Host "Current Directory"
	Write-Host (Get-Location)

	Write-Host "moduleFolder:"
	Write-Host $moduleFolder
	ImportModules $moduleFolder
	try {
		Set-Version $fileVersion
	}
	catch {
		exit 1
	}
}

function ImportModules {
	param(
		$moduleFolder = ".\"
	)
	$module = Join-Path -Path $moduleFolder -ChildPath "AutoBuildUtility.psm1"
	Import-Module $module -Force -Verbose
}
