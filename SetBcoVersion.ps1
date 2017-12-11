#
# SetBcoVersion.ps1
# Set version for bco build
#
param(	
	$moduleFolder=$env:MODULE_FOLDER ,
	$fileVersion=$env:ASSEMBLYINFO
)


function ImportModules {
	param(
		$moduleFolder = ".\"
	)
	$module = Join-Path -Path $moduleFolder -ChildPath "AutoBuildUtility.psm1"
	Import-Module $module -Force
}
Write-Host "Current Directory"
Write-Host (Get-Location)

Write-Host "moduleFolder:"
Write-Host $moduleFolder
ImportModules $moduleFolder
try {
	SetVersion $fileVersion
}
catch {
	exit 1
}
