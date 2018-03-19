
#
# AiBuild.ps1
#
function Publish-Package {	
    param(	
        [parameter (Mandatory = $true)] 
        [ValidateNotNullOrEmpty()]
        $remotePcName,
        $deployScript = $env:DEPLOY_SCRIPT,
        $pscmd = $env:PSCMD,	
        $moduleFolder = $env:MODULE_FOLDER 
	
	)
	
    Import-Modules $moduleFolder

    Write-Host "remotePcName:"
    Write-Host ($remotePcName)
    $cred = Select-Cred -GetCred $remotePcName
    $filePackage = $env:FILE_PACKAGE
    if (!([string]::IsNullOrEmpty($filePackage)) -and $env:IS_COPY -eq 1) {
        Install-Build $pscmd $remotePcName $cred.UserName $cred.CredentialBlob $deployScript $filePackage
    }
    else {
        Write-Host "Not deploy package on $remotePcName"
    }

}


