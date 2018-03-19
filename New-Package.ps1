
#
# AiBuild.ps1
#

function New-Package () {	
    param(		
        [parameter (Mandatory = $true)] 
        [ValidateNotNullOrEmpty()]
        $aipFolder,
        [parameter (Mandatory = $true)] 
        [ValidateNotNullOrEmpty()]
        $appFolder,
	
        $moduleFolder = $env:MODULE_FOLDER ,	
        $aipFileName = $env:AIP_FILE_NAME ,
        $aicmd = $env:AICMD,	
        $OutputFolder = $env:OUTPUT_FOLDER ,		
        $isAdd = $env:IS_ADD,
        $appFileExe = $env:APP_FILE_EXE,
        $isCopy = $env:IS_COPY
    )

    Write-Host "isAdd: $isAdd"
    Write-Host "moduleFolder: $moduleFolder"
    
    $bcoFile = "$($appFolder)\$($appFileExe)"

    $module = Join-Path -Path $moduleFolder -ChildPath "AutoBuildUtility.psm1"
    Import-Module $module -Force -Verbose
    
    $IsFileExist = Test-Path $bcoFile
    If ($IsFileExist -eq $true ) {
        try {
            $version = (Get-Item $bcoFile).VersionInfo.FileVersion
            $aipFileNew = New-AipWithNewVersion $version $aipFolder $aipFileName $bcoFile	

            if ($isAdd -eq 1) {
                Add-FileAndFolderToAip $aicmd $appFolder $aipFileNew
            }
            else {
                Write-Host "---------AddFileAndFolderToAip is ignored----------------------------------- "
            }
	
            Set-VersionAndBuildAip $aicmd $aipFileNew $version
	
            if ($isCopy -eq 1) {
                $fileName = Send-Build $moduleFolder $aipFileNew $OutputFolder 			
		
                $string = "FILE_PACKAGE=$($OutputFolder.Replace("\","\\"))\\$fileName`n"
                $string| Out-File "deploy.env.properties" -Encoding ASCII
            }
            else {
                Write-Host "---------CopyToFolder is ignored----------------------------------- " 
            }
        }
        catch {
            exit 1
        }
	
    }

}
