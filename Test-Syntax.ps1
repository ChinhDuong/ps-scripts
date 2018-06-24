function Test-Syntax ($filePath) {
    # Empty collection for errors
    $Errors = @()

    # Define input script
    $inputScript = Get-Content $filePath 

    [void][System.Management.Automation.Language.Parser]::ParseInput($inputScript,[ref]$null,[ref]$Errors)

    if($Errors.Count -gt 0){
        Write-Warning 'Errors found'
    }
    else{
        Write-Output "Ok"
    }
}
