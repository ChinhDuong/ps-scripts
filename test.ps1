Set-Location -Path C:\Users\dev1\Source\ps-scripts
$Path = "test-data\Blister_Check_Outs_1.7.3.1_x64.aip"
$xPath = "//COMPONENT[@cid='caphyon.advinst.msicomp.MsiFilesComponent']/ROW"
#Select-Xml -Path $Path -XPath $Xpath | Select-Object -ExpandProperty Node
#$SourcePaths = Select-Xml -Path $Path -XPath $Xpath | foreach {$_.node.SourcePath}
#$SourcePaths = Select-Xml -Path $Path -XPath $Xpath | Select-Object -ExpandProperty Node
#Select-Xml -Path $Path -XPath $Xpath | Select-Object -ExpandProperty Node
#foreach ($item in $SourcePaths)
#{
#    $item.ourcePath
#}

#Select-Xml -Path $Path -XPath $Xpath | Select-Object -ExpandProperty Node

#Select-Xml -Path $Path -XPath $Xpath | Select-Object -ExpandProperty Node | Select-Object SourcePath

#$file = Get-Item "test-data\Blister_Check_Outs_1.7.3.1_x64.aip"
#$file.FullName

$folderExclude = @( "NonObfuscatedAssemblyBackup","Confused","Release","Debug")
$fileExclude = @( "*.pdb","bco_log")

$appFolder = "test-data\Debug"
$directories = Get-ChildItem -Path $appFolder -Directory | Where-Object { $folderExclude -notcontains $_.Name }
$files = Get-ChildItem -Path "$($appFolder)\*" -File -Exclude $fileExclude
$aip = Get-Item "test-data\aip\Blister_Check_Outs_1.7.3.1_x64.aip"
Import-Module .\AutoBuildUtility.psm1  -Force -Verbose
#$list = Get-FilesDirsNotAdded $files $directories $aip $fileExclude
$aipFile = "test-data\aip\Blister_Check_Outs_1.7.3.1_x64.aip"
Clear-Host
$list
$aipcmd = "C:\Program Files (x86)\Caphyon\Advanced Installer 14.7\bin\x86\AdvancedInstaller.com"
Add-FileAndFolderToAip $aipcmd "test-data\Debug\" $aipFile $folderExclude $fileExclude
#Test-FileAdded .\test-data\aip\Blister_Check_Outs_1.7.3.1_x64.aip .\test-data\Debug\AutoMapper.dll
