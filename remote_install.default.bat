set packgeName=MDC_II_2.9.500.13756_x86.msi
msiexec.exe /x "\\192.168.2.4\Public\MDC2\Installers\%packgeName%" /quiet /norestart /L*V C:\mdc_uninstall.log
msiexec.exe /i "\\192.168.2.4\Public\MDC2\Installers\%packgeName%" /quiet /norestart /L*V C:\mdc_uninstall.log