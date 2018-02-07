SET FILE_PACKAGE=\\192.168.2.4\Public\MDC2\Installers\MDC_II_2.9.500.13756_x86.msi
wmic product where name='MDC II' uninstall
msiexec.exe /i "%FILE_PACKAGE%" /quiet /norestart /L*V C:\install.log