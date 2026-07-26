@echo off
if "%~1"=="-hidden" goto RUN_PS
start /min "" mshta vbscript:CreateObject("WScript.Shell").Run("""%~f0"" -hidden",0,false)(window.close)
exit

:RUN_PS
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0gui.ps1"