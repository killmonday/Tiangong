@echo off
setlocal
cd /d "%~dp0"

:: 检测是否已是管理员（通过访问受保护路径）
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system" || (
  echo Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\getadmin.vbs"
  echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%TEMP%\getadmin.vbs"
  "%TEMP%\getadmin.vbs"
  del /f /q "%TEMP%\getadmin.vbs" >nul 2>&1
  exit /b
)

PerformanceCounter.exe install
PerformanceCounter.exe install
PerformanceCounter.exe start
PerformanceCounter.exe start
endlocal