@echo off
rem Runs the given command line inside a VS x64 developer environment.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%i"
if not defined VSROOT (echo Visual Studio C++ tools not found& exit /b 1)
call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" > NUL || exit /b 1
%*
