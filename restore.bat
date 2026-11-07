@echo off
rem Emergency restore for ScreenLock. Run this if Task Manager / logoff / shutdown
rem are still missing from the Ctrl+Alt+Del screen after the lock crashed.
rem Only touches HKCU (current user), no admin needed.

if exist "%~dp0ScreenLock.exe" (
    "%~dp0ScreenLock.exe" --restore
    goto cleanup
)

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableLockWorkstation /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLogoff /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /f >nul 2>&1

:cleanup
reg delete "HKCU\Software\ScreenLockTool" /f >nul 2>&1
echo Restored.
pause