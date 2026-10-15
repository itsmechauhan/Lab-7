@echo off
echo Cleaning System Temp...
del /s /f /q "C:\Windows\Temp\*.*" 2>nul
for /d %%p in ("C:\Windows\Temp\*") do rmdir "%%p" /s /q 2>nul

echo Cleaning All User Temp Profiles...
for /d %%u in ("C:\Users\*") do (
    if exist "%%u\AppData\Local\Temp" (
        del /s /f /q "%%u\AppData\Local\Temp\*.*" 2>nul
        for /d %%p in ("%%u\AppData\Local\Temp\*") do rmdir "%%p" /s /q 2>nul
    )
)
echo Done!
pause
