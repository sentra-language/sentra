@echo off
set passed=0
set failed=0

for %%f in (examples\*.sn) do (
    timeout /t 1 /nobreak > nul 2>&1
    sentra.exe run %%f > nul 2>&1
    if !errorlevel!==0 (
        echo PASS: %%~nf
        set /a passed+=1
    ) else (
        echo FAIL: %%~nf
        set /a failed+=1
    )
)

echo.
echo Results: %passed% passed, %failed% failed