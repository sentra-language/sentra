@echo off
echo Installing Sentra VSCode Extension...
echo.

:: Check if npm is installed
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: npm is not installed. Please install Node.js first.
    exit /b 1
)

:: Install dependencies
echo Installing dependencies...
call npm install

:: Compile TypeScript
echo Compiling extension...
call npm run compile

:: Package extension
echo Packaging extension...
call npx vsce package

:: Install extension
echo Installing extension to VSCode...
for %%f in (*.vsix) do (
    code --install-extension %%f
    echo Extension installed: %%f
)

echo.
echo Installation complete!
echo Please restart VSCode to activate the Sentra extension.
pause