@echo off
echo ==================================================
echo    WINEX CORE // WINDOWS SUITE BUILD SCRIPT
echo ==================================================

if not exist bin mkdir bin

echo Building WINEX Node...
cd cmd\winex-node
go build -trimpath -ldflags="-s -w" -o ..\..\bin\winex-node.exe .
if errorlevel 1 goto error
cd ..\..

echo Building WINEX Desktop Wallet...
cd cmd\winex-wallet
go build -trimpath -ldflags="-s -w -H=windowsgui" -o ..\..\bin\winex-wallet.exe .
if errorlevel 1 goto error
cd ..\..

echo Building WINEX Dedicated Miner...
cd cmd\winex-miner
go build -trimpath -ldflags="-s -w" -o ..\..\bin\winex-miner.exe .
if errorlevel 1 goto error
cd ..\..

echo.
echo All WINEX components successfully compiled into bin\
exit /b 0

:error
echo.
echo [ERROR] Build failed. Please check your Go installation (1.23+ required).
exit /b 1
