@echo off
setlocal enabledelayedexpansion

:: Script simple d'execution des sauvegardes Active Directory
:: Auteur: Thibaut Maurras
:: Version: 1.0

:: Configuration des couleurs
set "COLOR_TITRE=0E"
set "COLOR_ERREUR=0C"
set "COLOR_SUCCES=0A"
set "COLOR_INFO=09"

:: Verification des privileges administrateur
net session >nul 2>&1
if %errorLevel% neq 0 (
    color %COLOR_ERREUR%
    echo.
    echo ===============================================================
    echo                    PRIVILEGES REQUIS
    echo ===============================================================
    echo.
    echo Ce script necessite des privileges administrateur.
    echo Relancez-le en tant qu'administrateur.
    echo.
    pause
    exit /b 1
)

:MENU_SIMPLE
cls
color %COLOR_TITRE%
echo.
echo  ===============================================================
echo  ^|        SAUVEGARDE ACTIVE DIRECTORY - SIMPLE              ^|
echo  ===============================================================
echo.
color %COLOR_INFO%
echo  [1] Sauvegarde rapide (objets essentiels)
echo  [2] Sauvegarde complete (avec base de donnees)
echo  [3] Sauvegarde personnalisee (menu avance)
echo  [4] Restauration
echo  [5] Programmation automatique
echo  [0] Quitter
echo.
set /p "choix=Votre choix (0-5): "

if "%choix%"=="1" goto BACKUP_RAPIDE
if "%choix%"=="2" goto BACKUP_COMPLET
if "%choix%"=="3" goto MENU_AVANCE
if "%choix%"=="4" goto RESTORATION
if "%choix%"=="5" goto PROGRAMMATION
if "%choix%"=="0" goto QUITTER

echo Choix invalide!
timeout /t 2 >nul
goto MENU_SIMPLE

:BACKUP_RAPIDE
cls
echo ===============================================================
echo                   SAUVEGARDE RAPIDE
echo ===============================================================
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Backup-ActiveDirectory.ps1"
goto FIN_OPERATION

:BACKUP_COMPLET
cls
echo ===============================================================
echo                  SAUVEGARDE COMPLETE
echo ===============================================================
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Backup-ActiveDirectory.ps1" -FullBackup
goto FIN_OPERATION

:MENU_AVANCE
call "%~dp0menu-backup-ad.bat"
goto MENU_SIMPLE

:RESTORATION
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Restore-Interactive.ps1"
goto FIN_OPERATION

:PROGRAMMATION
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Schedule-ADBackup.ps1"
goto FIN_OPERATION

:FIN_OPERATION
if errorlevel 1 (
    color %COLOR_ERREUR%
    echo.
    echo Operation terminee avec des erreurs!
) else (
    color %COLOR_SUCCES%
    echo.
    echo Operation terminee avec succes!
)
echo.
pause
goto MENU_SIMPLE

:QUITTER
cls
color %COLOR_SUCCES%
echo.
echo  Merci d'avoir utilise l'outil de sauvegarde AD!
echo.
timeout /t 2 >nul
exit /b 0
