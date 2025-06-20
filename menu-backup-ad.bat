REM filepath: c:\Users\thiba\Documents\Environnement_dev\backup-ad-atp\menu-backup-ad.bat
@echo off
setlocal enabledelayedexpansion

:: Configuration des couleurs
set "COLOR_TITRE=0E"
set "COLOR_MENU=0B"
set "COLOR_OPTION=0F"
set "COLOR_ERREUR=0C"
set "COLOR_SUCCES=0A"
set "COLOR_INFO=09"

:MENU_PRINCIPAL
cls
color %COLOR_TITRE%
echo.
echo  ===============================================================
echo  ^|             SAUVEGARDE ACTIVE DIRECTORY                  ^|
echo  ===============================================================
echo.
color %COLOR_MENU%
echo  [1] Sauvegarde manuelle rapide
echo  [2] Sauvegarde complete avec base de donnees
echo  [3] Sauvegarde interactive (choisir elements)
echo  [4] Restauration interactive
echo  [5] Programmer sauvegarde automatique
echo  [6] Restaurer objets AD depuis sauvegarde
echo  [7] Voir les sauvegardes existantes
echo  [8] Nettoyer anciennes sauvegardes
echo  [9] Tester la connectivite AD
echo  [0] Quitter
echo.
color %COLOR_OPTION%
set /p "choix=Votre choix (0-9): "

if "%choix%"=="1" goto SAUVEGARDE_RAPIDE
if "%choix%"=="2" goto SAUVEGARDE_COMPLETE
if "%choix%"=="3" goto SAUVEGARDE_INTERACTIVE
if "%choix%"=="4" goto RESTAURATION_INTERACTIVE
if "%choix%"=="5" goto PROGRAMMER_SAUVEGARDE
if "%choix%"=="6" goto RESTAURER_OBJETS
if "%choix%"=="7" goto VOIR_SAUVEGARDES
if "%choix%"=="8" goto NETTOYER_SAUVEGARDES
if "%choix%"=="9" goto TESTER_AD
if "%choix%"=="0" goto QUITTER

color %COLOR_ERREUR%
echo Choix invalide. Appuyez sur une touche pour continuer...
pause >nul
goto MENU_PRINCIPAL

:SAUVEGARDE_RAPIDE
cls
color %COLOR_INFO%
echo ===============================================================
echo                 SAUVEGARDE RAPIDE
echo ===============================================================
echo.
echo Lancement de la sauvegarde rapide des objets AD...
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Backup-ActiveDirectory.ps1"
if errorlevel 1 (
    color %COLOR_ERREUR%
    echo Erreur lors de la sauvegarde!
) else (
    color %COLOR_SUCCES%
    echo Sauvegarde rapide terminee avec succes!
)
echo.
pause
goto MENU_PRINCIPAL

:SAUVEGARDE_COMPLETE
cls
color %COLOR_INFO%
echo ===============================================================
echo                SAUVEGARDE COMPLETE
echo ===============================================================
echo.
echo Lancement de la sauvegarde complete (objets + base de donnees)...
echo Cette operation peut prendre plusieurs minutes...
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Backup-ActiveDirectory.ps1" -FullBackup
if errorlevel 1 (
    color %COLOR_ERREUR%
    echo Erreur lors de la sauvegarde complete!
) else (
    color %COLOR_SUCCES%
    echo Sauvegarde complete terminee avec succes!
)
echo.
pause
goto MENU_PRINCIPAL

:SAUVEGARDE_INTERACTIVE
cls
color %COLOR_INFO%
echo ===============================================================
echo              SAUVEGARDE INTERACTIVE
echo ===============================================================
echo.
echo Lancement du menu de selection interactif...
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Backup-Interactive.ps1"
if errorlevel 1 (
    color %COLOR_ERREUR%
    echo Erreur lors de la sauvegarde interactive!
) else (
    color %COLOR_SUCCES%
    echo Sauvegarde interactive terminee!
)
echo.
pause
goto MENU_PRINCIPAL

:RESTAURER_OBJETS
cls
color %COLOR_INFO%
echo ===============================================================
echo                  RESTAURER OBJETS AD
echo ===============================================================
echo.
echo Lancement de la restauration simple...
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Restore-Interactive.ps1"
if errorlevel 1 (
    color %COLOR_ERREUR%
    echo Erreur lors de la restauration!
) else (
    color %COLOR_SUCCES%
    echo Restauration terminee!
)
echo.
pause
goto MENU_PRINCIPAL

:VOIR_SAUVEGARDES
cls
color %COLOR_INFO%
echo ===============================================================
echo               SAUVEGARDES EXISTANTES
echo ===============================================================
echo.
if exist "C:\ADBackup\" (
    for /f "tokens=*" %%a in ('dir /b /ad "C:\ADBackup\" 2^>nul') do (
        echo [DOSSIER] %%a
        for /f "tokens=*" %%b in ('dir /b "C:\ADBackup\%%a\*.csv" 2^>nul') do (
            echo     %%b
        )
        echo.
    )
) else (
    echo Aucune sauvegarde trouvee dans C:\ADBackup\
)
echo.
pause
goto MENU_PRINCIPAL

:NETTOYER_SAUVEGARDES
cls
color %COLOR_INFO%
echo ===============================================================
echo              NETTOYER ANCIENNES SAUVEGARDES
echo ===============================================================
echo.
set /p "jours=Supprimer les sauvegardes de plus de combien de jours? (defaut: 30): "
if "%jours%"=="" set "jours=30"
echo.
echo Suppression des sauvegardes de plus de %jours% jours...
forfiles /p "C:\ADBackup" /m *.* /d -%jours% /c "cmd /c rmdir /s /q @path" 2>nul
if errorlevel 1 (
    echo Aucune ancienne sauvegarde a supprimer.
) else (
    color %COLOR_SUCCES%
    echo Nettoyage termine!
)
echo.
pause
goto MENU_PRINCIPAL

:TESTER_AD
cls
color %COLOR_INFO%
echo ===============================================================
echo               TEST CONNECTIVITE AD
echo ===============================================================
echo.
echo Test de la connectivite Active Directory...
echo.
powershell.exe -Command "try { Import-Module ActiveDirectory; Get-ADDomain | Select-Object Name,DomainMode,PDCEmulator; Write-Host 'Connexion AD OK' -ForegroundColor Green } catch { Write-Host 'Erreur de connexion AD' -ForegroundColor Red }"
echo.
pause
goto MENU_PRINCIPAL

:RESTAURATION_INTERACTIVE
cls
color %COLOR_INFO%
echo ===============================================================
echo              RESTAURATION INTERACTIVE
echo ===============================================================
echo.
echo Lancement du menu de restauration interactive...
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Restore-Interactive.ps1"
if errorlevel 1 (
    color %COLOR_ERREUR%
    echo Erreur lors de la restauration interactive!
) else (
    color %COLOR_SUCCES%
    echo Restauration interactive terminee!
)
echo.
pause
goto MENU_PRINCIPAL

:PROGRAMMER_SAUVEGARDE
cls
color %COLOR_INFO%
echo ===============================================================
echo              PROGRAMMER SAUVEGARDE AUTOMATIQUE
echo ===============================================================
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Scripts\Schedule-ADBackup.ps1"
echo.
pause
goto MENU_PRINCIPAL

:QUITTER
cls
color %COLOR_SUCCES%
echo.
echo  ===============================================================
echo  ^|                     AU REVOIR!                         ^|
echo  ===============================================================
echo.
timeout /t 2 >nul
exit /b 0