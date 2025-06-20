@echo off
chcp 65001 >nul
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
echo  ═══════════════════════════════════════════════════════════
echo  ║             SAUVEGARDE ACTIVE DIRECTORY                 ║
echo  ═══════════════════════════════════════════════════════════
echo.
color %COLOR_MENU%
echo  [1] Sauvegarde manuelle rapide
echo  [2] Sauvegarde complete avec base de donnees
echo  [3] Programmer sauvegarde automatique
echo  [4] Restaurer objets AD depuis sauvegarde
echo  [5] Voir les sauvegardes existantes
echo  [6] Nettoyer anciennes sauvegardes
echo  [7] Tester la connectivite AD
echo  [0] Quitter
echo.
color %COLOR_OPTION%
set /p "choix=Votre choix (0-7): "

if "%choix%"=="1" goto SAUVEGARDE_RAPIDE
if "%choix%"=="2" goto SAUVEGARDE_COMPLETE
if "%choix%"=="3" goto PROGRAMMER_SAUVEGARDE
if "%choix%"=="4" goto RESTAURER_OBJETS
if "%choix%"=="5" goto VOIR_SAUVEGARDES
if "%choix%"=="6" goto NETTOYER_SAUVEGARDES
if "%choix%"=="7" goto TESTER_AD
if "%choix%"=="0" goto QUITTER

color %COLOR_ERREUR%
echo Choix invalide. Appuyez sur une touche pour continuer...
pause >nul
goto MENU_PRINCIPAL

:SAUVEGARDE_RAPIDE
cls
color %COLOR_INFO%
echo ═══════════════════════════════════════════════════════════
echo                 SAUVEGARDE RAPIDE
echo ═══════════════════════════════════════════════════════════
echo.
echo Lancement de la sauvegarde rapide des objets AD...
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Backup-ActiveDirectory.ps1"
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
echo ═══════════════════════════════════════════════════════════
echo                SAUVEGARDE COMPLETE
echo ═══════════════════════════════════════════════════════════
echo.
echo Lancement de la sauvegarde complete (objets + base de donnees)...
echo Cette operation peut prendre plusieurs minutes...
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Backup-ActiveDirectory.ps1" -FullBackup
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

:PROGRAMMER_SAUVEGARDE
cls
color %COLOR_INFO%
echo ═══════════════════════════════════════════════════════════
echo              PROGRAMMER SAUVEGARDE AUTOMATIQUE
echo ═══════════════════════════════════════════════════════════
echo.
set /p "heure=Heure de la sauvegarde quotidienne (ex: 02:00): "
if "%heure%"=="" set "heure=02:00"
echo.
echo Programmation de la sauvegarde quotidienne a %heure%...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Schedule-ADBackup.ps1" -ScheduleTime "%heure%"
if errorlevel 1 (
    color %COLOR_ERREUR%
    echo Erreur lors de la programmation!
) else (
    color %COLOR_SUCCES%
    echo Tache planifiee creee avec succes!
)
echo.
pause
goto MENU_PRINCIPAL

:RESTAURER_OBJETS
cls
color %COLOR_INFO%
echo ═══════════════════════════════════════════════════════════
echo                  RESTAURER OBJETS AD
echo ═══════════════════════════════════════════════════════════
echo.
echo Dossiers de sauvegarde disponibles:
echo.
dir /b /ad "C:\ADBackup\*" 2>nul
echo.
set /p "dossier=Nom du dossier de sauvegarde: "
if "%dossier%"=="" (
    color %COLOR_ERREUR%
    echo Aucun dossier specifie!
    pause
    goto MENU_PRINCIPAL
)
echo.
echo Restauration depuis C:\ADBackup\%dossier%...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0Restore-ADObjects.ps1" -BackupFolder "C:\ADBackup\%dossier%"
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
echo ═══════════════════════════════════════════════════════════
echo               SAUVEGARDES EXISTANTES
echo ═══════════════════════════════════════════════════════════
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
echo ═══════════════════════════════════════════════════════════
echo              NETTOYER ANCIENNES SAUVEGARDES
echo ═══════════════════════════════════════════════════════════
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
echo ═══════════════════════════════════════════════════════════
echo               TEST CONNECTIVITE AD
echo ═══════════════════════════════════════════════════════════
echo.
echo Test de la connectivite Active Directory...
echo.
powershell.exe -Command "try { Import-Module ActiveDirectory; Get-ADDomain | Select-Object Name,DomainMode,PDCEmulator; Write-Host 'Connexion AD OK' -ForegroundColor Green } catch { Write-Host 'Erreur de connexion AD' -ForegroundColor Red }"
echo.
pause
goto MENU_PRINCIPAL

:QUITTER
cls
color %COLOR_SUCCES%
echo.
echo  ═══════════════════════════════════════════════════════════
echo  ║                     AU REVOIR!                         ║
echo  ═══════════════════════════════════════════════════════════
echo.
timeout /t 2 >nul
exit /b 0