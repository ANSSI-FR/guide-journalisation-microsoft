# Ce script est un exemple qu'il peut être nécessaire d'adapter

# Ici, renseigner le partage contenant Sysmon :
$SysmonShare = "\\ad.LAN\SYSVOL\ad.lan\TOOLS\Sysmon"
# Ici, préciser une source pour les journaux générés par le script
$LogSource = "ANSSI.Sysmon"
# Ici, préciser un EventId de départ pour les évènements journalisés
$LogEventId = 64210

# Initialisation de la journalisation
New-EventLog -LogName System -Source $LogSource -ErrorAction SilentlyContinue
Write-EventLog -LogName System -Source $LogSource -EntryType Information -Message "Running Sysmon Service Deployment Script" `
  -EventId $LogEventId
# Si un service Sysmon est déjà installé
$RegKey = "Registry::HKLM\SYSTEM\CurrentControlSet\Services\Sysmon"
# Si l'option -d a été utilisée à l'installation de sysmon pour renommer le pilote, modifier la clé de registre ci-dessus
$RegKey64ImagePath = (Get-ItemProperty -Path ($RegKey + "64") -Name ImagePath).ImagePath
$RegKey32ImagePath = (Get-ItemProperty -Path $RegKey -Name ImagePath).ImagePath
$SysmonShareVersion = (get-Item ($SysmonShare + "\Sysmon.exe")).VersionInfo.FileVersion
if ($RegKey64ImagePath)
{
    # Si Sysmon est déjà à jour, l'exécution du script se termine
    # Si cela arrive, c'est que le filtre WMI de la GPP n'est pas bon car ce script n'aurait pas dû s'exécuter
    $SysmonLocalVersion = (Get-Item ($RegKey64ImagePath)).VersionInfo.FileVersion
    if ($SysmonShareVersion -eq $SysmonLocalVersion){
        Write-EventLog -LogName System -Source $LogSource -EntryType Error -Message "Sysmon64 is already up to date" `
           -EventId ($LogEventId + 1)
        exit
    }

    # Obtention du nom de pilote
    $RegKey64DriverName = (Get-ItemProperty -Path ($RegKey + "64\Parameters") -Name DriverName).DriverName

    # Désinstallation
    $UninstallOutput = & $RegKey64ImagePath -u force 2>&1
    # (NB : Si le format de sortie de Sysmon change, l'argument match ci-dessous doit être changé en conséquence)
    if (($UninstallOutput -match ('.*(' + $RegKey64DriverName + ' removed\.|Sysmon64 removed\.)')).count -eq 2)
    {
        Remove-Item $RegKey64ImagePath
        Write-EventLog -LogName System -Source $LogSource -EntryType Information -Message ("Sysmon64 v" + $SysmonLocalVersion `
            + " has been uninstalled successfully") -EventId ($LogEventId + 2)
    }
    else
    {
        Write-EventLog -LogName System -Source $LogSource -EntryType Error -Message ("Sysmon64 v" + $SysmonLocalVersion `
            + " uninstall failed") -EventId ($LogEventId + 3)
        exit 1
    }
}
elseif ($RegKey32ImagePath)
{
    # Si Sysmon est déjà à jour l'exécution du script se termine
    # Si cela arrive, c'est que le filtre WMI de la GPP n'est pas bon car ce script n'aurait pas dû s'exécuter
    $SysmonLocalVersion = (Get-Item ($RegKey32ImagePath)).VersionInfo.FileVersion
    if ($SysmonShareVersion -eq $SysmonLocalVersion){
        Write-EventLog -LogName System -Source $LogSource -EntryType Error -Message "Sysmon is already up to date" `
            -EventId ($LogEventId + 1)
        exit
    }

    # Obtention du nom de pilote
    $RegKey32DriverName = (Get-ItemProperty -Path ($RegKey + "\Parameters") -Name DriverName).DriverName

    # Désinstallation
    $UninstallOutput = & $RegKey32ImagePath -u force 2>&1
    # (NB : Si le format de sortie de Sysmon change, l'argument match ci-dessous doit être changé en conséquence)
    if (($UninstallOutput -match ('.*(' + $RegKey32DriverName + ' removed\.|Sysmon removed\.)')).count -eq 2)
    {
        Remove-Item $RegKey32ImagePath
        Write-EventLog -LogName System -Source $LogSource -EntryType Information -Message ("Sysmon v" + $SysmonLocalVersion `
            + " has been uninstalled successfully") -EventId ($LogEventId + 2)
    }
    else
    {
        Write-EventLog -LogName System -Source $LogSource -EntryType Error -Message ("Sysmon v" + $SysmonLocalVersion `
            + " uninstall failed") -EventId ($LogEventId + 3)
        exit 1
    }
}
# Installation du Sysmon à jour, sans configuration spécifiée (car appliquée ensuite par GPP de registre)
$if64 = if($env:PROCESSOR_ARCHITECTURE -like "*64*"){"64"}else{""}
$SysmonPath = $SysmonShare + "\Sysmon" + $if64 + ".exe"
$InstallOutput = & $SysmonPath -accepteula -i 2>&1
# (NB : Si le format de sortie de Sysmon change, l'argument match ci-dessous doit être changé en conséquence)
if (($InstallOutput -match '.*(installed\.|started\.)').count -eq 4)
{
    Write-EventLog -LogName System -Source $LogSource -EntryType Information -Message ("Sysmon" + $if64 + " v" `
        + $SysmonShareVersion + " has been installed successfully") -EventId ($LogEventId + 4)
}
else
{
    Write-EventLog -LogName System -Source $LogSource -EntryType Error -Message ("Sysmon" + $if64 + " v" `
        + $SysmonShareVersion + " install failed") -EventId ($LogEventId + 5)
}
# Application des GPO (pour mise à jour, dans la foulée, de la configuration de Sysmon par GPP de registre)
& gpupdate /target:computer
