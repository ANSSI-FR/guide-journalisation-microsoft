#requires -version 2
<#
.SYNOPSIS
  Configure les journaux d'événements Windows pour qu'ils puissent être collectés
.DESCRIPTION
  Ce script permet que les événements des journaux Windows soient en capacité d'être transférés à un collecteur
  en donnant le droit au service WinRM d'accéder en lecture aux journaux.
  Il permet aussi d'appliquer les recommandations de l'ANSSI sur les journaux Windows à activer et leurs tailles
  maximales.
  Les changements appliqués sont indiqués dans la section "Configuration de la politique de journalisation" du script.
  Par défaut, les recommandations de base et d'extension sont appliquées.
  Tout changement est réversible.
.PARAMETER -DryRun
  Affiche les changements qui seraient appliqués par le script sans les appliquer
.INPUT
  None
.OUTPUT
  Journalise dans le journal "Application" des événements d'information et d'erreur sur l'exécution du script
  avec comme source "Configure-Channel".

  EventID :
    1  : lancement du script
    2  : fin du script
    3  : information sur un journal
    10 : activation réussie d'un journal
    11 : échec de l'activation d'un journal
    20 : ajout réussie d'une ACE à l'ACL d'un journal
    21 : échec de l'ajout d'une ACE à l'ACL d'un journal
    22 : ACE retirée avec succès de l'ACL d'un journal
    23 : échec pour retirer l'ACE de l'ACL d'un journal
    30 : taille maximale d'un journal changée avec succès
    31 : échec à changer la taille maximale d'un journal
.NOTES
  Version:        1.0
  Author:         ANSSI/SDO/DD/DDS
  Creation Date:  2022/01/03
  Purpose/Change: Initial script development
#>

#-- Get exec mode (dry-run or normal, normal by default)
param ([switch]$dryRun = $false)


############## Configuration de la politique de journalisation ################

#-----------------------------
#  Journalisation de base
#-----------------------------


# Journaux désactivés par défaut à activer
$channels_to_activate_array = @(
    'Microsoft-Windows-CAPI2/Operational'
    'Microsoft-Windows-DriverFrameworks-UserMode/Operational'
    'Microsoft-Windows-LSA/Operational'
    'Microsoft-Windows-TaskScheduler/Operational'
    'Microsoft-IIS-Configuration/Operational'
    'Microsoft-Windows-PrintService/Operational'
    'Microsoft-Windows-Sysmon/Operational'  # DEBUG : to remove
    )

# Augmentation de la  taille maximale des journaux de base.
# La taille est indiquée en octets.
$channels_max_size_hash = @{
  Security      = 1000000000 ; # 1 Go
  Application   = 50000000 ;   # 50 Mo
  Setup         = 50000000 ;   # 50 Mo
  System        = 50000000 ;   # 50 Mo
}


#---------------------------------------------
#  Extension recommandée de la journalisation
#---------------------------------------------

# Paramètres de journalisation additionnels recommandés par l'ANSSI.
#
# - augmentation de la taille maximale de certains journaux additionnels (généralement par défaut à 1 Mo) à 20 Mo.
#
#
# Changements appliqués par défaut. Pour ne pas appliquer ces changements,
# mettre la variable $APPLY_LOGGING_POLICY_EXTENSION à $false
$APPLY_LOGGING_POLICY_EXTENSION = $true


# Noms exacts de journaux dont on veut modifier la taille maximale.
# La taille est indiquée en octets.
$other_channels_max_size_hash = @{
  "Microsoft-Windows-Application-Experience/Program-Inventory" = 20000000; # 20 Mo
  "Microsoft-Windows-Bits-Client/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-CodeIntegrity/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-DeviceGuard/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-DriverFrameworks-UserMode/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-Kernel-PnP/Configuration" = 20000000; # 20 Mo
  "Microsoft-Windows-NetworkProfile/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-NTLM/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-PowerShell/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-PrintService/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-SmartCard-Audit/Authentication" = 20000000; # 20 Mo
  "Microsoft-Windows-SMBClient/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-SMBClient/Security" = 20000000; # 20 Mo
  "Microsoft-Windows-SMBServer/Audit" = 20000000; # 20 Mo
  "Microsoft-Windows-SMBServer/Security" = 20000000; # 20 Mo
  "Microsoft-Windows-TaskScheduler/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-VPN-Client/Operational"= 20000000; # 20 Mo
  "Microsoft-Windows-Wired-AutoConfig/Operational"= 20000000; # 20 Mo
  "Microsoft-Windows-WLAN-AutoConfig/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-Win32k/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" = 20000000; # 20 Mo
  "Microsoft-Windows-WindowsUpdateClient/Operational" = 20000000; # 20 Mo
  "Microsoft-Windows-WMI-Activity/Operational" = 20000000; # 20 Mo
  "Microsoft Office Alerts (OAlerts)" = 20000000; # 20 Mo
  "Windows PowerShell" = 20000000; # 20 Mo
  "Autoruns"= 20000000; # 20 Mo
}

# Modifie la taille maximale des journaux dont le nom contient un de
# ces mots clefs (un mot clef peut contenir un espace).
# Permet ainsi de définir un ensemble de journaux dont on veut modifier
# la taille maximale.
# La taille est indiquée en octets.
$other_channel_keyword_max_size_hash = @{
  "Microsoft-Windows-AppLocker/" = 20000000 ;  # 20 Mo
  "Microsoft-Windows-Authentication/" = 20000000 ;  # 20 Mo
  "Microsoft-Windows-Security-Mitigations/" = 20000000 ; # 20 Mo
  "Microsoft-Windows-TerminalServices" = 20000000 ; # 20 Mo
  "Microsoft-Windows-Windows Defender/" = 20000000 ; # 20 Mo
}

############## INTERNAL CONFIGURATION ################

# script logging
$script_version = "v1.0_20220301"
$event_log = "Application"
$source = "Configure-Channel"

# ACE for giving read access to NT AUTHORITY\WinRM service
$winrm_read_ACE = "(A;;0x1;;;S-1-5-80-569256582-2953403351-2909559716-1301513147-412116970)"

# dry run report variables
$dr_enabled_channels = @()
$dr_max_size_channels = @()
$dr_increase_max_size_channels = 0
$dr_sddl_channels = @()

################### FUNCTIONS ########################

function Log {

    param(
      [int64] $event_id,
      [String] $event_type_str,
      [String] $event_message,
      [Collections.Hashtable] $event_data,
      [Boolean] $isSilent
    )

    try {
      $event_type = [System.Diagnostics.EventLogEntryType] $event_type_str
    }
    catch
    {
      $err_msg = $_
      Write-Output "[ERROR] calling Log function with an unknown event type '$event_type_str'"
      Write-Output "[ERROR] Error message: $err_msg"
      Return
    }

    # build an event messages array with all informations (message + data)
    $event_messages_array = @($event_message)

    $event_messages_array += foreach ($key in $event_data.Keys) {
      '{0}:{1}' -f $key, $event_data.$key
    }

    # write the event
    $id_object = New-Object System.Diagnostics.EventInstance($event_id, $null, $event_type)
    $event_object = New-Object System.Diagnostics.EventLog;
    $event_object.Log = $event_log;
    $event_object.Source = $source;
    $event_object.WriteEvent($id_object,$event_messages_array)

    # write the message on the output
    if ( -not $isSilent ) { Write-Output "[$($event_type.ToString())] $event_message" }
  }

function Log-Channel-Info {
  param(
  $channel # expect a System.Diagnostics.Eventing.Reader.EventLogConfiguration object
  )

  $event_data = @{
    IsEnabled = $channel.IsEnabled;
    IsClassicLog = $channel.IsClassicLog;
    LogName = $channel.LogName;
    LogType = $channel.LogType;
    MaximumSizeInBytes = $channel.MaximumSizeInBytes;
    SecurityDescriptor = $channel.SecurityDescriptor
    IsLogFull = $channel.IsLogFull
    RecordCount = $channel.RecordCount;
  }

  # determine channel retention if there are events in it
  if ($channel.RecordCount -gt 0)
  {
    $oldest_event_date = (Get-WinEvent -LogName $channel.LogName -MaxEvents 1 -Oldest).TimeCreated.ToUniversalTime()
    $newest_event_date = (Get-WinEvent -LogName $channel.LogName -MaxEvents 1).TimeCreated.ToUniversalTime()

    $retention = (New-TimeSpan -Start $oldest_event_date -End $newest_event_date ).TotalSeconds

    $event_data["OldestEventDate"] = $oldest_event_date.ToString("yyyy-MM-ddThh:mm:ssZ")
    $event_data["NewestEventDate"] =  $newest_event_date.ToString("yyyy-MM-ddThh:mm:ssZ")
    $event_data["Retention"] = [int] $retention
  }

  # keep dates only if there are not null
  if ( $null -ne $channel.LastAccessTime ) { $event_data["LastAcessTime"] = $channel.LastAccessTime.ToString("yyyy-MM-ddThh:mm:ssZ") }
  if ( $null -ne $channel.LastWriteTime ) { $event_data["LastWriteTime"] = $channel.LastWriteTime.ToString("yyyy-MM-ddThh:mm:ssZ") }

  # convert isEnabled boolean to string for reporting
  $change_type = If ($channel.IsEnabled) {"enabled"} Else {"disabled"}

  $event_message = "Channel '$($channel.LogName)' is $change_type and as the following SDDL : $($channel.SecurityDescriptor)"

  Log 3 Information $event_message $event_data $true
}

function Set-Enabled-Channel {

  param(
    $channel,  # expect a System.Diagnostics.Eventing.Reader.EventLogConfiguration object
    [Boolean] $state,
    [Boolean] $isDryRun
  )

  $current_state = $channel.IsEnabled

  # do nothing if the channel is already in the desired state
  If ($current_state -eq $state) { Return }

  # convert state to string for reporting
  $change_type = If ($state) {"enable"} Else {"disable"}

  # DryRun : update reporting values then exit
  If( $isDryRun )
  {
    $script:dr_enabled_channels += "$($channel.LogName) has been $($change_type)d"
    Return
  }

  $channel.IsEnabled = $state

  # Apply and log status change
  try
    {
      $channel.SaveChanges()
      
      $event_message = "Channel '$($channel.LogName)' has been $($change_type)d"
      $event_data = @{ LogName = $channel.LogName; Status = $change_type }

      Log 10 Information $event_message $event_data
    }
    catch
    {
      $err_msg = $_

      $event_message = "failure to $change_type channel '$($channel.LogName)' : $err_msg"
      $event_data = @{ LogName = $channel.LogName; Status = $current_state; WantedStatus = $change_type; Err_message = $err_msg }

      Log 11 Error $event_message $event_data
    }

}

function Add-ACE-ToChannel {

  param(
    $channel,  # expect a System.Diagnostics.Eventing.Reader.EventLogConfiguration object
    [String] $ACE,
    [Boolean] $isDryRun
  )

  # some SDDL contain an SACL (System Access Control List) at the end, in addition to the DACL.
  # we need to find the index of the beginning of the DACL.

  $dacl_head = "SYD:"
  $channel_dacl_index = $channel.SecurityDescriptor.IndexOf($dacl_head)
  $channel_dacl_first_entry_index = $channel_dacl_index + $dacl_head.Length

  # add our ACE at the beginning of the DACL
  $current_sddl = $channel.SecurityDescriptor
  $new_sddl = $channel.SecurityDescriptor.Insert($channel_dacl_first_entry_index, $ACE)

  # Dry run : update reporting values and exit
  if ( $isDryRun )
  {
    $script:dr_sddl_channels += "ACE $ACE add to channel '$($channel.LogName)'"
    Return
  }

  $channel.SecurityDescriptor = $new_sddl

  # save the change
  try
  {
    $channel.SaveChanges()

    $event_message = "ACE '$ACE' added to '$($channel.LogName)' channel SDDL"
    $event_data = @{LogName = $channel.LogName; ACE = $ACE; sddl = $current_sddl.ToString(); new_sddl = $new_sddl.ToString()}

    Log 20 Information $event_message $event_data
  }
  catch
  {
    $err_msg = $_
    $event_message = "Failure to add ACE '$ACE' to '$($channel.LogName)' channel SDDL"
    $event_data = @{LogName = $channel.LogName; ACE = $ACE; sddl = $current_sddl.ToString(); Err_message = $err_msg }

    Log 21 Error $event_message $event_data
  }

}

function Remove-ACE-ToChannel{

  param(
    $channel,  # expect a System.Diagnostics.Eventing.Reader.EventLogConfiguration object
    [string] $ACE,
    [boolean] $isDryRun
  )

  # build the new SDDL
  $ACE_index = $channel.SecurityDescriptor.IndexOf($ACE)
  If ( $ACE_index -lt 0 ) { Return } # ACE not found in the SDDL, exit function
  $new_sddl = $channel.SecurityDescriptor.Remove($ACE_index, $ACE.Length)

  # update the SDDL
  $old_sddl = $channel.SecurityDescriptor

  # Dry run : update reporting values then exit
  if ($isDryRun)
  {
    $script:dr_sddl_channels += "ACE $ACE removed from channel '$($channel.LogName)'"
    Return
  }

  $channel.SecurityDescriptor = $new_sddl

  try
  {
    $channel.SaveChanges()

    $event_message = "ACE '$ACE' removed from '$($channel.LogName)' channel SDDL"
    $event_data = @{LogName = $channel.LogName; ACE = $ACE; SDDL = $old_sddl.ToString(); NewSDDL = $new_sddl.ToString()}

    Log 22 Information $event_message $event_data
  }
  catch
  {
    $err_msg = $_

    $event_message = "failure to remove the '$ACE' ACE from '$($channel.LogName)' channel SDDL : $err_msg"
    $event_data = @{LogName = $channel.LogName; ACE = $ACE;  SDDL = $old_sddl.ToString();  Err_message = $err_msg}

    Log 23 Error $event_message $event_data
  }
}

function Change-Channel-MaxSize{

  param(
    $channel,  # expect a System.Diagnostics.Eventing.Reader.EventLogConfiguration object
    [Int64] $new_max_size,
    [Boolean] $isDryRun
  )

  $current_max_size = $channel.MaximumSizeInBytes

  $diff_size = $new_max_size - $current_max_size

  # do nothing if the max size is already what we want
  If ( $diff_size -eq 0 ) { Return }

  # DryRun : update reporting values then exit
  If ( $isDryRun )
  {
    $script:dr_max_size_channels += "Change '$($channel.LogName)' max size from $current_max_size to $new_max_size bytes"
    $script:dr_increase_max_size_channels += $diff_size
    Return
  }

  $channel.MaximumSizeInBytes = $new_max_size

  # Apply and log status change
  try
  {
    $channel.SaveChanges()

    $event_message = "Channel '$($channel.LogName)' max size changed to $new_max_size bytes"
    $event_data = @{LogName = $channel.LogName; current_max_size = $current_max_size; new_max_size = $new_max_size}

    Log 30 Information $event_message $event_data
  }
  catch
  {
    $err_msg = $_

    $event_message = "Failure to change channel '$($channel.LogName)' max size"
    $event_data = @{LogName = $channel.LogName; current_max_size = $current_max_size; new_max_size = $new_max_size; Err_msg = $err_msg }

    Log 31 Error $event_message $event_data
  }

}

function bytes_to_hr_str {
  param([Int64]$bytecount)

  switch -Regex ([math]::truncate([math]::log($bytecount,1024))) {

    '^0' { $output_str = "$bytecount Bytes"}

    '^1' { $output_str = "{0:n2} KB" -f ($bytecount / 1KB)}

    '^2' { $output_str = "{0:n2} MB" -f ($bytecount / 1MB)}

    Default { $output_str = "{0:n2} GB" -f ($bytecount / 1GB)}
  }
  
  return $output_str
}


################### MAIN ########################


#-- Initialize logging for the script

# Load the event source if not already loaded. This will fail if the event source is already assigned to a different log.
If ([System.Diagnostics.EventLog]::SourceExists($source) -eq $false)
{
    [System.Diagnostics.EventLog]::CreateEventSource($source, $event_log)
}

$script_start_time = Get-Date
If ( -not $dryRun ) { Log 1 Information "Script Configure-Channel.ps1 version $script_version launched" @{ ScriptVersion = $script_version } }

#-- Process all existing event log channels

$event_log_channel_array = Get-WinEvent -ListLog * -ErrorAction Stop 

foreach ($event_log_channel in $event_log_channel_array)
{
  $log_name = $event_log_channel.LogName

  If ( -not $dryRun ) { Log-Channel-Info $event_log_channel }

  #----------------------
  # Base Logging Policy 
  #----------------------

  # Enables channels we want which are not by default
  If( ($channels_to_activate_array -Contains $log_name) -and -not $event_log_channel.IsEnabled )
  {
    Set-Enabled-Channel $event_log_channel $true $dryRun
  }

  # Add read permission for NT  SERVICE\WinRM on event log channel if needed
  If( -not ($event_log_channel.SecurityDescriptor | Select-String -Pattern $winrm_read_ACE -Quiet -SimpleMatch) )
  {
    Add-ACE-ToChannel $event_log_channel $winrm_read_ACE $dryRun
  }


  # Change channel max size if needed
  If ( $null -ne $channels_max_size_hash[$log_name] )
  {
    Change-Channel-MaxSize $event_log_channel $channels_max_size_hash[$log_name] $dryRun
  }

  #--------------------------
  # Extended Logging Policy
  #--------------------------

  If ($APPLY_LOGGING_POLICY_EXTENSION )
  {
    # check if we want to increase this particular channel max size
    If ( $null -ne $other_channels_max_size_hash[$log_name] )
    {
      Change-Channel-MaxSize $event_log_channel $other_channels_max_size_hash[$log_name] $dryRun
    }

    # increase channel max size if it's name match one of these keywords
    foreach ($key in $other_channel_keyword_max_size_hash.Keys)
    {
      If ($log_name | Select-String -Pattern $key -SimpleMatch -Quiet)
      {
        Change-Channel-MaxSize $event_log_channel $other_channel_keyword_max_size_hash[$key] $dryRun
      }
    }
  }

}

# Print change report only if we are in dry-run mode
If ( -not $dryRun ){
  $script_end_time = Get-Date
  $script_duration = (New-TimeSpan -Start $script_start_time -End $script_end_time ).TotalSeconds
  Log 2 Information "Script Configure-Channel.ps1 version $script_version ended" @{ ScriptVersion = $script_version; ScriptDuration = $script_duration }
  Exit
  }


Write-Output "Channel state changed :"

foreach ($channel_info in $dr_enabled_channels)
{
  Write-Output "  - $channel_info"
}

Write-Output "`nChannel max size changed :"

foreach ($channel_info in $dr_max_size_channels)
{
  Write-Output "  - $channel_info"
}

$dr_increase_max_size_channels_str = bytes_to_hr_str $dr_increase_max_size_channels

Write-Output "`nTotal log size increase : $dr_increase_max_size_channels_str"

Write-Output "`nChannel SDDL changed :"

foreach ($channel_info in $dr_sddl_channels)
{
  Write-Output "  - $channel_info"
}
