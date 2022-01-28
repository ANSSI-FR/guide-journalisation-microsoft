 # Ce script est un exemple qui doit être adapté avant toute mise en production
 
 # Lister les plugins
$Plugins = dir WSMAN:\localhost\Plugin\
# Pour chaque plugin, sauf le "Event Forwarding Plugin"
# ATTENTION : Si d'autres plugins sont utilisés en production, il convient d'ajouter une condition les autorisant
foreach ($Plugin in $Plugins.Name){
  if ($Plugin -ne "Event Forwarding Plugin"){
    # Désactivation du plugin
    set-item "WSMAN:\localhost\Plugin\$Plugin\enabled" -value False
  }
}
# Redémarrage du service WinRM
Restart-Service winrm

# Affichage du SDDL de chaque plugin (pour information seulement)
# Lister les plugins
$Plugins = dir WSMAN:\localhost\Plugin\
# Pour chaque plugin
foreach ($Plugin in $Plugins.Name){
  Write-Host "Plugin $Plugin :"
  $Resources = (dir "WSMAN:\localhost\Plugin\$Plugin\Resources").PSPath
  # Pour chaque ressource du plugin
  foreach ($Resource in $Resources){
    Write-Host "`tResource Uri = " (Get-Item ("$Resource\ResourceUri")).value
    $Security = (dir ($Resource + "\Security")).PSPath
    Write-Host "`tSDDL = " $(dir ($Security + "\sddl")).value
    }
}
