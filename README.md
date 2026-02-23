# Guide journalisation Microsoft

<img src="https://www.sgdsn.gouv.fr/files/styles/ds_image_paragraphe/public/files/Notre_Organisation/logo_anssi.png" alt="Logo ANSSI" width="30%">

## Agence nationale de la sécurité des systèmes d'information

![badge_repo](https://img.shields.io/badge/ANSSI--FR-guide--journalisation--microsoft-white)
[![badge_catégorie_doctrinal](https://img.shields.io/badge/catégorie-doctrinal-%23e9c7e7)](https://github.com/ANSSI-FR#types-de-projets)
[![badge_ouverture_B](https://img.shields.io/badge/code.gouv.fr-ouvert-green)](https://documentation.ouvert.numerique.gouv.fr/les-parcours-de-documentation/ouvrir-un-projet-num%C3%A9rique/#niveau-ouverture)

*Ce projet est géré par l'[ANSSI](https://cyber.gouv.fr/). Pour en savoir plus, voir la [page dédiée à la stratégie open source de l'ANSSI](https://cyber.gouv.fr/open-source-lanssi). Vous pouvez également cliquer sur les badges pour en savoir plus sur leur signification.*

Ce dépôt met à disposition le contenu technique pointé par le guide  guide ANSSI [Sécuriser la 
journalisation dans un environnement Microsoft Active 
Directory](https://messervices.cyber.gouv.fr/guides/securiser-la-journalisation-dans-un-environnement-microsoft-active-directory).

> [!WARNING]
> Plusieurs problèmes ont été identifiés sur la collecte des journaux systèmes Windows, vraisemblablement liés à la migration de serveurs WEC vers Windows Server 2025.
> Ces différents problèmes, qui peuvent dégrader voire interrompre la collecte des journaux et donc la supervision, sont en cours d’instruction et ont été remontés au support Microsoft.
> 
> Par mesure de précaution et pour éviter d’impacter la supervision système en place, il est conseillé d’éviter la migration des serveurs WEC vers Windows Server 2025, le temps que la situation soit clarifiée et que des solutions aient été trouvées.
> La version Windows Server 2022 est encore supportée par l’éditeur et les serveurs WEC ne souffrent, à notre connaissance, d’aucun problème fonctionnel sur cette version.
