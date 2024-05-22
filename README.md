# WikiNess

WikiNess est un script Python qui permet de récupérer des informations sur les vulnérabilités à partir de la base de données NVD (National Vulnerability Database) en utilisant différents critères de recherche.

## Installation

```powershell
pip.exe install requirements.txt
```

Pour utiliser WikiNess, vous devez avoir Python 3.x installé sur votre système. Vous pouvez ensuite télécharger le script depuis le dépôt GitHub et l'exécuter à l'aide de la commande `python WikiNess.py`.

## Fonctionnalités

WikiNess offre les fonctionnalités suivantes :

### Recherche par nom CPE

Vous pouvez rechercher des CVEs associées à un nom CPE donné en utilisant les options `--part`, `--vendor`, `--product`, `--version`, `--update`, `--edition`, `--language`, `--software_edition`, `--target_software`, `--target_hardware` et `--other`. Le nom CPE est une chaîne de caractères qui identifie de manière unique un produit, un logiciel ou un matériel.

Exemple :
```powershell
python.exe WikiNess.py --part a --vendor microsoft --product internet_explorer --version 11.0.9600.18537
```
Cet exemple recherche les CVEs associées à Internet Explorer 11.0.9600.18537.

### Recherche par métriques CVSS v2

Vous pouvez rechercher des CVEs qui correspondent aux métriques CVSS v2 données en utilisant la commande `cvss-v2` et les options `-av`, `-ac`, `-au`, `-c`, `-i` et `-a`. Les métriques CVSS v2 sont des valeurs qui mesurent la sévérité d'une vulnérabilité.

Exemple :
```powershell
python.exe WikiNess.py cvss-v2 -av N -ac L -au N -c P -i P -a N
```
Cet exemple recherche les CVEs qui correspondent aux métriques CVSS v2 "AV:N/AC:L/Au:N/C:P/I:P/A:N".

### Recherche par métriques CVSS v3

Vous pouvez rechercher des CVEs qui correspondent aux métriques CVSS v3 données en utilisant la commande `cvss-v3` et les options `-av`, `-ac`, `-pr`, `-ui`, `-s`, `-c`, `-i` et `-a`. Les métriques CVSS v3 sont des valeurs qui mesurent la sévérité d'une vulnérabilité.

Exemple :
```powershell
python.exe WikiNess.py cvss-v3 -av N -ac L -pr N -ui R -s U -c H -i H -a H
```
Cet exemple recherche les CVEs qui correspondent aux métriques CVSS v3 "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H".

### Recherche par identifiant CVE

Vous pouvez rechercher des informations sur une vulnérabilité spécifique en utilisant l'option `--cve-id`.

Exemple :
```powershell
python.exe WikiNess.py --cve-id CVE-2019-1010218
```
Cet exemple recherche des informations sur la vulnérabilité avec l'identifiant CVE-2019-1010218.
