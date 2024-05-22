import json
import requests
import argparse
from colorama import Fore, Style

def print_logo():
    print('                                                                                          ')
    print('                                                                                          ')
    print('                                          .::.                                            ')
    print('                                  .:-=+*########*+=-:.                                    ')
    print('                          .:-=+*########################*+=-:.                            ')
    print('                  .:-=+*########################################*+=-:.                    ')
    print('          .:-=+*###########################*++*#########################*+=-:.            ')
    print('         -#########################********+------==++*#######################    :--     ')
    print('         -#################****************+--------------==++*###############    *##     ')
    print('         -#########************************+----------------------==++*#######            ')
    print('         -#######**************************+---------------------------#######    -==     ')
    print('         -#######**************************+---------------------------#######    *##     ')
    print('         -#######**********************#####***++==--------------------#######    *##     ')
    print('         -#######*****************##################*+=----------------#######    *##     ')
    print('         -#######**************#############***#########+=-------------#######    *##     ')
    print('         -#######************########******+-----=+*######*=-----------#######    *##     ')
    print('         -#######**********#######*********+---------=*#####*----------#######    *##     ')
    print('         -#######*********######***********+------+*---=*#####=--------#######    *##     ')
    print('         :#######********#####*************+-----=#+-----=#####--------#######    *##     ')
    print('         :#######*******#####**************+------+-------=####*------=#######    *##     ')
    print('         .#######******#####***************+-----=---------+####=-----=######*    ###     ')
    print('          #######******#####***************+----------------####*-----+######+    ##*     ')
    print('          +######*+++++####*++++++++++++++++================#####=====#######-   :##=     ')
    print('          -#######-----####+----------------****************#####*****#######    =##.     ')
    print('           #######+----####*----------------****************#####****#######=             ')
    print('           -#######----+####=---------------***************#####*****#######.             ')
    print('      .:    *######*----#####=--------------**************######****#######=              ')
    print('     +##:   .#######+----#####+-------------*************######****#######*               ')
    print('      .      -#######=----*#####=-----------***********#######****########.               ')
    print('       +#+    =#######=----+######+---------*********########****########:                ')
    print('       -##=    +#######+-----+#######*+==---*****##############*########:                 ')
    print('        +##=    +#######*------+*#######################**#############:                  ')
    print('         +##=    =########=-------=+*################*******##########:                   ')
    print('          =##+    :########+------------===+****************#########.                    ')
    print('           -##*.   .*########=--------------**************############=                   ')
    print('            :###:    -#########=------------************#########**#####-                 ')
    print('              +##+     +#########+----------**********##########-  :*#####-               ')
    print('               :###-    .+#########*=-------********##########=      :*####*              ')
    print('                 =##*:    .+##########+=----*****###########=          :+#*:              ')
    print('                  .*##*:    .=###########*==*############*-                               ')
    print('                    :*##*:     -*######################+.                                 ')
    print('                      .+###-      -*################+:                                    ')
    print('                         =###+:      :+#########*=:                                       ')
    print('                           :+*.         .-+**=:                                           ')
    print('                                                                                          ')
    print('                                                                                          ')

def get_cve_by_cpe(part, vendor, product, version='*', update='*', edition='*', language='*', software_edition='*', target_software='*', target_hardware='*', other='*'):
    cpe_name = f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{software_edition}:{target_software}:{target_hardware}:{other}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Received status code {response.status_code}")
        return None

def get_cve_by_cvss_v2_metrics(av, ac, au, c, i, a):
    cvss_v2_metrics = f"AV:{av}/AC:{ac}/Au:{au}/C:{c}/I:{i}/A:{a}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV2Metrics={cvss_v2_metrics}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Received status code {response.status_code}")
        return None

def get_cve_by_cvss_v3_metrics(av, ac, pr, ui, s, c, i, a):
    cvss_v3_metrics = f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Metrics={cvss_v3_metrics}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Received status code {response.status_code}")
        return None

def get_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Received status code {response.status_code}")
        return None

def get_cve_data(cve_json, query_type):
    if query_type == 'cve_id':
        if cve_json and 'cveChanges' in cve_json:
            cve_changes = cve_json['cveChanges']
            return cve_changes
    else:
        if cve_json and 'vulnerabilities' in cve_json:
            vulnerabilities = cve_json['vulnerabilities']
            return vulnerabilities
    return None

def extract_cve_info(vulnerabilities):
    cves = []
    exploits = []
    patches = []
    for vulnerability in vulnerabilities:
        if 'change' in vulnerability:
            cve_id = vulnerability['change']['cveId']
            details = vulnerability['change']['details']
            cves.append(cve_id)
            for detail in details:
                new_value = detail.get('newValue', '').lower()
                old_value = detail.get('oldValue', '').lower()
                if 'exploit' in new_value or 'exploit' in old_value:
                    exploits.append(new_value or old_value)
                elif 'patch' in new_value or 'patch' in old_value:
                    patches.append(new_value or old_value)
        elif 'cve' in vulnerability:
            cve_id = vulnerability['cve']['id']
            cves.append(cve_id)
            for ref in vulnerability['cve'].get('references', []):
                if 'tags' in ref and 'exploit' in ref['tags']:
                    exploits.append(ref['url'])
                elif 'tags' in ref and 'patch' in ref['tags']:
                    patches.append(ref['url'])
    return cves, exploits, patches

def format_list(items):
    return '\n'.join(items)

def generate_report(cves, exploits, patches, filename='rapport.md'):
    with open(filename, 'w') as file:
        file.write("# Rapport de CVEs\n\n")

        file.write("## CVEs\n")
        if cves:
            for cve in cves:
                file.write(f"{cve}\n")
        else:
            file.write("Pas de CVEs trouvées\n")

        file.write("\n## Exploits\n")
        if exploits:
            for exploit in exploits:
                file.write(f"({exploit})\n")
        else:
            file.write("Pas d'exploits trouvés\n")

        file.write("\n## Patches\n")
        if patches:
            for patch in patches:
                file.write(f"({patch})\n")
        else:
            file.write("Pas de patches trouvés\n")

def main():
    parser = argparse.ArgumentParser(
        description="Recherche des CVEs à partir de différents critères. Vous pouvez rechercher des CVEs par nom CPE, par métriques CVSS v2, par métriques CVSS v3 ou par identifiant CVE."
    )

    parser.add_argument(
        '--cpe',
        nargs='+',
        metavar='CPE_ARGS',
        help=(
            "Recherche par nom CPE. Fournir au moins 'part', 'vendor', et 'product'. Les autres champs sont optionnels et seront remplis par défaut avec '*'. "
            "Format : part vendor product [version update edition language software_edition target_software target_hardware other]\n"
            "Exemple : --cpe o microsoft windows_10 22h2"
        )
    )

    parser.add_argument(
        '--cvss_v2',
        nargs=6,
        metavar=('av', 'ac', 'au', 'c', 'i', 'a'),
        help=(
            "Recherche par métriques CVSS v2. Fournir les valeurs pour les métriques dans l'ordre : AV AC Au C I A.\n"
            "Options pour AV (Access Vector) : N (Network), A (Adjacent Network), L (Local)\n"
            "Options pour AC (Access Complexity) : H (High), M (Medium), L (Low)\n"
            "Options pour Au (Authentication) : M (Multiple), S (Single), N (None)\n"
            "Options pour C (Confidentiality Impact) : N (None), P (Partial), C (Complete)\n"
            "Options pour I (Integrity Impact) : N (None), P (Partial), C (Complete)\n"
            "Options pour A (Availability Impact) : N (None), P (Partial), C (Complete)\n"
            "Exemple : --cvss_v2 N H N C C C"
        )
    )

    parser.add_argument(
        '--cvss_v3',
        nargs=8,
        metavar=('av', 'ac', 'pr', 'ui', 's', 'c', 'i', 'a'),
        help=(
            "Recherche par métriques CVSS v3. Fournir les valeurs pour les métriques dans l'ordre : AV AC PR UI S C I A.\n"
            "Options pour AV (Attack Vector) : N (Network), A (Adjacent), L (Local), P (Physical)\n"
            "Options pour AC (Attack Complexity) : L (Low), H (High)\n"
            "Options pour PR (Privileges Required) : N (None), L (Low), H (High)\n"
            "Options pour UI (User Interaction) : N (None), R (Required)\n"
            "Options pour S (Scope) : U (Unchanged), C (Changed)\n"
            "Options pour C (Confidentiality Impact) : N (None), L (Low), H (High)\n"
            "Options pour I (Integrity Impact) : N (None), L (Low), H (High)\n"
            "Options pour A (Availability Impact) : N (None), L (Low), H (High)\n"
            "Exemple : --cvss_v3 N L N N U L L L"
        )
    )

    parser.add_argument(
        '--cve_id',
        type=str,
        help="Recherche par identifiant CVE. Fournir l'identifiant complet du CVE.\nExemple : --cve_id CVE-2023-50564"
    )

    args = parser.parse_args()

    if args.cpe:
        if len(args.cpe) < 3:
            print("Erreur: Il faut qu'au moins 'part', 'vendor', et 'product' soient spécifiés pour CPE.")
            return
        while len(args.cpe) < 11:
            args.cpe.append('*')
        part, vendor, product, version, update, edition, language, software_edition, target_software, target_hardware, other = args.cpe
        cve_data = get_cve_by_cpe(part, vendor, product, version, update, edition, language, software_edition, target_software, target_hardware, other)
        data = get_cve_data(cve_data, 'cpe')
        if data is not None:
            cves, exploits, patches = extract_cve_info(data)
            print("CVEs:")
            if cves:
                print(Fore.RED + format_list(cves) + Style.RESET_ALL)
            else:
                print("Pas de CVEs trouvées")
            print("Exploits:")
            if exploits:
                print(Fore.YELLOW + format_list(exploits) + Style.RESET_ALL)
            else:
                print("Pas exploits trouvés")
            print("Patches:")
            if patches:
                print(Fore.GREEN + format_list(patches) + Style.RESET_ALL)
            else:
                print("Pas de patches trouvés")
            generate_report(cves, exploits, patches)

    elif args.cvss_v2:
        cve_data = get_cve_by_cvss_v2_metrics(*args.cvss_v2)
        data = get_cve_data(cve_data, 'cvss_v2')
        if data is not None:
            cves, exploits, patches = extract_cve_info(data)
            print("CVEs:")
            if cves:
                print(Fore.RED + format_list(cves) + Style.RESET_ALL)
            else:
                print("Pas de CVEs trouvées")
            print("Exploits:")
            if exploits:
                print(Fore.YELLOW + format_list(exploits) + Style.RESET_ALL)
            else:
                print("Pas exploits trouvés")
            print("Patches:")
            if patches:
                print(Fore.GREEN + format_list(patches) + Style.RESET_ALL)
            else:
                print("Pas de patches trouvés")
            generate_report(cves, exploits, patches)

    elif args.cvss_v3:
        cve_data = get_cve_by_cvss_v3_metrics(*args.cvss_v3)
        data = get_cve_data(cve_data, 'cvss_v3')
        if data is not None:
            cves, exploits, patches = extract_cve_info(data)
            print("CVEs:")
            if cves:
                print(Fore.RED + format_list(cves) + Style.RESET_ALL)
            else:
                print("Pas de CVEs trouvées")
            print("Exploits:")
            if exploits:
                print(Fore.YELLOW + format_list(exploits) + Style.RESET_ALL)
            else:
                print("Pas exploits trouvés")
            print("Patches:")
            if patches:
                print(Fore.GREEN + format_list(patches) + Style.RESET_ALL)
            else:
                print("Pas de patches trouvés")
            generate_report(cves, exploits, patches)

    elif args.cve_id:
        cve_data = get_cve_details(args.cve_id)
        data = get_cve_data(cve_data, 'cve_id')
        if data is not None:
            cves, exploits, patches = extract_cve_info(data)
            print("CVEs:")
            if cves:
                print(Fore.RED + format_list(cves) + Style.RESET_ALL)
            else:
                print("Pas de CVEs trouvées")
            print("Exploits:")
            if exploits:
                print(Fore.YELLOW + format_list(exploits) + Style.RESET_ALL)
            else:
                print("Pas exploits trouvés")
            print("Patches:")
            if patches:
                print(Fore.GREEN + format_list(patches) + Style.RESET_ALL)
            else:
                print("Pas de patches trouvés")
            generate_report(cves, exploits, patches)

    elif not any(vars(args).values()):
        parser.print_help()

if __name__ == "__main__":
    print_logo()
    main()
