import streamlit as st
import subprocess
import sys
import json

def run_script(command):
    result = subprocess.run([sys.executable, 'WikiNess.py'] + command, capture_output=True, text=True)
    lines = result.stdout.split('\n')
    json_lines = [line for line in lines if line.strip().startswith('{') or line.strip().startswith('[')]
    json_output = ''.join(json_lines)
    if json_output:
        try:
            return json.loads(json_output)
        except json.JSONDecodeError:
            return {"error": "Erreur de décodage JSON après filtrage: " + json_output}
    elif result.stderr:
        return {"error": "Erreur d'exécution: " + result.stderr}
    return {"error": "Aucune donnée reçue, vérifiez les logs pour plus de détails."}


# Configuration de la page
st.set_page_config(page_title="WikiNess", page_icon="./WikiNess.png")
st.title('WIKINESS')

# Section de recherche par nom CPE
st.header("Recherche par nom de CPE")
with st.form(key='cpe_form'):
    part = st.text_input("part")
    vendor = st.text_input("vendor")
    product = st.text_input("product")
    version = st.text_input("version", value="*")
    update = st.text_input("update", value="*")
    edition = st.text_input("edition", value="*")
    language = st.text_input("language", value="*")
    software_edition = st.text_input("software_edition", value="*")
    target_software = st.text_input("target_software", value="*")
    target_hardware = st.text_input("target_hardware", value="*")
    other = st.text_input("other", value="*")
    submit_cpe = st.form_submit_button("Recherche par CPE")
    
    if submit_cpe:
        command = ['--cpe', part, vendor, product, version, update, edition, language, software_edition, target_software, target_hardware, other]
        results = run_script(command)
        if "error" not in results:
            # Affiche les CVEs, Exploits et Patches
            st.subheader("Résultats pour CPE:")
            st.write("CVEs trouvées:")
            st.write(results.get('cves', "Pas de CVEs trouvées"))
            st.write("Exploits disponibles:")
            st.write(results.get('exploits', "Pas d'exploits trouvés"))
            st.write("Patches disponibles:")
            st.write(results.get('patches', "Pas de patches trouvés"))
        else:
            st.error(results["error"])

# Section de recherche par ID CVE
st.header("Recherche par ID de CVE")
cve_id = st.text_input("CVE ID")
if st.button("Recherche par CVE ID"):
    output = run_script(['--cve_id', cve_id])
    if "error" not in output:
        st.text_area("Résultat", output.get('cves', "Pas de CVEs trouvées"), height=100)
    else:
        st.error(output["error"])

# Section pour CVSS
st.header("Paramètres CVSS")
av = st.selectbox("Attack Vector", ["Physical", "Local", "Adjacent network", "Network"])
ac = st.selectbox("Attack Complexity", ["Low", "High"])
pr = st.selectbox("Privileges Required", ["None", "Low", "High"])
ui = st.selectbox("User Interaction", ["None", "Required"])
s = st.selectbox("Scope", ["Unchanged", "Changed"])
c = st.selectbox("Confidentiality", ["None", "Low", "High"])
i = st.selectbox("Integrity", ["None", "Low", "High"])
a = st.selectbox("Availability", ["None", "Low", "High"])
if st.button("Recherche par CVSS"):
    cvss_command = ['--cvss_v3', av, ac, pr, ui, s, c, i, a]
    output = run_script(cvss_command)
    if "error" not in output:
        st.text_area("Résultat", output.get('cves', "Pas de CVEs trouvées"), height=300)
    else:
        st.error(output["error"])