import subprocess
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template

app = Flask(__name__)

def parse_nmap_xml(xml_output):
    """Parse Nmap XML output and return a structured dictionary for templating."""
    data = {
        "host_state": None,
        "ip_address": None,
        "hostnames": [],
        "os_guess": None,
        "open_ports": [],
        "host_scripts": [],
        "port_scripts": []
    }

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        data["error"] = "Failed to parse Nmap XML output."
        return data

    host = root.find('host')
    if host is None:
        data["error"] = "No host information found."
        return data

    # Host state
    status_el = host.find('status')
    if status_el is not None:
        data["host_state"] = status_el.get('state')

    # IP address
    address_el = host.find('address')
    if address_el is not None:
        data["ip_address"] = address_el.get('addr')

    # Hostnames
    hostnames_el = host.find('hostnames')
    if hostnames_el is not None:
        for hn in hostnames_el.findall('hostname'):
            name = hn.get('name')
            if name:
                data["hostnames"].append(name)

    # OS detection
    os_el = host.find('os')
    if os_el is not None:
        os_matches = os_el.findall('osmatch')
        if os_matches:
            best_match = os_matches[0].get('name')
            accuracy = os_matches[0].get('accuracy')
            data["os_guess"] = f"{best_match} (Accuracy: {accuracy}%)"

    # Ports
    ports_el = host.find('ports')
    if ports_el is not None:
        for p in ports_el.findall('port'):
            port_id = p.get('portid')
            protocol = p.get('protocol')
            state_el = p.find('state')
            service_el = p.find('service')

            if state_el is not None and state_el.get('state') == 'open':
                service_name = service_el.get('name') if service_el is not None else 'unknown'
                product = service_el.get('product') if service_el is not None else ''
                version = service_el.get('version') if service_el is not None else ''
                data["open_ports"].append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version
                })

    # Hostscript outputs
    for hostscript in host.findall('hostscript'):
        for script_el in hostscript.findall('script'):
            script_id = script_el.get('id')
            output = script_el.get('output', '').strip()
            if output:
                data["host_scripts"].append({
                    "id": script_id,
                    "output": output
                })

    # Port-specific scripts
    if ports_el is not None:
        for port_el in ports_el.findall('port'):
            for script_el in port_el.findall('script'):
                script_id = script_el.get('id')
                output = script_el.get('output', '').strip()
                if output:
                    data["port_scripts"].append({
                        "port": port_el.get('portid'),
                        "id": script_id,
                        "output": output
                    })

    return data

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    results = None

    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        ports = request.form.get('ports', '').strip()

        if not target:
            error = "Target is required."
        else:
            command = ["nmap", "-A", "--script=vuln", "-oX", "-"]
            if ports:
                command.extend(["-p", ports])
            command.append(target)

            try:
                proc = subprocess.run(command, capture_output=True, text=True)
                if proc.stderr and "Error" in proc.stderr:
                    error = f"Nmap encountered an error: {proc.stderr}"
                else:
                    results = parse_nmap_xml(proc.stdout)
            except FileNotFoundError:
                error = "Nmap not found. Please install Nmap on the server."
            except Exception as e:
                error = f"An unexpected error occurred: {e}"

    return render_template('index.html', error=error, results=results)

if __name__ == '__main__':
    # WARNING: do not deploy debug=True in production
    app.run(host='127.0.0.1', port=5000, debug=True)

