from flask import Flask, jsonify, redirect, render_template
import requests
import random
from pathlib import Path
import re
import sqlite3
import json
import os
import subprocess
import time
from vagrant import Vagrant
import pyxploitdb
import logging
import paramiko
import signal
import sys
from colorama import Fore, Style
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
#logging.basicConfig(level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"
POC_API_URL = "https://poc-in-github.motikan2010.net/api/v1/"
DOCKER_API_URL = "https://hub.docker.com/v2/search/repositories/?query={cve_id}"
VULHUB_PATH = ".\\vulhub"
vagrant_attacker_path = ".\\vagrant\\kali_vagrant"
vagrant_docker_host_path = ".\\vagrant\\ubuntu_docker_host"
vagrant_entry_path = ".\\vagrant\\ubuntu_entrypoint"
API_BASE_URL = "http://127.0.0.1:5000"
API_KEY = '' # Get API key from https://cvecrowd.com/


attacker_start_time = None
docker_host_start_time = None

attacker_ip = None
docker_host_ip = None
entry_ip = None


def ctrl_c_handler(sig, frame):
    attacker_vagrant = Vagrant(vagrant_attacker_path)
    docker_host_vagrant = Vagrant(vagrant_docker_host_path)
    entry_vagrant = Vagrant(vagrant_entry_path)

    print("Shutting down the VMs, this will take a while, please wait...")

    attacker_vagrant.halt()
    print("attacker Linux VM stopped!")
    docker_host_vagrant.halt()
    print("docker_host VM stopped!")
    entry_vagrant.halt()
    print("Entrypoint VM stopped!")


    sys.exit(0)


# Enable for ctrl+c handling, stops the VMs
#signal.signal(signal.SIGINT, ctrl_c_handler)


def run_on_startup():
    command = "cd .\\vulhub && git pull"

    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error updating vulhub repository: {e}")
        app.logger.error(f"Command Output (stderr): {e.stderr}")

def create_database():
    try:
        conn = sqlite3.connect('cve_database.sqlite')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_details (
                cve TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                technology TEXT,
                vendor TEXT,
                epss REAL
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error(f"Error creating database: {e}")

def execute_command(server_address, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(server_address, port=22, username="vagrant", password="vagrant")
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        client.close()
        return output
    except Exception as e:
        return f"Error: {e}"


@app.route('/')
def index():
    lastest_cves_api_url = f"{API_BASE_URL}/api/latest_cves"


    try:
        response = requests.get(lastest_cves_api_url)
        response.raise_for_status()
        latest_cves = response.json()

        results = []
        for item in latest_cves:
            cve_details = get_cve_details_api(item)
            results.append((cve_details["cve"],cve_details["description"],cve_details["cvss_score"],cve_details["severity"],cve_details["technology"],cve_details["vendor"],cve_details["epss"]))

        

    except requests.exceptions.RequestException as e:
        results = ""


    return render_template('index.html', latest_cves=results)

@app.route('/cve/<cve_id>')
def show_cve(cve_id):
    api_url = f"{API_BASE_URL}/api/cve/{cve_id}"
    exploits_edb_api_url = f"{API_BASE_URL}/api/exploit_edb2/{cve_id}"
    exploits_github_api_url = f"{API_BASE_URL}/api/exploit_github/{cve_id}"
    docker_api_url = f"{API_BASE_URL}/api/docker/{cve_id}"
    vulhub_api_url = f"{API_BASE_URL}/api/vulhub/{cve_id}"
    status_attacker_api_url = f"{API_BASE_URL}/api/status_attacker"
    status_docker_host_api_url = f"{API_BASE_URL}/api/status_docker_host"
    status_entry_api_url = f"{API_BASE_URL}/api/status_entry"
    status_docker_api_url = f"{API_BASE_URL}/api/docker_status"

    print("Loading CVE page, this will take a while...")
    app.logger.info(f"Loading CVE page for {cve_id}")

    try:
        response = requests.get(api_url)
        response.raise_for_status()
        response = requests.get(api_url)
        response.raise_for_status()
        cve_info = response.json()
    except requests.exceptions.RequestException as e:
        cve_info = ""

    try:
        exploits_info_edb = requests.get(exploits_edb_api_url)
        exploits_info_edb.raise_for_status()
        exploits_info_edb = exploits_info_edb.json()
    except requests.exceptions.RequestException as e:
        exploits_info_edb = ""

    try:
        exploits_info_github = requests.get(exploits_github_api_url)
        exploits_info_github.raise_for_status()
        exploits_info_github = exploits_info_github.json()
    except requests.exceptions.RequestException as e:
        exploits_info_github = ""

    try:
        docker_info = requests.get(docker_api_url)
        docker_info.raise_for_status()
        docker_info = docker_info.json()
    except requests.exceptions.RequestException as e:
        docker_info = ""

    try:
        vulhub_info = requests.get(vulhub_api_url)
        vulhub_info.raise_for_status()
        vulhub_info = vulhub_info.json()
    except requests.exceptions.RequestException as e:
        vulhub_info = ""

    try:
        status_attacker = requests.get(status_attacker_api_url)
        status_attacker.raise_for_status()
        status_attacker = status_attacker.json()
    except requests.exceptions.RequestException as e:
        status_attacker = ""

    try:
        status_docker_host = requests.get(status_docker_host_api_url)
        status_docker_host.raise_for_status()
        status_docker_host = status_docker_host.json()
    except requests.exceptions.RequestException as e:
        status_docker_host = ""

    try:
        status_entry = requests.get(status_entry_api_url)
        status_entry.raise_for_status()
        status_entry = status_entry.json()
    except requests.exceptions.RequestException as e:
        status_entry = ""

    try:
        status_docker = requests.get(status_docker_api_url)
        status_docker.raise_for_status()
        status_docker = status_docker.json()
    except requests.exceptions.RequestException as e:
        status_docker = ""

    print("CVE page loaded!")

    return render_template('cve_template.html', cve_id=cve_id, cve_info=cve_info, exploits_info_edb=exploits_info_edb, exploits_info_github=exploits_info_github, docker_info=docker_info, vulhub_info=vulhub_info, status_attacker=status_attacker, status_docker_host=status_docker_host, status_entry=status_entry, status_docker=status_docker)

def clean_html(raw_html):
    soup = BeautifulSoup(raw_html, "html.parser")
    return soup.get_text(strip=True)

@app.route('/api/search/<name>', methods=['GET'])
def search(name):
        try:
            header = get_header()
            search_url = requests.get("https://app.opencve.io/cve/?search=" + name, headers = header)

            pattern = re.compile(
            r'<a href="/cve/(CVE-\d{4}-\d+)">.*?</a>.*?'  # Capture CVE ID
            r'<td class="col-md-3">(.*?)</td>.*?'  # Capture Vendor (optional)
            r'<td class="col-md-3">(.*?)</td>.*?'  # Capture Technology (optional)
            r'<td class="col-md-2 text-center">(.*?)</td>.*?'  # Capture Date
            r'<span class="label.*?">(.*?)</span>.*?'  # Capture CVSS Score
            r'<tr class="cve-summary">\s*<td.*?colspan="5">(.*?)</td>',  # Capture Summary
            re.DOTALL
            )

            matches = pattern.findall(search_url.text)

            results = []
            for match in matches:
                cve_id, vendor, product, date, cvss, summary = match
                vendor_clean = clean_html(vendor) if vendor else "-"
                product_clean = clean_html(product) if product else "-"
                cvss = cvss.strip() if cvss else "N/A"
                clean_summary = clean_html(summary)

                if cvss:
                    parts = cvss.strip().split(" ")
                    score = parts[0]
                    severity = parts[1] if len(parts) > 1 else "Unknown"
                else:
                    score = "N/A"
                    severity = "N/A"

                results.append([cve_id, clean_summary, score, severity, product_clean, vendor_clean, 0])


                    

            return jsonify(results)
        except Exception as e:
            return jsonify(message=f"Error fetching data from API: {e}"), 500
    
@app.route('/api/exploit_github/<cve_id>', methods=['GET'])
def exploit_github(cve_id):
    try:
        response = requests.get(POC_API_URL, params={"cve_id": cve_id, "sort": "stargazers_count"})
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return None

@app.route('/api/exploit_edb/<cve_id>', methods=['GET'])
def exploit_edb(cve_id):
    cve_id = cve_id.upper()
    try:
        header = get_header()
        cve = cve_id.strip("CVE-")
        cve_url = requests.get(f"https://www.exploit-db.com/search?cve={cve}", headers=header).json()
        cve_infos = json.dumps(cve_url, sort_keys=False, indent=4)
        cve_infos = json.loads(cve_infos)
        cve_infos = cve_infos['data']

        if cve_infos == []:
            return None
        else:
            return jsonify(cve_infos)
    except requests.exceptions.RequestException as e:
        return None

@app.route('/api/exploit_edb2/<cve_id>', methods=['GET'])
def exploit_edb2(cve_id):
    cve_id = cve_id.upper()

    exploits = pyxploitdb.searchCVE(cve_id)

    return jsonify(exploits)

@app.route('/api/docker/<cve_id>', methods=['GET'])
def docker(cve_id):
    docker_url = DOCKER_API_URL.format(cve_id=cve_id)
    try:
        response = requests.get(docker_url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return None

# If the API stops responding to requests, disable the cve_search_info
@app.route('/api/cve/<cve_id>', methods=['GET'])
def cve(cve_id):

    cve_id = cve_id.upper()

    if(check_cve_exists_db(cve_id)):
        cve_details = get_cve_details_db(cve_id)

        return jsonify(cve_details)
    else:
        cve_details = get_cve_details_api(cve_id)

        if(cve_details is not None):
            store_cve_details(cve_details["cve"], cve_details["description"], cve_details["cvss_score"], cve_details["severity"], cve_details["technology"], cve_details["vendor"], cve_details["epss"])

            details = cve_details["cve"], cve_details["description"], cve_details["cvss_score"], cve_details["severity"], cve_details["technology"], cve_details["vendor"], cve_details["epss"]


            return jsonify(details)
        else:
            return None

@app.route('/api/latest_cves', methods=['GET'])
def latest_cves():
    headers = {'Authorization': f'Bearer {API_KEY}'}
    try:
        response = requests.get(f'https://api.cvecrowd.com/api/v1/cves?limit=10', headers=headers)
        data = response.json()

        return data
    except Exception as e:
        return jsonify(message=f"Error fetching data from API: {e}"), 500

@app.route('/api/vulhub/<cve_id>', methods=['GET'])
def vulhub(cve_id):
    try:
        result = find_directory_with_docker_compose(VULHUB_PATH, cve_id)

        if result:
            directory_path, compose_content = result
            
            relative_path = os.path.relpath(directory_path, VULHUB_PATH)

            vulhub_url = "https://github.com/vulhub/vulhub/tree/master/"

            url = vulhub_url + relative_path

            url = url.replace("\\", "/")

            return jsonify(message=f"{relative_path}", url=url, compose_content=compose_content)
        else:
            return jsonify(message=f"Error fetching data from API: {e}"), 500
    except Exception as e:
        return jsonify(message=f"Error fetching data from API: {e}"), 500

@app.route('/api/start_attacker', methods=['GET'])
def start_attacker():
    return jsonify(vagrant_attacker_start())

def vagrant_attacker_start():
    global attacker_start_time
    global attacker_ip
    try:
        vagrant = Vagrant(vagrant_attacker_path)

        if vagrant.status()[0].state == "running":
            print(f"Attacker Linux Machine is already running...")
            attacker_ip = vagrant.ssh(command="ip a | awk '/inet / && /eth0/ {print $2}' | cut -d '/' -f 1")
            attacker_ip = attacker_ip.strip()
            return vagrant.status()

        print(f"Starting Attacker Machine using Vagrant...")
        status = vagrant.up()

        time.sleep(60)

        attacker_ip = vagrant.ssh(command="ip a | awk '/inet / && /eth0/ {print $2}' | cut -d '/' -f 1")
        attacker_ip = attacker_ip.strip() 

        execute_command(attacker_ip, "nohup tightvncserver")

        print(f"Vagrant machine status: {status}")

        attacker_start_time = time.time()

        return status
    except Exception as e:
        return e

@app.route('/api/status_attacker', methods=['GET'])
def status_attacker():
    global attacker_ip
    global attacker_start_time

    if attacker_ip is None:
        status = "not_running"
    else:
        status = "running"

    if attacker_start_time is not None:
        elapsed_time = time.time() - attacker_start_time
        return jsonify(status, elapsed_time)
    else:
        return jsonify(status, 0)

@app.route('/api/stop_attacker', methods=['GET'])
def stop_attacker():
    global attacker_ip
    global attacker_start_time
    try:
        result = execute_command(attacker_ip, "sudo shutdown now")

        attacker_ip = None

        status = "not_running"

        if attacker_start_time is not None:
            elapsed_time = time.time() - attacker_start_time
            attacker_start_time = None
            return jsonify(message=f"Vagrant machine status: {status}", elapsed_time=elapsed_time) 
        else:
            return jsonify(message=f"Vagrant machine status: {status}")
    except Exception as e:
        return jsonify(message=f"Error stopping Vagrant machine: {e}"), 500

@app.route('/api/view_attacker_vnc', methods=['GET'])
def view_attacker_vnc():
    global entry_ip
    target_url = 'http://' + entry_ip + '/vnc.html'
    return redirect(target_url)

@app.route('/api/view_attacker', methods=['GET'])
def view_attacker():
    global attacker_ip
    global entry_ip

    if attacker_ip is None:
        return jsonify(message="Attacker Linux machine is not running, please start it first!"), 500
    else:
        target_url = 'http://' + entry_ip + ':8022/ssh/host/' + attacker_ip
        return redirect(target_url)

@app.route('/api/start_docker_host', methods=['GET'])
def start_docker_host():
    return jsonify(docker_host_start())

def docker_host_start():
    global docker_host_start_time
    global docker_host_ip
    try:
        vagrant = Vagrant(vagrant_docker_host_path)

        if vagrant.status()[0].state == "running":
            print(f"docker_host Machine is already running...")
            docker_host_ip = vagrant.ssh(command="ip a | awk '/inet / && /eth0/ {print $2}' | cut -d '/' -f 1")
            docker_host_ip = docker_host_ip.strip()
            return vagrant.status()

        print(f"Starting docker_host machine...")
        vagrant.up()
        status = vagrant.status()
        print(f"Vagrant machine status: {status}")
        docker_host_start_time = time.time()
        print("docker_host machine started at:", docker_host_start_time)

        docker_host_ip = vagrant.ssh(command="ip a | awk '/inet / && /eth0/ {print $2}' | cut -d '/' -f 1")
        docker_host_ip = docker_host_ip.strip()

        return status
    except Exception as e:
        return e

@app.route('/api/view_docker_host', methods=['GET'])
def view_docker_host():
    global docker_host_ip
    global entry_ip

    target_url = 'http://' + entry_ip + ':8022/ssh/host/' + docker_host_ip
    return redirect(target_url)

@app.route('/api/start_entry', methods=['GET'])
def start_entry():
    return jsonify(vagrant_entry_start())

def vagrant_entry_start():
    global entry_ip
    entry_vagrant = Vagrant(vagrant_entry_path)
    attacker_vagrant = Vagrant(vagrant_attacker_path)

    if entry_vagrant.status()[0].state == "running":
        print(f"Entrypoint machine is already running...")
        entry_ip = entry_vagrant.ssh(command="ip a | awk '/inet / && /eth0/ {print $2}' | cut -d '/' -f 1")
        entry_ip = entry_ip.strip()
        return entry_vagrant.status()

    attacker_ip = attacker_vagrant.ssh(command="ip a | awk '/inet / && /eth0/ {print $2}' | cut -d '/' -f 1")
    attacker_ip = attacker_ip.strip()

    print(f"Starting Entrypoint machine...")
    entry_vagrant.up()
    status = entry_vagrant.status()
    print(f"Vagrant machine status: {status}")
    result = entry_vagrant.ssh(command="docker rm -f $(docker ps -aq); nohup docker run --rm -it --name webssh2 -p 8022:2222 -d psharkey/webssh2 && nohup docker run --name noVNC --detach --publish 80:6080 gotget/novnc --vnc " + attacker_ip.strip() + ":5901")
    print("Entry machine started!", result)

    entry_ip = entry_vagrant.ssh(command="ip a | awk '/inet / && /eth0/ {print $2}' | cut -d '/' -f 1")
    entry_ip = entry_ip.strip()

    return status

@app.route('/api/stop_docker_host', methods=['GET'])
def stop_docker_host():
    global docker_host_start_time
    global docker_host_ip

    vagrant = Vagrant(vagrant_docker_host_path)

    print(f"Stopping Vagrant machine in {vagrant_docker_host_path}...")
    vagrant.halt()

    status = vagrant.status()

    docker_host_start_time = None
    docker_host_ip = None

    print(f"Vagrant machine status: {status}")

    return jsonify(message=f"Vagrant machine status: {status}")

@app.route('/api/status_docker_host', methods=['GET'])
def status_docker_host():
    global docker_host_start_time
    global docker_host_ip

    if docker_host_ip is None:
        status = "not_running"
    else:
        status = "running"

    if docker_host_start_time is not None:
        elapsed_time = time.time() - docker_host_start_time
        return jsonify(status, elapsed_time)
    else:
        return jsonify(status, 0)
    
@app.route('/api/status_entry', methods=['GET'])
def status_entry():
    global entry_ip
    try:
        return jsonify("running", entry_ip)
    except Exception as e:
        return jsonify(message=f"Error fetching data from API: {e}"), 500
            
@app.route('/api/start_docker_container/<par1>/', defaults={'par2': ""}, methods=['GET'])
@app.route('/api/start_docker_container/<par1>/<par2>/', methods=['GET'])
def start_docker_container(par1, par2):
    global docker_host_ip

    if par2 != "":
        container_name = f"{par1}/{par2}"
    else:
        container_name = par1

    app.logger.info(f"Starting Docker container with name: {container_name}")

    execute_command(docker_host_ip, f"docker rm -f $(docker ps -aq); echo "" > /tmp/capture")

    #TODO: Remove python3.8
    command = "python3.8 /home/vagrant/converter.py " + container_name

    result = execute_command(docker_host_ip, command)

    result2 = execute_command(docker_host_ip, "container_name=$(image_name=$(grep -E '^\s*image:' docker-compose.yml | awk '{print $2}') && docker ps --filter \"ancestor=$image_name\" --format \"{{.Names}}\") ; docker run -d --rm --net container:$container_name nicolaka/netshoot tcpdump -i eth0 -w /tmp/capture.pcap")

    ports = execute_command(docker_host_ip, "cat /home/vagrant/docker-compose.yml | grep \"-\" | awk -F \":\" '{print $2}'")

    return jsonify(message=f"Starting Docker container with name: {container_name}", result=result, ports=ports)

@app.route('/api/start_docker_container_vulhub/<cve_id>', methods=['GET'])
def start_docker_container_vulhub(cve_id):
    result = find_directory_with_docker_compose(VULHUB_PATH, cve_id)
    global docker_host_ip

    if result:
        print("Starting Docker container with name:", cve_id)
        directory_path, compose_content = result

        compose_path = os.path.join(directory_path, "docker-compose.yml")

        execute_command(docker_host_ip, "docker rm -f $(docker ps -aq); echo "" > /tmp/capture")

        execute_command(docker_host_ip, f"echo '{compose_content}' > /home/vagrant/docker-compose.yml")

        execute_command(docker_host_ip, "sh /home/vagrant/docker_compose_fixer.sh")

        result = execute_command(docker_host_ip, "docker-compose -f /home/vagrant/docker-compose.yml up -d")

        print("Docker container started with name:", cve_id)
        print("Starting packet capture...")

        result2 = execute_command(docker_host_ip, "container_name=$(image_name=$(grep -E '^\s*image:' /home/vagrant/docker-compose.yml | awk '{print $2}') && docker ps --filter \"ancestor=$image_name\" --format \"{{.Names}}\") ; docker run -d --rm --net container:$container_name nicolaka/netshoot tcpdump -i eth0 -w /tmp/capture.pcap")

        print("Packet capture started!")

        return jsonify(result=result, result2=result2)
    
    else:
        return jsonify(message=f"Error starting Docker container with name: {cve_id}")
    
@app.route('/api/get_container_traffic', methods=['GET'])
def get_container_traffic():
    global docker_host_ip
    try:
        execute_command(docker_host_ip, "name=$(docker ps -qf \"ancestor=nicolaka/netshoot\"); docker cp $name:/tmp/capture.pcap /var/www/html/capture.pcap")

        url = 'http://' + docker_host_ip + '/capture.pcap'

        return redirect(url)
    except Exception as e:
        return jsonify(message=f"Error fetching data from API: {e}"), 500

@app.route('/api/stop_docker_containers', methods=['GET'])
def stop_docker_containers():
    global docker_host_ip
    try:
        result = execute_command(docker_host_ip, "docker rm -f $(docker ps -aq)")

        return jsonify(message=f"Stopping Docker containers", result=result)
    except Exception as e:
        return jsonify(message=f"Error stopping Docker containers: {e}"), 500

@app.route('/api/docker_network_info', methods=['GET'])
def docker_open_ports():
    global docker_host_ip

    try:
        result = execute_command(docker_host_ip, "docker container inspect $(docker ps -aq)")

        result = json.loads(result)

        open_ports_list = []

        for container_info in result:
            network_settings = container_info.get("NetworkSettings", {})
            ports = network_settings.get("Ports", {})

        for port, port_info_list in ports.items():
            for port_info in port_info_list:
                host_port = port_info.get("HostPort")
                open_ports_list.append(host_port)

        open_ports_list = list(set(open_ports_list))


        full_urls = []

        for port in open_ports_list:
            full_urls.append("http://" + docker_host_ip + ":" + port)

        return jsonify(ip=docker_host_ip, ports=open_ports_list, full_urls=full_urls)
    
    except Exception as e:
        return jsonify(message=f"Error fetching data from API: {e}"), 500

@app.route('/api/docker_status', methods=['GET'])
def docker_status():
    global docker_host_ip
    try:
        result = execute_command(docker_host_ip, "docker ps -q | grep . && echo \"running\" || echo \"not_running\"")

        if 'not_running' in result:
            result = 'not_running'
        else:
            result = 'running'


        result2 = execute_command(docker_host_ip, "docker container inspect $(docker ps -aq)")

        result2 = json.loads(result2)

        open_ports_list = []

        for container_info in result2:
            network_settings = container_info.get("NetworkSettings", {})
            ports = network_settings.get("Ports", {})

        for port, port_info_list in ports.items():
            for port_info in port_info_list:
                host_port = port_info.get("HostPort")
                open_ports_list.append(host_port)

        open_ports_list = list(set(open_ports_list))

        return jsonify(result=result, ip_result=docker_host_ip, ports=open_ports_list)
    except Exception as e:
        return jsonify(message=f"Error fetching data from API: {e}"), 500

def calculate_severity(cvss_score):
    if cvss_score >= 9.0:
        return 'Critical'
    elif cvss_score >= 7.0:
        return 'High'
    elif cvss_score >= 4.0:
        return 'Medium'
    else:
        return 'Low'

def store_cve_details(cve_id, description, cvss_score, severity, technology, vendor, epss_score):
    conn = sqlite3.connect('cve_database.sqlite')

    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO cve_details (cve, description, cvss_score, severity, technology, vendor, epss)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (cve_id, description, cvss_score, severity, technology, vendor, epss_score))

    conn.commit()
    conn.close()

def get_cve_details_api(cve_id):
    headers = {'Authorization': f'Bearer {API_KEY}'}
    response = requests.get(f'https://api.cvecrowd.com/v2/cves/{cve_id}', headers=headers)

    print(response.status_code )

    if response.status_code == 200:
        print("++++++++++++++ IM HERE +++++++++++++++++")
        cve_data = response.json()
        description = cve_data.get('description', '')
        cvss_score = cve_data.get('base_score', None)
        severity = cve_data.get('base_severity', 'Unknown')
        technology = cve_data.get('product', 'Unknown')
        vendor = cve_data.get('vendor', 'Unknown')
        epss_score = cve_data.get('epss', 0.0)

        cve_details = {
            "cve": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "technology": technology,
            "vendor": vendor,
            "epss": epss_score
        }


        return cve_details
    else:
        print(f"Failed to fetch data for {cve_id}: {response.status_code}")

def get_cve_details_db(cve_id):
    try:
        conn = sqlite3.connect('cve_database.sqlite')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cve_details WHERE cve = ?", (cve_id,))
        result = cursor.fetchone()
        conn.close()
        return result
    except Exception as e:
        app.logger.error(f"Error fetching data from database: {e}")
        return None
    
def check_cve_exists_db(cve_id):
    try:
        conn = sqlite3.connect('cve_database.sqlite')
        cursor = conn.cursor()
        cursor.execute("SELECT cve FROM cve_details WHERE cve = ?", (cve_id,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        app.logger.error(f"Error fetching data from database: {e}")
        return False
    
def get_description_cve(cve_item):
    descriptions = cve_item.get("descriptions", [])
    description = next(
        (desc["value"] for desc in descriptions if desc["lang"] == "en"),
        "No description available",
    )
    return description

def get_cve_data(nvd_url):
    try:
        response = requests.get(nvd_url)
        response.raise_for_status()
        cve_data = response.json()

        return cve_data
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching data from API: {e}")
        return None
    
def get_header():
    try:
        headers_file_path = Path("headers.txt")

        with open(headers_file_path, "r") as file:
            user_agents = [line.strip() for line in file.readlines() if line.strip()]

        if not user_agents:
            raise ValueError("No user agents found in headers.txt")

        random_user_agent = random.choice(user_agents)

        header = {"User-Agent": random_user_agent, "X-Requested-With": "XMLHttpRequest"}
        return header
    except Exception as e:
        app.logger.error(f"Error fetching header: {e}")
        return None
    
def get_cve_search_info(cve_id, header):
    try:
        search_url = requests.get("https://www.opencve.io/cve?search=" + cve_id, headers = header)
        searchs = re.findall("<strong>(CVE-.*?)<\/strong>.*?(?:\n.*?)+(?:vendor=(.*?)&product=(.*?)'.*\n.*(\d{4}-\d{2}-\d{2})|(\d{4}-\d{2}-\d{2})).*?(?:\n.*?(\d?\d.\d).*?|\n.*?)+<tr class=\"cve-summary\">\n.*colspan=\"5\">(.*)", search_url.text, re.IGNORECASE)
        return searchs
    except Exception as e:
        app.logger.error(f"Error fetching data from API: {e}")
        return None
    
def get_epss_score(epss_url):
    try:
        response = requests.get(epss_url)
        response.raise_for_status()
        epss_data = response.json()


        if epss_data and "data" in epss_data and len(epss_data["data"]) > 0:
            epss_score = epss_data["data"][0].get("epss", "N/A")
            return epss_score
        else:
            return 0
        
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching data from API: {e}")
        return None
    
def find_directory_with_docker_compose(start_path, target_directory):
    try:
        target_directory_lower = target_directory.lower()

        for root, dirs, files in os.walk(start_path):
            for directory in dirs:
                if directory.lower() == target_directory_lower:
                    directory_path = os.path.join(root, directory)
                    compose_file_path = os.path.join(directory_path, "docker-compose.yml")

                    if os.path.exists(compose_file_path):
                        with open(compose_file_path, 'r') as compose_file:
                            compose_content = compose_file.read()

                        return directory_path, compose_content
    except Exception as e:
        app.logger.error(f"Error finding directory with docker-compose: {e}")
        return None



run_on_startup()
create_database()
#Uncomment to have VMs working
#print("Starting virtual machines, this will take a while...")
#vagrant_attacker_start()
#docker_host_start()
#vagrant_entry_start()
print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Application started successfully!")



if __name__ == '__main__':
    app.run(debug=True)
