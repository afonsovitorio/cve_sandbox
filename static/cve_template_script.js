function toggleSection(sectionId) {
    var section = document.getElementById(sectionId);
    section.style.display = (section.style.display === 'none' || section.style.display === '') ? 'block' : 'none';
}

async function deployImage(image_name){
    var dockerDeployStuff = document.getElementById('dockerDeployStuff');
    dockerDeployStuff.innerHTML = '';


    const dockerDeployStuffElements = document.querySelectorAll('#dockerDeployStuff');
    dockerDeployStuffElements.forEach(element => {
        element.innerHTML = '';
    });

    var statusHeading = document.createElement('h3');
    statusHeading.textContent = 'Starting Docker Container...';
    dockerDeployStuff.appendChild(statusHeading);

    var loadingIndicator = document.createElement('img');
    loadingIndicator.src = '../static/spinner.gif'; 
    loadingIndicator.alt = 'Loading...';
    loadingIndicator.width = 50; 
    loadingIndicator.height = 50; 
    dockerDeployStuff.appendChild(loadingIndicator);

    var apiUrl = `http://127.0.0.1:5000/api/start_docker_container/${image_name}`;
    response = await fetch(apiUrl);

    if (!response.ok) {
        window.alert("Unable to deploy Docker container. Please try again later.");
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
        throw new Error(`Failed to fetch data. Status: ${response.status}`);
    }else{
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
    }
}

async function deployImageVulhub(cve_id){
    dockerVulhubStuff.innerHTML = '';

    var statusHeading = document.createElement('h3');
    statusHeading.textContent = 'Starting Docker Container...';
    dockerVulhubStuff.appendChild(statusHeading);

    var loadingIndicator = document.createElement('img');
    loadingIndicator.src = '../static/spinner.gif'; 
    loadingIndicator.alt = 'Loading...';
    loadingIndicator.width = 50; 
    loadingIndicator.height = 50; 
    dockerVulhubStuff.appendChild(loadingIndicator);

    var apiUrl = `http://127.0.0.1:5000/api/start_docker_container_vulhub/${cve_id}`;
    response = await fetch(apiUrl);

    if (!response.ok) {
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
        throw new Error(`Failed to fetch data. Status: ${response.status}`);
    }else{
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
    }
}

function showOpenPorts() {
    window.open("http://127.0.0.1:5000/api/docker_network_info", "_blank");
}

async function stopDockerContainers(){
    var dockerControl = document.getElementById('dockerControl');
    dockerControl.innerHTML = '';

    var statusHeading = document.createElement('h3');
    statusHeading.textContent = 'Stopping Docker Containers...';
    dockerControl.appendChild(statusHeading);

    var loadingIndicator = document.createElement('img');
    loadingIndicator.src = '../static/spinner.gif'; 
    loadingIndicator.alt = 'Loading...';
    loadingIndicator.width = 50; 
    loadingIndicator.height = 50; 
    dockerControl.appendChild(loadingIndicator);

    var apiUrl = `http://127.0.0.1:5000/api/stop_docker_containers`;
    response = await fetch(apiUrl);

    if (!response.ok) {
        window.alert("Unable to stop Docker containers. Please try again later.");
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
        throw new Error(`Failed to fetch data. Status: ${response.status}`);
    }else{
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
    }

}

async function startAttacker(){
    var attackerControl = document.getElementById('attackerControl');
    attackerControl.innerHTML = '';

    var statusHeading = document.createElement('h3');
    statusHeading.textContent = 'Starting Attacker VM...';
    attackerControl.appendChild(statusHeading);

    var loadingIndicator = document.createElement('img');
    loadingIndicator.src = '../static/spinner.gif'; 
    loadingIndicator.alt = 'Loading...';
    loadingIndicator.width = 50; 
    loadingIndicator.height = 50; 
    attackerControl.appendChild(loadingIndicator);

    var apiUrl = `http://127.0.0.1:5000/api/start_attacker`;
    response = await fetch(apiUrl);

    if (!response.ok) {
        throw new Error(`Failed to fetch data. Status: ${response.status}`);
    }else{
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
    }

}

async function stopAttacker(){
    var attackerControl = document.getElementById('attackerControl');
    attackerControl.innerHTML = '';

    var statusHeading = document.createElement('h3');
    statusHeading.textContent = 'Stopping Attacker VM...';
    attackerControl.appendChild(statusHeading);

    var loadingIndicator = document.createElement('img');
    loadingIndicator.src = '../static/spinner.gif'; 
    loadingIndicator.alt = 'Loading...';
    loadingIndicator.width = 50; 
    loadingIndicator.height = 50; 
    attackerControl.appendChild(loadingIndicator);

    var apiUrl = `http://127.0.0.1:5000/api/stop_attacker`;
    response = await fetch(apiUrl);

    if (!response.ok) {
        throw new Error(`Failed to fetch data. Status: ${response.status}`);
    }else{
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
    }
}

function showAttacker(){
    window.open("http://127.0.0.1:5000/api/view_attacker", "_blank");
}

function showAttackerVNC(){
    window.open("http://127.0.0.1:5000/api/view_attacker_vnc", "_blank");
}

function showAttackerStatus(){
    window.open("http://127.0.0.1:5000/api/status_attacker", "_blank");
}

async function startDockerHost(){
    var dockerHostControl = document.getElementById('dockerHostControl');
    dockerHostControl.innerHTML = '';

    var statusHeading = document.createElement('h3');
    statusHeading.textContent = 'Starting DockerHost Server...';
    dockerHostControl.appendChild(statusHeading);

    var loadingIndicator = document.createElement('img');
    loadingIndicator.src = '../static/spinner.gif'; 
    loadingIndicator.alt = 'Loading...';
    loadingIndicator.width = 50; 
    loadingIndicator.height = 50; 
    dockerHostControl.appendChild(loadingIndicator);

    var apiUrl = `http://127.0.0.1:5000/api/start_docker_host`;
    response = await fetch(apiUrl);

    if (!response.ok) {
        throw new Error(`Failed to fetch data. Status: ${response.status}`);
    }else{
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
    }

}

async function stopDockerHost(){
    var dockerHostControl = document.getElementById('dockerHostControl');
    dockerHostControl.innerHTML = '';

    var statusHeading = document.createElement('h3');
    statusHeading.textContent = 'Stopping DockerHost Server...';
    dockerHostControl.appendChild(statusHeading);

    var loadingIndicator = document.createElement('img');
    loadingIndicator.src = '../static/spinner.gif'; 
    loadingIndicator.alt = 'Loading...';
    loadingIndicator.width = 50; 
    loadingIndicator.height = 50; 
    dockerHostControl.appendChild(loadingIndicator);

    var apiUrl = `http://127.0.0.1:5000/api/stop_docker_host`;
    response = await fetch(apiUrl);

    if (!response.ok) {
        throw new Error(`Failed to fetch data. Status: ${response.status}`);
    }else{
        $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
        $('#loadingModal').modal('show');
        location.reload(true);
    }
}

function showDockerHost(){
    window.open("http://127.0.0.1:5000/api/view_docker_host", "_blank");
}

function showNetworkLogs() {
    window.open("http://127.0.0.1:5000/api/get_container_traffic", "_blank");
}

function goBack() {
    window.location.href = '../..';
}

    