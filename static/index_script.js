async function fetchData(apiUrl) {
    try {
        var response = await fetch(apiUrl);

        if (!response.ok) {
            throw new Error(`Failed to fetch data. Status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        throw new Error(`Error fetching data: ${error.message}`);
    }
}

function isCVEID(str) {
    const cvePattern = /^CVE-\d{4}-\d{4,}$/;
  
    return cvePattern.test(str);
}

async function searchCVE() {
    var searchInput = document.getElementById('searchInput').value;
    var resultContainer = document.getElementById('resultContainer');

    resultContainer.innerHTML = '';
    
    var loadingIndicator = document.createElement('img');
    loadingIndicator.src = 'static/spinner.gif'; 
    loadingIndicator.alt = 'Loading...';
    loadingIndicator.width = 50; 
    loadingIndicator.height = 50; 
    resultContainer.appendChild(loadingIndicator);

    if (searchInput.trim() !== '') {
        console.log(searchInput);

        var apiUrl = null;
        var response = null;

        try {
            if (isCVEID(searchInput)) {
                apiUrl = `http://127.0.0.1:5000/api/cve/${searchInput}`;
            }else{
                apiUrl = `http://127.0.0.1:5000/api/search/${searchInput}`;
            }

            response = await fetch(apiUrl);

            if (!response.ok) {
                throw new Error(`Failed to fetch data. Status: ${response.status}`);
            }

            var result = await response.json();

            for (let i = 0; i < result.length; i++) {
                flag = Array.isArray(result[i]);
            }

            if (flag) {
                var tableElement = document.createElement('table');
                tableElement.classList.add('result-table');
                tableElement.classList.add('table');

                var headerRow = tableElement.insertRow();
                var headers = ["CVE ID", "Description", "CVSS Score", "Severity", "Technology", "Vendor", "EPSS Score"];

                headers.forEach(header => {
                    var headerCell = document.createElement('th');
                    headerCell.textContent = header;
                    headerRow.appendChild(headerCell);
                });

                for (let i = 0; i < result.length; i++) {
                    var dataRow = tableElement.insertRow();
                    result[i].forEach((value, index) => {
                        var dataCell = document.createElement('td');
                        dataCell.textContent = value;
                        dataRow.appendChild(dataCell);
    
                        if (index === result[i].length - 1) {
                            var button = document.createElement('button');
                            button.textContent = 'Select';
                            button.addEventListener('click', () => {
                                $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
                                $('#loadingModal').modal('show');
                                var destinationURL = `/cve/${result[i][0]}`;
                                window.location.href = destinationURL;
                            });

                            button.classList.add('btn');
                            button.classList.add('btn-dark');
    
                            var buttonCell = document.createElement('td');
                            buttonCell.appendChild(button);
                            dataRow.appendChild(buttonCell);
                        }
                    });
                }

                resultContainer.appendChild(tableElement);

            }else if (!flag) {
                var tableElement = document.createElement('table');
                tableElement.classList.add('result-table');
                tableElement.classList.add('table');
                

                var headerRow = tableElement.insertRow();
                var headers = ["CVE ID", "Description", "CVSS Score", "Severity", "Technology", "Vendor", "EPSS Score"];

                headers.forEach(header => {
                    var headerCell = document.createElement('th');
                    headerCell.textContent = header;
                    headerRow.appendChild(headerCell);
                });

                var dataRow = tableElement.insertRow();
                result.forEach((value, index) => {
                    var dataCell = document.createElement('td');
                    dataCell.textContent = value;
                    dataRow.appendChild(dataCell);

                    if (index === result.length - 1) {
                        var button = document.createElement('button');
                        button.textContent = 'Select';
                        button.addEventListener('click', () => {
                            $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
                            $('#loadingModal').modal('show');
                            var destinationURL = `/cve/${searchInput}`;
                            window.location.href = destinationURL;
                        });
                        button.classList.add('btn');
                        button.classList.add('btn-dark');

                        var buttonCell = document.createElement('td');
                        buttonCell.appendChild(button);
                        dataRow.appendChild(buttonCell);
                    }
                });

                resultContainer.appendChild(tableElement);
            } else {
                console.error('Invalid API response.');
            }
        } catch (error) {
            console.error('Error:', error.message);
        }finally{
            loadingIndicator.remove();
        }
    } else {
        alert('Please enter a CVE ID for search.');
    }
}

function selectCVE(cveID) {
    $('#loadingModal').modal({backdrop: 'static', keyboard: false}, 'show');
    $('#loadingModal').modal('show');
    var destinationURL = `/cve/${cveID}`;
    window.location.href = destinationURL;
}



function checkEnter(event) {
    if (event.keyCode === 13) {
        searchCVE();
    }
}
