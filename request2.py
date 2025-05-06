import sqlite3
import requests

# API Key
API_KEY = '9152da16-be42-45e0-bff1-8f3d70bc8c42'

# Check if a CVE exists in the database
def is_cve_in_database(cve_id):
    conn = sqlite3.connect('cve_database.sqlite')
    cursor = conn.cursor()

    # Query the database to check for the CVE
    cursor.execute("SELECT 1 FROM cve_details WHERE cve = ?", (cve_id,))
    exists = cursor.fetchone()

    conn.close()
    return exists is not None

# Your existing function to store CVE details
def store_cve_details(cve_id, description, cvss_score, severity, technology, vendor, epss_score):
    conn = sqlite3.connect('cve_database.sqlite')
    cursor = conn.cursor()

    # Insert the CVE into the database
    cursor.execute('''
        INSERT INTO cve_details (cve, description, cvss_score, severity, technology, vendor, epss)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (cve_id, description, cvss_score, severity, technology, vendor, epss_score))
    conn.commit()
    conn.close()

# Fetch CVE data and save it to the database
def fetch_and_store_cve(cve_id):
    headers = {'Authorization': f'Bearer {API_KEY}'}
    response = requests.get(f'https://api.cvecrowd.com/api/v1/cves/{cve_id}', headers=headers)

    if response.status_code == 200:
        cve_data = response.json()
        # Extract data
        description = cve_data.get('description', '')
        cvss_score = cve_data.get('base_score', None)  # Assuming CVSS score maps to base_score
        severity = cve_data.get('base_severity', 'Unknown')
        technology = cve_data.get('product', 'Unknown')
        vendor = cve_data.get('vendor', 'Unknown')
        epss_score = cve_data.get('epss', 0.0)

        # Store in database
        store_cve_details(cve_id, description, cvss_score, severity, technology, vendor, epss_score)
        print(f"Stored details for {cve_id}")
    else:
        print(f"Failed to fetch data for {cve_id}: {response.status_code}")

if __name__ == '__main__':
    # Read CVE IDs from file
    cve_file = 'C:\\Users\\afonso\\Desktop\\cve_ids.txt'  # Update with the actual file name
    with open(cve_file, 'r') as file:
        cve_ids = [line.strip() for line in file]

    # Process each CVE ID
    for cve_id in cve_ids:
        if is_cve_in_database(cve_id):
            print(f"CVE {cve_id} is already in the database. Skipping API request.")
        else:
            fetch_and_store_cve(cve_id)

    print("Finished processing all CVEs.")
