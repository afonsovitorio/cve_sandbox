import requests
from datetime import datetime, timedelta
import json

#Obtain date of today and yesterday
current_date = datetime.now()
today = current_date.strftime("%Y-%m-%d")
today_formatted = today 

yesterday = current_date - timedelta(days=1)
yesterday_formatted = yesterday.strftime("%Y-%m-%d")


#API call to NVD
url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate="
url = url + yesterday_formatted + "T00:00:00.000&pubEndDate=" + today_formatted + "T00:00:00.000"

response = requests.get(url)
if response.status_code == 200:
    data = response.json()

    return data
else:
    print(f"API call failed with status code {response.status_code}")

