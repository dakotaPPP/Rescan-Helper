import requests
from rescan_helper import get_API_key, get_Qualys_Platform, get_LOGIN_url, get_Scanner_Appliance, get_SNOW_url 

#Global variables
API_KEY = get_API_key()
QUALYS_PLATFORM = get_Qualys_Platform()
LOGIN_URL = get_LOGIN_url()
SCANNER_APPLIANCE = get_Scanner_Appliance()
SNOW_URL = get_SNOW_url()


#improve so function takes in list of ips, then from there return list of IPs, tied with Names i.e. DeviceName (X.X.X.X) 

def doesIPHaveCloudAgent(ip):
    url = f"https://qualysapi.{QUALYS_PLATFORM}/qps/rest/2.0/search/am/hostasset"
    
    payload = f'<ServiceRequest><filters><Criteria field="address" operator="EQUALS">{ip}</Criteria><Criteria field="trackingMethod" operator="EQUALS">QAGENT</Criteria></filters></ServiceRequest>'

    headers = {
        'X-Requested-With': 'RescanHelperAPI',
        'Authorization': API_KEY
    }

    response = requests.post(url, headers=headers, data=payload)

    if(response.status_code != 200):
        print(f"Error bad response\nCode: {response.status_code}\nMessage: {response.text}")
        return []

    #This only occurs when the search query returns a cloud agent count of 0
    if(len(response.text) < 300):
        return False
    else:
        return True

    
