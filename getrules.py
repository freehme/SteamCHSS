import logging
import requests
import os
import json
import sys
import calendar

from operator import itemgetter
from iso8601utils import parsers


# Access Token from CSP
access_token = ''

if "REFRESH_TOKEN" in os.environ:
    refresh_token = os.environ['REFRESH_TOKEN']
else:
    logging.error("REFRESH_TOKEN was not set in environment variable.\nToken can be obtained from CSP\n")
    sys.exit()
    

class ErrorStatusCode(Exception):
    pass

## Get Access Token from CSP
def auth():

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize'
    payload = {"refresh_token": refresh_token }

    response = requests.post(url, data=payload , headers=headers)

    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()

    data = json.loads(response.content)

    global access_token
    access_token = data["access_token"]



def vss_rules():
    url = "https://api.securestate.vmware.com/v1/rules"
    payload = {}    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.get(url, headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    

    print(response.json())


if __name__ == '__main__':
    auth()
    vss_rules()

