import logging
import requests
import os
import json
import sys


from operator import itemgetter
from iso8601utils import parsers
from requests.models import Response


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


#download account inventory status

def vss_accnt_status():
    url = 'https://api.securestate.vmware.com/v1/cloud-accounts/collection-status/query'
    payload = {
       "paginationInfo": {"pageSize": 1000},
   }
    headers = {
        'Content-Type': 'application/json',
         'Authorization': 'Bearer {}'.format(access_token)

    }
    while True:
      response = requests.post(url, json=payload , headers=headers)
      try:
         if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
      except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
            if response.status_code != 200:
                raise Exception(f"something went wrong: {response.text}")
      r = response.json()
      create_or_update_file("account.json", response) 
      
      print(r)
      
      if r.get('paginationInfo').get("continuationToken"):
                payload["paginationInfo"] = {
                "continuationToken": r.get('paginationInfo').get('continuationToken'),
                "pageSize": 1000,
            }
      else:
         break
         
     

def create_or_update_file(file_path, content):
    if os.path.isfile(file_path):
        with open(file_path, "a+") as output_file:
            json.dump(content.json(), output_file, indent=4)
            output_file.close()
    else:
        output_file = open(file_path, "w")
        json.dump(content.json(), output_file, indent=4)
        output_file.close()
      


if __name__ == '__main__':
    auth()
    vss_accnt_status()




