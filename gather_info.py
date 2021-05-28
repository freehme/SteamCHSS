import logging
import requests
import os
import json
import sys
import calendar

from operator import itemgetter
from iso8601utils import parsers
from generate import parse_arguments

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

"""Add Payload Filters - Payload, Existing Filters (Set True if filters exist), Set Levels Filter(If filtering by severity should be enabled), Status of findings ("Open" or "Resolved")"""
def add_payload_filters(pl, existing_filters=True, set_levels_filter=False,status="Open"):
    if(existing_filters):
        pass    
    else:
        filter_dict = {"filters":{}}
        
        pl.update(filter_dict)
    
    if(get_config()["config"]["cloudAccountIds"][0].lower() != "all"):
            pl["filters"]["cloudAccountIds"] = get_config()["config"]["cloudAccountIds"]
            pl["filters"]["status"] = status
    if(isinstance(get_config()["config"]["cloudTags"], dict)):
            pl["filters"]["cloudTags"] = get_config()["config"]["cloudTags"]
            pl["filters"]["status"] = status
    if(isinstance(get_config()["config"]["severity"], list) and set_levels_filter):
            pl["filters"]["levels"] = get_config()["config"]["severity"]
            pl["filters"]["status"] = status
    if(isinstance(get_config()["config"]["providers"], list)):
            pl["filters"]["cloudProviders"] = get_config()["config"]["providers"]
            pl["filters"]["status"] = status
        
    return pl


def create_or_update_file(file_path, content):
    if os.path.isfile(file_path):
        with open(file_path, "w") as output_file:
            json.dump(content.json(), output_file, indent=4)
        output_file.close()
    else:
        output_file = open(file_path, "w")
        json.dump(content.json(), output_file, indent=4)
        output_file.close()
 
# Creates necessary directories
def create_dir():
    if os.path.isdir("data"):
        logging.info("data directory exists in current path\n")
    else:
        logging.info("Creating data directory\n")
        os.mkdir("data")   
        logging.info("Successfully created data directory\n")

def vss_account_info():
    
    url = "https://api.securestate.vmware.com/v2/findings/query"
    payload = {
                "aggregations": {
                            "find": {
                                "fieldName":"CloudProvider",
                                "aggregationType": "Terms"
                                },
                            "accounts": {
                                "fieldName":"CloudAccountId",
                                "aggregationType":"Terms",
                                "termsCount":10
                                }
                            }
               }    
    
    payload = add_payload_filters(payload, False, True)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()   
    
    create_or_update_file("data/account_info.json", response)
    
def vss_all_rules():
    url = "https://api.securestate.vmware.com/v1/rules/query"
    payload = "{\n}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=payload, headers=headers)

    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
        
    create_or_update_file("data/all_rules_info.json", response)

def vss_top_10_rules():
    
    url = "https://api.securestate.vmware.com/v2/findings/query"
    
    payload = {
	    "aggregations":{
		    "rules":{
			    "fieldName":"RuleId",
			    "aggregationType": "Terms",
			    "termsCount":10
		    }
	    }
    }
    
    payload = add_payload_filters(payload, False, True)
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }    
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()   
    
    create_or_update_file("data/rules_info_top_10.json", response)
    

def vss_open_resolved_findings():
   
    url = "https://api.securestate.vmware.com/v2/findings/query"
    payload = {
                "aggregations": {
                        "accounts":{
                                "fieldName": "CloudAccountId",
                                "aggregationType":"Terms"
                                }
                        },
                "filters":{
                    "status":"Resolved"
                    }
            }
        
    payload = add_payload_filters(payload, True, True, status="Resolved")
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    
    create_or_update_file("data/resolved_findings.json", response)
    
def vss_frameworks():
    url = "https://api.securestate.vmware.com/v1/compliance-frameworks"
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
    
    create_or_update_file("data/frameworks.json", response)


def vss_top_10_by_severity(sev, accounts):
    url = "https://api.securestate.vmware.com/v2/findings/query"

    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    "subAggregations": {
                        sev:{
                            "fieldName":"CloudAccountId",
                            "aggregationType":"Terms",
                            "termsCount": 10
                        }
                    }
                }
            },
            "filters":{
                "cloudAccountIds": accounts,
                "levels":[sev],
                "status":"Open"    
            }
        }
    
    payload = add_payload_filters(payload, True, set_levels_filter=False)
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)

    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    return response

def vss_high_med_low_top_10_findings():
    
    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()
    
    open_accounts = accounts["aggregations"]["accounts"]["buckets"]
    
    top_10_account = []
    
    for account in open_accounts:
        top_10_account.append(account)   
    
    response = vss_top_10_by_severity("high", top_10_account)
    
    create_or_update_file("data/high_severity_top_10.json", response)

    #Medium Severity
    
    response = vss_top_10_by_severity("medium", top_10_account)
 
    create_or_update_file("data/medium_severity_top_10.json", response)

    # Low Severity

    response = vss_top_10_by_severity("low", top_10_account)
    
    create_or_update_file("data/low_severity_top_10.json", response)
    

def vss_suppressed_findings():
    
    url = "https://api.securestate.vmware.com/v2/findings/query"
    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",

                    "subAggregations": {
                        "suppressed":{
                            "fieldName":"CloudAccountId",
                            "aggregationType":"Terms",
                            "termsCount": 10
                            
                        }
                    }
                }
            },
            "filters":{
                "isSuppressed": True
            }

        }


    if(get_config()["config"]["cloudAccountIds"][0].lower() != "all"):
        payload["filters"]["cloudAccountIds"] = get_config()["config"]["cloudAccountIds"]
    
    if(isinstance(get_config()["config"]["cloudTags"], dict)):
        payload["filters"]["cloudTags"] = get_config()["config"]["cloudTags"]
        
    if(isinstance(get_config()["config"]["severity"], list)):
        payload["filters"]["levels"] = get_config()["config"]["severity"]
        
    if(isinstance(get_config()["config"]["providers"], list)):
        payload["filters"]["cloudProviders"] = get_config()["config"]["providers"]

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)

    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    create_or_update_file("data/suppressed_findings.json", response)

def vss_all_violations_by_severity():
    
    url = "https://api.securestate.vmware.com/v2/findings/query"
    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    }
            },
            "filters":{
                "levels":["High"],
                "status":"Open"
            }
        }
        
    payload = add_payload_filters(payload, True)
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    
    create_or_update_file("data/high_severity.json", response)
    
    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    }
                },
            "filters":{
                "levels":["Medium"],
                "status":"Open"
                }
        }
    
    payload = add_payload_filters(payload, True)
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    create_or_update_file("data/medium_severity.json", response)
    
    payload = {
            "aggregations":{
                "cloud":{
                    "fieldName":"CloudProvider",
                    "aggregationType":"Terms",
                    }
                },
            "filters":{
                "levels":["Low"],
                "status":"Open"
                }
            }
    
    payload = add_payload_filters(payload, True)

    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    create_or_update_file("data/low_severity.json", response)

def vss_top_10_objects_by_risk():
    url = "https://api.securestate.vmware.com/v2/findings/query"
    
    payload = {
                "aggregations":{
                    "provider":{
                        "fieldName":"CloudProvider",
                        "aggregationType":"Terms",
                        "subAggregations":{
                                "findingsCount":{
                                    "fieldName":"ObjectXid",
                                        "aggregationType":"Terms",
                                        "termsCount":10,
                                            "subAggregations":{

                                            "AccountId":{
                                            "fieldName":"CloudAccountId",
                                                "aggregationType":"Terms",
                                            "subAggregations":{
                                                "riskSummary":{
                                                    "fieldName":"RiskScore",
                                                    "aggregationType":"Terms",
                                                        "subAggregations":{
                                                            "resourceName":{
                                                                "fieldName":"ObjectId",
                                                                "aggregationType":"Terms"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                },
                "filters":{
                    "status":"Open",
                    "descending":True
                    
                }
            }
    
    
    payload = add_payload_filters(payload, True, set_levels_filter=True)
    
    headers = {
        'Content-Type':'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    create_or_update_file("data/objects_risk_top_10.json", response)
    
def vss_trends():
    url = "https://api.securestate.vmware.com/v2/findings/trends-query"
    payload = {
            "filters":{
                "status":"Open"
            },
            "Interval":"month",
            "TopNThreshold":3
        }


    payload = add_payload_filters(payload, True, set_levels_filter=True)
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(access_token)
    }

    response = requests.post(url, data=json.dumps(payload), headers=headers)
    
    try:
        if(response.status_code !=200):
            raise ErrorStatusCode(str(response.status_code))
    except ErrorStatusCode:
            logging.error("Cannot generate report " + str(response.content) + "\n")
            sys.exit()
    
    create_or_update_file("data/trends.json", response)

def get_org_name():
    return get_config()["org_name"]

def get_account_info():

    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()
    
    with open("data/all_rules_info.json", "r") as rules_info:
        rules = json.load(rules_info)
    rules_info.close()
    
    with open("data/frameworks.json", "r") as frameworks_info:
        frameworks = json.load(frameworks_info)
    frameworks_info.close()
    
    with open("data/suppressed_findings.json", "r") as suppressed_info:
        suppressed_findings = json.load(suppressed_info)
    suppressed_info.close()
    

    dict_accounts = accounts["aggregations"]["accounts"]["buckets"]
    total_accounts = len(dict_accounts.keys())
    
    account_info = {
        "accounts": total_accounts,
        "rules": rules["totalCount"],
        "compliance_frameworks": frameworks["totalCount"],
        "total_violations": accounts["totalCount"],
        "suppressed_findings": suppressed_findings["totalCount"]
    }
    
    return account_info

def get_open_resolved_findings():
    
    with open("data/account_info.json", "r") as findings:
        open_findings = json.load(findings)
    findings.close()
    
    with open("data/resolved_findings.json", "r") as findings:
        resolved_findings = json.load(findings)
    findings.close()
    
    data = {
        "open": open_findings["totalCount"],
        "resolved": resolved_findings["totalCount"]
    }
    return data
    

def get_config():
    
    Config_file_name, report_file_name = parse_arguments()
    
    with open(Config_file_name) as config_file:
        configuration = json.load(config_file)
    config_file.close()
    
    return configuration


def get_findings_by_provider():
    
    with open("data/account_info.json", "r") as account_info:
        accounts = json.load(account_info)
    account_info.close()
    
    provider = []
    if("aws" in accounts["aggregations"]["find"]["buckets"]):
        if("count" in accounts["aggregations"]["find"]["buckets"]["aws"]):
            provider.append(accounts["aggregations"]["find"]["buckets"]["aws"]["count"])
        else:
            provider.append(0)
    
    if("azure" in accounts["aggregations"]["find"]["buckets"]):
        if("count" in accounts["aggregations"]["find"]["buckets"]["azure"]):
            provider.append(accounts["aggregations"]["find"]["buckets"]["azure"]["count"])
        else:
            provider.append(0)
        
    result = []
    result.append(provider)
    return result


def get_top_10_accounts_by_findings():
    
    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()
    
    with open("data/resolved_findings.json", "r") as output_file:
        findings = json.load(output_file)
    output_file.close()

    account_ids = []
    
    open_findings = []
    resolved_findings = []
    resolved_accounts = findings["aggregations"]["accounts"]["buckets"]
    open_accounts = accounts["aggregations"]["accounts"]["buckets"]
    sorted_open_accounts = dict(sorted(open_accounts.items(), key=lambda k_v:k_v[1]['count'], reverse=True))
    
    total_accounts = max(len(resolved_accounts.keys()), len(open_accounts))
    for open_account in sorted_open_accounts:
        if(open_account in resolved_accounts):
            resolved_findings.append(resolved_accounts[open_account]["count"])
            open_findings.append(sorted_open_accounts[open_account]["count"])
        else:
            resolved_findings.append(0)
            open_findings.append(sorted_open_accounts[open_account]["count"])
        ## @TODO - Change account ID logic with inventory service API    
        account_ids.append(open_account)
    
    return [open_findings],[resolved_findings], account_ids


def get_high_med_low_top_10_violations():
    
    with open("data/account_info.json", "r") as accounts_info:
        accounts = json.load(accounts_info)
    accounts_info.close()
    
    open_accounts = accounts["aggregations"]["accounts"]["buckets"]
    sorted_open_accounts = dict(sorted(open_accounts.items(), key=lambda k_v:k_v[1]['count'], reverse=True))
    
    high_sev = {}
    medium_sev = {}
    low_sev = {}
    aws_suppressed_findings = {}
    azure_suppressed_findings = {}
    aws_accounts_high_sev = {}
    azure_accounts_high_sev = {}
    aws_accounts_med_sev = {}
    azure_accounts_med_sev = {}
    aws_accounts_low_sev = {}
    azure_accounts_low_sev = {}
    
    if("high" in (level.lower() for level in get_config()["config"]["severity"])):
        with open("data/high_severity_top_10.json", "r") as severity_info:
            high_sev = json.load(severity_info)
        severity_info.close()
        if("aws" in high_sev["aggregations"]["cloud"]["buckets"]):
            aws_accounts_high_sev = high_sev["aggregations"]["cloud"]["buckets"]["aws"]["subAggregations"]["high"]["buckets"]
        if("azure" in high_sev["aggregations"]["cloud"]["buckets"]):
            azure_accounts_high_sev = high_sev["aggregations"]["cloud"]["buckets"]["azure"]["subAggregations"]["high"]["buckets"]
    
    
    if("medium" in (level.lower() for level in get_config()["config"]["severity"])):
        with open("data/medium_severity_top_10.json", "r") as severity_info:
            medium_sev = json.load(severity_info)
        severity_info.close()
            
        if("aws" in medium_sev["aggregations"]["cloud"]["buckets"]):
            aws_accounts_med_sev = medium_sev["aggregations"]["cloud"]["buckets"]["aws"]["subAggregations"]["medium"]["buckets"]
        if("azure" in medium_sev["aggregations"]["cloud"]["buckets"]):
            azure_accounts_med_sev = medium_sev["aggregations"]["cloud"]["buckets"]["azure"]["subAggregations"]["medium"]["buckets"]
    
    if("low" in (level.lower() for level in get_config()["config"]["severity"])):
    
        with open("data/low_severity_top_10.json", "r") as severity_info:
            low_sev = json.load(severity_info)
        severity_info.close()
    
        if("aws" in low_sev["aggregations"]["cloud"]["buckets"]):
            aws_accounts_low_sev = low_sev["aggregations"]["cloud"]["buckets"]["aws"]["subAggregations"]["low"]["buckets"]
        if("azure" in low_sev["aggregations"]["cloud"]["buckets"]):
            azure_accounts_low_sev = low_sev["aggregations"]["cloud"]["buckets"]["azure"]["subAggregations"]["low"]["buckets"]
    
    with open("data/suppressed_findings.json", "r") as suppressed_info:
        suppressed_findings = json.load(suppressed_info)
    suppressed_info.close()
    
    if("aws" in suppressed_findings["aggregations"]["cloud"]["buckets"]):
        aws_suppressed_findings = suppressed_findings["aggregations"]["cloud"]["buckets"]["aws"]["subAggregations"]["suppressed"]["buckets"]
    if("azure" in suppressed_findings["aggregations"]["cloud"]["buckets"]):
        azure_suppressed_findings = suppressed_findings["aggregations"]["cloud"]["buckets"]["azure"]["subAggregations"]["suppressed"]["buckets"]
       

    
    with open("data/resolved_findings.json", "r") as output_file:
        resolved_findings = json.load(output_file)
    output_file.close()

    final_result = []
    
    for account in sorted_open_accounts:
        high = "N/A"
        medium = "N/A"
        low = "N/A"
        suppressed = 0
        resolved = 0
            
        if (account in aws_accounts_high_sev):
            high = aws_accounts_high_sev[account]["count"]
            provider = "AWS"
        elif(account in aws_accounts_high_sev):
            high = azure_accounts_high_sev[account]["count"]
            provider = "Azure"
        if (account in aws_accounts_med_sev):
            medium = aws_accounts_med_sev[account]["count"]
            provider = "AWS"
        elif(account in azure_accounts_med_sev):
            medium = azure_accounts_med_sev[account]["count"]
            provider = "Azure"
        if (account in aws_accounts_low_sev):           
            low = aws_accounts_low_sev[account]["count"]         
            provider = "AWS"
        elif(account in azure_accounts_low_sev):
            low = azure_accounts_low_sev[account]["count"]
            provider = "Azure"
        if (account in aws_suppressed_findings):
            suppressed = aws_suppressed_findings[account]["count"]
            provider = "AWS"
        elif(account in azure_suppressed_findings):
            suppressed = azure_suppressed_findings[account]["count"]
            provider = "Azure"
        if(account in resolved_findings["aggregations"]["accounts"]["buckets"]):
            resolved = resolved_findings["aggregations"]["accounts"]["buckets"][account]["count"]            
            
        data = []
        data.append(provider)
        data.append(account)
        data.append(high)
        data.append(medium)
        data.append(low)
        data.append(suppressed)
        data.append(resolved)
        final_result.append(data)

    return final_result
    
def get_all_violations_by_severity():
    
    
    high = {}
    medium = {}
    low = {}
    
    aws_high = 0 
    azure_high = 0
    aws_med = 0 
    azure_med = 0    
    aws_low = 0 
    azure_low = 0 
    
    if("high" in (level.lower() for level in get_config()["config"]["severity"])):
        with open("data/high_severity.json", "r") as output_file:
            high = json.load(output_file)
        output_file.close()
        if("aws" in high["aggregations"]["cloud"]["buckets"]):
            if("count" in high["aggregations"]["cloud"]["buckets"]["aws"]):
                aws_high = high["aggregations"]["cloud"]["buckets"]["aws"]["count"]
            else:
                aws_high = 0
        if("azure" in high["aggregations"]["cloud"]["buckets"]):
            if("count" in high["aggregations"]["cloud"]["buckets"]["azure"]):   
                azure_high = high["aggregations"]["cloud"]["buckets"]["azure"]["count"]
            else:
                azure_high = 0
    
    if("medium" in (level.lower() for level in get_config()["config"]["severity"])):
        with open("data/medium_severity.json", "r") as output_file:
            medium = json.load(output_file)
        output_file.close()
        if("aws" in medium["aggregations"]["cloud"]["buckets"]):
            if("count" in medium["aggregations"]["cloud"]["buckets"]["aws"]):
                aws_med = medium["aggregations"]["cloud"]["buckets"]["aws"]["count"]
            else:
                aws_med = 0
        if("azure" in medium["aggregations"]["cloud"]["buckets"]):
            if("count" in medium["aggregations"]["cloud"]["buckets"]["azure"]):
                azure_med = medium["aggregations"]["cloud"]["buckets"]["azure"]["count"]
            else:
                azure_med = 0 
    
    if("low" in (level.lower() for level in get_config()["config"]["severity"])):
        with open("data/low_severity.json", "r") as output_file:
            low = json.load(output_file)
        output_file.close()
        if("aws" in low["aggregations"]["cloud"]["buckets"]):
            if("count" in low["aggregations"]["cloud"]["buckets"]["aws"]):
                aws_low = low["aggregations"]["cloud"]["buckets"]["aws"]["count"]
            else:
                aws_low = 0
        if("azure" in low["aggregations"]["cloud"]["buckets"]):
            if("count" in low["aggregations"]["cloud"]["buckets"]["azure"]):
                azure_low = low["aggregations"]["cloud"]["buckets"]["azure"]["count"]
            else:
                azure_low = 0
    
    aws = [aws_high, aws_med, aws_low]
    azure = [azure_high, azure_med, azure_low]
    
    return aws, azure
 
def get_top_10_rules():
    
    with open("data/all_rules_info.json", "r") as output_file:
        all_rules = json.load(output_file)
    output_file.close()
    
    with open("data/rules_info_top_10.json", "r") as output_file:
        rules = json.load(output_file)
    output_file.close()
    
    result = []
    top_10_rules = rules["aggregations"]["rules"]["buckets"]
    sorted_top_10_rules = dict(sorted(top_10_rules.items(), key=lambda k_v:k_v[1]['count'], reverse=True))
    
    for rule in sorted_top_10_rules:
        for item in all_rules["results"]:
            data = []
            if(item["id"]==rule):
                name = item["displayName"]
                provider = item["provider"]
                if(provider == "aws"):
                    provider = "AWS"
                elif(provider == "azure"):
                    provider = "Azure"
                object_type = item["service"]
                severity = item["level"]
                count = top_10_rules[rule]["count"]
                data.append(name)
                data.append(provider)
                data.append(object_type)
                data.append(severity)
                data.append(count)
                result.append(data)

    return result
                            
def get_top_10_objects_by_risk():
    with open("data/objects_risk_top_10.json", "r") as object_risks_info:
        objects_top_10 = json.load(object_risks_info)
    object_risks_info.close()
    
    aws_object_ids = []
    azure_object_ids = []
    result = []          
    
    if("aws" in objects_top_10["aggregations"]["provider"]["buckets"]):
        aws_object_ids = objects_top_10["aggregations"]["provider"]["buckets"]["aws"]["subAggregations"]["findingsCount"]["buckets"]
  
    if("azure" in objects_top_10["aggregations"]["provider"]["buckets"]):
        azure_object_ids = objects_top_10["aggregations"]["provider"]["buckets"]["azure"]["subAggregations"]["findingsCount"]["buckets"]

    for obj in aws_object_ids:
        data = []
        provider = "AWS"
        objectId = obj
        finding_data = aws_object_ids[obj]["subAggregations"]["AccountId"]["buckets"]
        account_id = list(finding_data)[0]
        count = finding_data[account_id]["count"]
        riskSummary = finding_data[account_id]["subAggregations"]["riskSummary"]["buckets"]
        score = 0
        for risk in list(riskSummary):
            score += int(risk) * riskSummary[risk]["count"]
            object_name = list(riskSummary[risk]["subAggregations"]["resourceName"]["buckets"].keys())[0]
        
        data.append(score)
        data.append(count)
        data.append(object_name)
        data.append(objectId)
        data.append(provider)
        data.append(account_id)
        result.append(data)
            
    for obj in azure_object_ids:
        data = []
        provider = "Azure"
        objectId = obj
        finding_data = azure_object_ids[obj]["subAggregations"]["AccountId"]["buckets"]
        account_id = list(finding_data)[0]
        count = finding_data[account_id]["count"]
        riskSummary = finding_data[account_id]["subAggregations"]["riskSummary"]["buckets"]
        score = 0
        for risk in list(riskSummary):
            score += int(risk) * riskSummary[risk]["count"]
            object_name = list(riskSummary[risk]["subAggregations"]["resourceName"]["buckets"].keys())[0]
        
        data.append(score)
        data.append(count)
        data.append(object_name)
        data.append(objectId)
        data.append(provider)
        data.append(account_id)
        result.append(data)
        
    result = sorted(result, key=itemgetter(0,1), reverse=True)
    result = result[0:9]
    return result

def get_open_findings_trends():
    with open("data/trends.json", "r") as trends_file:
        trends = json.load(trends_file)
    trends_file.close()
    
    open_findings = trends["results"]["Open"]["buckets"]
    
    result = []
    trend_month = []
    data = []
    for findings in open_findings:
        parse_date = parsers.datetime(findings).date().month 
        trend_month.append(calendar.month_abbr[parse_date])
        data.append(open_findings[findings]["count"])
    
    
    result.append(data)
            
    return result, trend_month

def get_new_resolved_trends():
    with open("data/trends.json", "r") as trends_file:
        trends = json.load(trends_file)
    trends_file.close()
    
    new_findings = trends["results"]["New"]["buckets"]
    resolved_findings = trends["results"]["Resolved"]["buckets"]
    
    result = []
    trend_month = []
    data = []
    for findings in new_findings:
        parse_date = parsers.datetime(findings).date().month
        trend_month.append(calendar.month_abbr[parse_date])
        if("count" in new_findings[findings]):
            data.append(new_findings[findings]["count"])
        else:
            data.append(0)
        
    result.append(data)
    data = []
    for findings in resolved_findings:
        if("count" in resolved_findings[findings]):
            data.append(resolved_findings[findings]["count"])
        else:
            data.append(0)
            
    result.append(data)
    
    return result, trend_month


# Sequentially makes API calls to Secure state to gather information and store it in a directory
def gather_data():
    
    logging.info("Checking to see if data directory exists\n")
    create_dir()
    logging.info("Gathering Account Info\n")
    vss_account_info()
    logging.info("Gathering All Rules Info\n")
    vss_all_rules()
    logging.info("Gathering Frameworks Info\n")
    vss_frameworks()
    logging.info("Gathering Open and Resolved Findings\n")
    vss_open_resolved_findings()
    logging.info("Gathering Top 10 Findings by severity\n")
    vss_high_med_low_top_10_findings()
    logging.info("Gathering Suppressed Findings\n")
    vss_suppressed_findings()
    logging.info("Gathering All Findings by severity\n")
    vss_all_violations_by_severity()
    logging.info("Gathering Top 10 Rules\n")
    vss_top_10_rules()
    logging.info("Gathering Top 10 Objects by Risk\n")
    vss_top_10_objects_by_risk()
    logging.info("Gathering Trends info\n")
    vss_trends()