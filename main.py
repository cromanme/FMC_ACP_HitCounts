# -*- coding: utf-8 -*-
__author__ = "Christian Méndez Murillo"
__email__ = "cmendezm@cisco.com"
__copyright__ = """
Copyright 2020, Cisco Systems, Inc. 
All Rights Reserved. 
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE. 
"""
__status__ = "Development"  # Prototype, Development or Production

import sys
import logging
import requests
import json
import csv

requests.packages.urllib3.disable_warnings()

logging.basicConfig(filename='app.log', 
                    filemode='w', 
                    format='%(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)


print()
uri = "https://127.0.0.1:9443/api/"
user = "apiadmin"
passwd = "BCP2019!"

# Request Authentication Token

url = uri + "fmc_platform/v1/auth/generatetoken"
response = requests.request("POST", url, auth=(user,passwd), verify=False)

token = response.headers.get("X-auth-access-token")
domain_uuid = response.headers.get("DOMAIN_UUID")

# Request Access Policies

url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/policy/accesspolicies"
headers = {
  'X-auth-access-token': token
}
response = requests.request("GET", url, headers=headers, verify=False)
acp_name = response.json().get("items")[0].get("name")
acp_id = response.json().get("items")[0].get("id")

# Request Device ID

url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/deviceclusters/ftddevicecluster"
headers = {
  'X-auth-access-token': token
}
parameters = {'expanded': "true"}
response = requests.request("GET", url, headers=headers, params=parameters, verify=False)
device_id = response.json().get("items")[0].get("masterDevice").get("id")

# Request ACP HitCounts

url = uri + "fmc_config/v1/domain/"+ domain_uuid +"/policy/accesspolicies/"+ acp_id +"/operational/hitcounts"
headers = {
  'X-auth-access-token': token
}
parameters = {'filter': '"deviceid:'+device_id+'"',
            'limit': '50',
            'expanded': 'true'
            }
response = requests.request("GET", url, headers=headers, params=parameters, verify=False)
rules = response.json().get("items")

# now we will open a file for writing 
data_file = open('data_file.csv', 'w') 

# create the csv writer object 
csv_writer = csv.writer(data_file) 

# Headers to the CSV file 

csv_headers = ["Rule Name", "firstHitTimeStamp", "lastHitTimeStamp", "HitCount"]
csv_writer.writerow(csv_headers) 
row = []

for rule in rules:
    row.append(rule.get("rule").get("name"))
    row.append(rule.get("firstHitTimeStamp"))
    row.append(rule.get("lastHitTimeStamp"))
    row.append(str(rule.get("hitCount")))
    csv_writer.writerow(row)
    row = []
  
data_file.close() 
