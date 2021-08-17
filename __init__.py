#!/usr/bin/python3

#from _typeshed import SupportsItemAccess
import json
import requests
from flask import Flask, request
import urllib3
import datetime


urllib3.disable_warnings()

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return "Hello World :-)"

@app.route("/webhook", methods=["POST"])
def webhook():

    #parse data from webhook
    targetIp = request.json['event']['target_ip']
    targetIp = str(targetIp)

    try:
        targetName = request.json['event']['target_hostname']
        targetName = str(targetName)
    except KeyError:
        targetName = "unknown"

    #write host to log
    #logData = "Webhook received: " + str(targetIp)
    logData = 'test'
    writeLog(logData)

    #assign values to dict
    newHost = {}
    newHost['name'] = targetName + "-" + targetIp
    newHost['value'] = targetIp
    newHost['apikey'] = gettoken()

    #create new host
    newHost = createHost(newHost)

    #get current group members
    groupMembers = getGroup(newHost)

    #add new host to group
    newGroupMember = {"type": "Host", "id": newHost['id'], "name": newHost['name']}
    groupMembers.append(newGroupMember)

    updateGroup(groupMembers, newHost)

    return "success"

def gettoken():
    #sends basic credentials to FMC and receives token

    #define request details
    url = "https://fmc.sankey.io/api/fmc_platform/v1/auth/generatetoken"
    payload = {}
    headers = {'Authorization': 'Basic YXBpOkMhc2NvMTIzNDU2Nw=='}

    #make api request
    response = requests.request("POST", url, headers=headers, data=payload, verify=False)

    #verify successful request
    if response.status_code == 204:
        #parse key from response header
        head = response.headers
        token = head["X-auth-access-token"]

        return token

    else:
        logData = "Error retrieving API key: " + response.text
        writeLog(logData)

def createHost(newHost):
    #creates new host object from webhook data

    #define request details
    url = "https://fmc.sankey.io/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts"
    payload = json.dumps({
        "name": newHost['name'],
        "type": "Host",
        "value": newHost['value'],
        "description": "This host was created by the stealthwatch automation integration"
    })
    headers = {
        'x-auth-access-token': newHost['apikey'],
        'Content-Type': 'application/json'
    }

    #make api request
    response = requests.request("POST", url, headers=headers, data=payload, verify=False)

    #verify request was successful
    if response.status_code == 201:

        #parse new host id from response
        response = response.json()
        hostId = response['id']
        hostId = str(hostId)
        newHost['id'] = hostId

        return newHost

    else:
        logData = "Error creating host: " + response.text
        writeLog(logData)
        quit()

def getGroup(newHost):
    #get existing group members

    #define request details
    url = "https://fmc.sankey.io/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/000D3A3A-EE99-0ed3-0000-004294968227"
    payload = ""
    headers = {'x-auth-access-token': newHost['apikey']}

    #make api request
    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    #verify successful request
    if response.status_code == 200:

        #parse existing group members from response
        groupMembers = response.json()
        groupMembers = groupMembers['objects']

        return groupMembers

    else:
        logData = "Error retrieving group: " + response.text
        writeLog(logData)

def updateGroup(groupMembers, newHost):
    #updates group with existing members + new host

    #define request details
    url = "https://fmc.sankey.io/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/000D3A3A-EE99-0ed3-0000-004294968227"
    payload = json.dumps({
        "id": "000D3A3A-EE99-0ed3-0000-004294968227",
        "name": "malicious_ips",
        "type": "NetworkGroup",
        "objects": groupMembers
    })
    headers = {
        'x-auth-access-token': newHost['apikey'],
        'Content-Type': 'application/json'
    }

    #make api request
    response = requests.request("PUT", url, headers=headers, data=payload, verify=False)

    #verify successful request
    if response.status_code == 200:

        logData = "Group successfully updated with new host"
        writeLog(logData)

    else:
        logData = "Error updating group: " + response.text
        writeLog(logData)

def writeLog(logData):

    #get date/time
    now = datetime.datetime.now()
    now = now.strftime("%Y-%m-%d %H:%M:%S  ")
   
    #writes data to a logfile
    logData = str(logData)
    logData = now + logData
    output = open("/var/www/flaskapps/ddc/webapp.log", "a")
    output.write(logData)
    output.write("\n")
    output.close()

if __name__ == "__main__":
    app.run(host='0.0.0.0')

