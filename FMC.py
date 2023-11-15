#! /Users/garlee2/API-Calls/venv/lib/python3.9
import requests, urllib3, json, base64
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""Script to interact with Firepower Management Center, requesting API keys and making a dummy network - SANDBOXED environment
	1) https://devnetsandbox.cisco.com/RM/Topology <<< Firepower Management System (Reserve)
	"""

##Global Variables Used
api_url = "https://fmcrestapisandbox.cisco.com/api/fmc_platform/v1/auth/generatetoken"
server = 'https://fmcrestapisandbox.cisco.com'
username = ""
password = ""
domain = "Global"
token = ""
headers = {
	'Content-Type': "application/json",
}


## Definition of Lab Network (192.168.0.0/24)
network_lab = {
	"name": "staticlab6",
	"value": "192.168.0.0/24",
	"overridable": False,
	"description": "Lab Network Object",
	"type": "Network"
}

def networkObject(network, uuid):
	""" Create a new Network Object """
	
	netpath = "/api/fmc_config/v1/domain/" + uuid + "/object/networks"
	url = server + netpath
	print("-------------------")
	print(headers)
	try:
		response = requests.post(url, data=json.dumps(network), headers=headers, verify=False)
		status_code = response.status_code
		resp = response.text
		json_response = json.loads(resp)
		print(response.headers)
		print("Status code is: " + str(status_code))
		if status_code == 201 or status_code == 202:
			print("Successfully created Network")
		else:
			response.raise_for_status()
		return json_response["name"], json_response["id"]
	except requests.exceptions.HTTPError as err:
		print("Reason Code: " + str(err))
	finally:
		if response:
			response.close()


# def showNetworkObject(network, uuid):
# 	""" Display all of the network objects under domain UUID """


# 	netpath = "/cpi/fmc_config/v1/domain" + uuid + "/networks"
# 	url = server + netpath
# 	try:
# 		response = requests.get(url, data=)



"""Two options, you can choose to pass encoded UN/PW or use HTTP Basic Auth to Request API Key, will be using BasicAuth in this script"""
def generateSessionToken():
	""" Generate the Session Token for FMC using basic HTTP Auth"""
	global uuid
	global headers
	response = requests.request(
		"POST",
		api_url,
		headers=headers,
		auth=requests.auth.HTTPBasicAuth(username, password),
		verify=False
	)
	auth_headers = response.headers
	token = auth_headers.get('X-auth-access-token', default=None)
	headers['X-auth-access-token'] = token
	domains = auth_headers.get('DOMAINS', default=None)
	domains = json.loads("{\"domains\":" + domains + "}")
	for item in domains["domains"]:
		if item["name"] == domain:
			uuid = item["uuid"]
		else:
			print("no UUID for the domain found!")
	print("Token is: " + token)






def generateSessionToken2():
	""""Generate the Session Token for FMC by passing encoded UN/PW"""
	global uuid
	global headers

	encoded = base64.b64encode((username + ":" + password).encode('UTF-8')).decode('ASCII')
	basic_encode = "Basic " + encoded

	headers = {
		'Content-Type': "application/xml",
		'Authorization': basic_encode
	}

	response = requests.request(
		"POST",
		api_url,
		headers=headers,
		verify=False
	)

	auth_headers = response.headers
	token = auth_headers.get('X-auth-access-token', default=None)
	headers['X-auth-access-token'] = token
	domains = auth_headers.get('DOMAINS', default=None)
	domains = json.loads("{\"domains\":" + domains + "}")
	for item in domains["domains"]:
		if item["name"] == domain:
			uuid = item["uuid"]
		else:
			print("no UUID for the domain found!")

	print("Token is: " + token)



## Main - Entry Point - Invoke Generate token and create network object
if __name__ == "__main__":
	generateSessionToken()
	networkObject(network_lab, uuid)
