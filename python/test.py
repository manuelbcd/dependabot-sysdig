import requests
import os
import urllib.parse
import json

# Define urls
url_endpoint_github = "https://api.github.com/repos/manuelbcd/dependabot-sysdig/code-scanning/alerts"
url_endpoint_github_issues = "https://api.github.com/repos/manuelbcd/dependabot-sysdig/issues"
url_endpoint_sysdig = "https://us2.app.sysdig.com/api/scanning/eveintegration/v2/runtimeimages?clusterName=partner-demos"

from os import environ
required_env_vars = [
    'CODESCAN_GITHUB_SECRET',
    'SYSDIG_SECURE_API_TOKEN',
    'DOCKER_IMAGE',
    'CODESCAN_CATEGORY'
]

missing_vars = [var for var in required_env_vars if not environ.get(var)]
if missing_vars:
    for var in missing_vars:
        print(f"{var.replace('_', ' ').title()} is not defined in environment vars")
    exit(1)


github_bearer_token = os.getenv('CODESCAN_GITHUB_SECRET')
sysdig_bearer_token = os.getenv('SYSDIG_SECURE_API_TOKEN')
docker_image = os.getenv('DOCKER_IMAGE')
github_codescan_category = os.getenv('CODESCAN_CATEGORY')

inUseFound = False


## Sysdig Risk Spotlight requests for a given docker image
# Try to find a running container matching with our docker image name
headers_sysdig = {
    "Authorization": f"Bearer {sysdig_bearer_token}"
}

responseSysdig = requests.get(url_endpoint_sysdig, headers=headers_sysdig)

if responseSysdig.status_code == 200:
    response_data = responseSysdig.json()    

    # Initialize objects with the result
    sysdig_objects = []

    for item in response_data["data"]:
        if item["workloadName"] == "security-playground":
            for package in item["packages"]:
                #print(package["name"])
                sysdig_objects.append(package)
else:
    print("HTTP request error:", responseSysdig.status_code)
    exit(1)



## GitHub Code-Scanner alerts
# Get a list of code-scanner alerts from a given tool

headers_github = {
    "Authorization": f"Bearer {github_bearer_token}"
}

class Rule:
    def __init__(self, id, severity, description, name, executed):
        self.id = id
        self.severity = severity
        self.description = description
        self.name = name
        self.executed = executed

class CodeqlObject:
    def __init__(self, number, url, state, rule, html_url, message, path, tool):
        self.number = number
        self.url = url
        self.state = state
        self.html_url = html_url
        self.rule = rule
        self.message = message
        self.path = path
        self.tool = tool

response = requests.get(url_endpoint_github, headers=headers_github)

if response.status_code == 200:
    data = response.json()    

    # Initialize objects with the result
    codeql_objects = []

    for item in data:
        
        #print(item["number"] , " | " , item["rule"]["id"])

        # Check 
        #   if the category corresponds to our github-image<->sysdig-container
        #   AND if the package is in-use at runtime
        in_use = False
        for inuseObj in sysdig_objects:
            if item["most_recent_instance"]["category"] == github_codescan_category and inuseObj["name"] in item["rule"]["description"]:
                in_use = True

        rule_data = item["rule"]
        rule_obj = Rule(
            rule_data["id"],
            rule_data["severity"],
            rule_data["description"],
            rule_data["name"],
            in_use,
        )
        codeql_obj = CodeqlObject(
            item["number"],
            item["url"],
            item["state"],
            rule_obj,
            item["html_url"],
            item["most_recent_instance"]["message"]["text"],
            item["most_recent_instance"]["location"]["path"],
            item["tool"]["name"]
        )
        codeql_objects.append(codeql_obj)

else:
    print("HTTP request error:", response.status_code)
    exit(1)



####@@@@@@@@@@@@

for item in codeql_objects:
    if item.rule.executed == True:
        if inUseFound == False:
            print("In-Use vulnerabilities found: ")
            inUseFound = True
        print(item.number, " | " , item.rule.id, "| " , item.html_url)
        
        issueTitle = ("Vulnerability: " + str(item.rule.id) + " | " + str(item.rule.severity) + " | In-use at runtime")
        issueBody = ("<b>Image</b>: " + str(docker_image) + "<br><br><b>Tool</b>: " + str(item.tool) + "<br><b>Severity:</b> " + str(item.rule.severity) +"<br><br>" + str(item.message) + "<br><br><b>Path:</b>" + str(item.path)  + "<br><br>" + str(item.html_url))

        responseGithubIssue = requests.post(url_endpoint_github_issues, headers=headers_github, data=json.dumps({"title":issueTitle,"body":issueBody}))

        if not responseGithubIssue.status_code == 200:
            print("Error creating issue:", responseGithubIssue.status_code, responseGithubIssue.content)
        else:
            print("Issue created with success")
