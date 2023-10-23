import requests
import requests

# Define urls
url_endpoint_github = "https://api.github.com/repos/manuelbcd/dependabot-sysdig/code-scanning/alerts"
url_endpoint_sysdig = "https://us2.app.sysdig.com/api/scanning/eveintegration/v2/runtimeimages?clusterName=partner-demos"

github_bearer_token = "<GITHUB-TOKEN>"
sysdig_bearer_token = "<SYSDIG-TOKEN>"

headers_github = {
    "Authorization": f"Bearer {github_bearer_token}"
}
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


# -----
    


# Definir la clase Rule
class Rule:
    def __init__(self, id, severity, description, name, executed):
        self.id = id
        self.severity = severity
        self.description = description
        self.name = name
        self.executed = executed

# Definir la clase CodeqlObject
class CodeqlObject:
    def __init__(self, number, url, state, rule):
        self.number = number
        self.url = url
        self.state = state
        self.rule = rule

response = requests.get(url_endpoint_github, headers=headers_github)

if response.status_code == 200:
    data = response.json()    

    # Initialize objects with the result
    codeql_objects = []

    for item in data:
        
       #print(item["number"] , " | " , item["rule"]["id"])
        in_use = False
        for inuseObj in sysdig_objects:
            if inuseObj["name"] in item["rule"]["description"]:
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
            rule_obj
        )
        codeql_objects.append(codeql_obj)

else:
    print("HTTP request error:", response.status_code)
    exit(1)



####@@@@@@@@@@@@

for item in codeql_objects:
    if item.rule.executed == True:
        print(item.number, " | " , item.rule.id)
