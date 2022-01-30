#!/usr/bin/python

import json
import re
import sys
import os
import argparse
import urllib
import glob
import requests
import base64

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description='Post Coverity issue summary to Azure Repos Pull Request Threads')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('--coverity-json', default='coverity-results.json', help='Coverity output JSON')

args = parser.parse_args()

debug = int(args.debug)

jsonFile = args.coverity_json

# Process output from Polaris CLI
with open(jsonFile, encoding='utf-8') as f:
    data = json.load(f)

print("INFO: Reading Coverity incremental analysis results from " + jsonFile)
if (debug): print("DEBUG: " + json.dumps(data, indent=4, sort_keys=True) + "\n")

# Get a list of all merge keys seen in analysis
seen_in_analysis = dict()
for issue in data["issues"]:
    seen_in_analysis[issue['mergeKey']] = 1

seen_in_comments = dict()

# Get list of open threads
# GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repositoryId}/pullRequests/{pullRequestId}/threads?api-version=6.0

SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')
SYSTEM_PULLREQUEST_PULLREQUESTID = os.getenv('SYSTEM_PULLREQUEST_PULLREQUESTID')
SYSTEM_TEAMPROJECT = os.getenv('SYSTEM_TEAMPROJECT')
BUILD_REPOSITORY_ID = os.getenv('BUILD_REPOSITORY_ID')
url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/git/repositories/{BUILD_REPOSITORY_ID}/pullRequests/{SYSTEM_PULLREQUEST_PULLREQUESTID}/threads?api-version=6.0"

accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')

headers = {
    'Accept': 'application/json',
    'Authorization': 'Basic ' + authorization
}

if (debug): print("DEBUG: perform API Call to ADO" + url + "\n")
r = requests.get(url=url, headers=headers)
if r.status_code == 200:
    if (debug): print("DEBUG: Success")
else:
    print(f"ERROR: Unable to get PR threads from Azure DevOps. Error code: {r.status_code}")
    print(r.text)
    sys.exit(1)

for thread in r.json()['value']:
    if debug: print(f"DEBUG: Thread={json.dumps(thread, indent=4, sort_keys=True)}")

    for comment in thread['comments']:
        match = re.search('<!-- Coverity (\S+) -->', comment['content'])
        if match:
            coverity_mk = match.group(1)
            seen_in_comments[coverity_mk] = 1
            if debug: print(f"DEBUG: Found Coverity comment for {coverity_mk}")
            if coverity_mk not in seen_in_analysis:
                print(f"DEBUG:  Not seen in analysis")

                url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/git/repositories/{BUILD_REPOSITORY_ID}/pullRequests/{SYSTEM_PULLREQUEST_PULLREQUESTID}/threads/{thread['id']}/comments/{comment['id']}?api-version=6.0"

                accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
                authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')

                headers = {
                  'Accept': 'application/json',
                  'Authorization': 'Basic ' + authorization
                }

                if (debug): print("DEBUG: perform API Call to ADO" + url + "\n")
                r = requests.delete(url=url, headers=headers)
                if r.status_code == 200:
                  if (debug): print("DEBUG: Success")
                else:
                  print(f"ERROR: Unable to Delete thread id={thread['id']} comment={comment['id']} from Azure DevOps. Error code: {r.status_code}")
                  print(r.text)
                  sys.exit(1)

####################

# Loop through found issues for specified merge keys, and build out output map
# TODO: Can there be multiple entries for the merge key? I think the right thing would be to list all of them.

sast_report = dict()
sast_report["version"] = "2.0"
vulnerabilities = []
azComments = []

for item in data["issues"]:

    if issue['mergeKey'] in seen_in_comments:
        if debug: print(f"DEBUG: Merge key {issue['mergeKey']} already seen in comments, do not create another comment")
        continue

    checkerName = item["checkerName"]
    checkerProperties = item["checkerProperties"]
    subcategoryShortDescription = checkerProperties["subcategoryShortDescription"]
    subcategoryLongDescription = checkerProperties["subcategoryLongDescription"]
    cwe = checkerProperties["cweCategory"]
    impact = checkerProperties["impact"]
    codeLangauge = item["code-language"]
    mergeKey = item["mergeKey"]
    strippedMainEventFilePathname = item["strippedMainEventFilePathname"]
    mainEventLineNumber = item["mainEventLineNumber"]


    eventNumber = 1
    description = None
    remediation = None
    start_line = 0
    location = dict()

    for event in item["events"]:
        if event["main"]:
            location["file"] = event["strippedFilePathname"]
            start_line = event["lineNumber"]
            description = event["eventDescription"]

        if event["remediation"]:
            remediation = event["eventDescription"]

    newComment = dict()

    comments = []
    comment = dict()
    comment["parentCommentId"] = 0
    comment["commentType"] = 1

    commentContent = ":warning: Coverity Static Analysis found this issue with your code:\n\n" + description + "\n\n[View the full issue report in Coverity](http://synopsys.com)"

    comment_body = f"**Coverity found issue: {checkerProperties['subcategoryShortDescription']} - CWE-{checkerProperties['cweCategory']}, {checkerProperties['impact']} Severity**\n\n"
    # BAD_CERT_VERIFICATION: The "checkServerIdentity" property in the "tls.connect()" function uses bad cert verification.
    #comment_body += f"**{checkerProps['subcategoryLocalEffect']}**\n\n"

    if (description):
        comment_body += f"**{issue['checkerName']}**: {description} {checkerProperties['subcategoryLocalEffect']}\n\n"
    else:
        comment_body += f"**{issue['checkerName']}**: {checkerProperties['subcategoryLocalEffect']}\n\n"

    if remediation:
        comment_body += f"**How to fix:** {remediation}\n"

    comment_body += f"\n<!-- Coverity {issue['mergeKey']} -->\n"

    comment["content"] = comment_body
    comments.append(comment)
    newComment["comments"] = comments

    threadContext = dict()

    rightFileEnd = dict()
    rightFileEnd["line"] = start_line
    rightFileEnd["offset"] = 1

    rightFileStart = dict()
    rightFileStart["line"] = start_line
    rightFileStart["offset"] = 1

    threadContext["filePath"] = "/" + location["file"]
    threadContext["rightFileEnd"] = rightFileEnd
    threadContext["rightFileStart"] = rightFileStart

    newComment["threadContext"] = threadContext

    newComment["status"] = "active"

    azComments.append(newComment)

# Ad commensts to PR
SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')
SYSTEM_PULLREQUEST_PULLREQUESTID = os.getenv('SYSTEM_PULLREQUEST_PULLREQUESTID')
SYSTEM_TEAMPROJECT = os.getenv('SYSTEM_TEAMPROJECT')
BUILD_REPOSITORY_ID = os.getenv('BUILD_REPOSITORY_ID')
url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/git/repositories/{BUILD_REPOSITORY_ID}/pullRequests/{SYSTEM_PULLREQUEST_PULLREQUESTID}/threads?api-version=6.0"

accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')

headers = {
    'Accept': 'application/json',
    'Authorization': 'Basic ' + authorization
}

for comment in azComments:
    if (debug): print(
        "DEBUG: perform API Call to ADO" + url + " : " + json.dumps(comment, indent=4, sort_keys=True) + "\n")
    r = requests.post(url=url, json=comment, headers=headers)
    if r.status_code == 200:
        if (debug): print("DEBUG: Success")
    else:
        print(f"ERROR: Unable to post PR comment to Azure DevOps. Error code: {r.status_code}")
        print(r.text)
        sys.exit(1)

# if (len(azComments) > 0):
#  print("INFO: New security weaknesses found, returning exit code 1 to break the build")
#  sys.exit(1)
