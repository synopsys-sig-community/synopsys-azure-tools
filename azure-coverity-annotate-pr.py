#!/usr/bin/python

import json
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
with open(jsonFile) as f:
  data = json.load(f)

print("INFO: Reading Coverity incremental analysis results from " + jsonFile)
if(debug): print("DEBUG: " + json.dumps(data, indent = 4, sort_keys=True) + "\n")

# Loop through found issues for specified merge keys, and build out output map
# TODO: Can there be multiple entries for the merge key? I think the right thing would be to list all of them.

sast_report = dict()
sast_report["version"] = "2.0"
vulnerabilities = []
azComments = []

for item in data["issues"]:
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
  description = ""
  start_line = 0
  location = dict();

  for event in item["events"]:
    if event["main"]:
      location["file"] = event["strippedFilePathname"]
      start_line = event["lineNumber"]
      description = description + "" + event["eventDescription"]

    if event["remediation"]:
      description = description + "\n\n" + event["eventDescription"]

  newComment = dict()

  comments = []
  comment = dict()
  comment["parentCommentId"] = 0
  comment["commentType"] = 1
  commentContent = ":warning: Coverity Static Analysis found this issue with your code:\n\n" + description + "\n\n[View the full issue report in Coverity](http://synopsys.com)"
  comment["content"] = commentContent
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
  'Authorization': 'Basic '+ authorization
}

for comment in azComments:
  if (debug): print("DEBUG: perform API Call to ADO" + url +" : " + json.dumps(comment, indent = 4, sort_keys=True) + "\n")
  r = requests.post(url=url, json=comment, headers=headers)
  if r.status_code == 200:
    if (debug): print("DEBUG: Success")
  else:
    print(f"ERROR: Unable to post PR comment to Azure DevOps. Error code: {r.status_code}")
    print(r.text)
    sys.exit(1)

if (len(azComments) > 0):
  print("INFO: New security weaknesses found, returning exit code 1 to break the build")
  sys.exit(1)