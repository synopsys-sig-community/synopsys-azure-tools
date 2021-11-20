#!/usr/bin/python

import json
import sys
import os
import argparse
import urllib
import glob
import requests
from requests_toolbelt.utils import dump
import base64

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Post Coverity issue summary to Azure Repos Pull Request Threads')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('mergeKeys', nargs=argparse.REMAINDER)
args = parser.parse_args()

debug = int(args.debug)
mergeKeys = args.mergeKeys

# Populate a map with the merge keys we want
mergeKeysToMatch = dict()
for mergeKey in mergeKeys:
    print("Match Merge Key: " + mergeKey)
    mergeKeysToMatch[mergeKey] = 1

#jsonFiles = glob.glob("./.synopsys/polaris/diagnostics/analyze,*/local-analysis/results/incremental-results.json")
jsonFiles  = glob.glob("./.synopsys/polaris/data/coverity/*/idir/incremental-results/incremental-results.json")
#jsonFiles = glob.glob("./incremental-results.json")
jsonFile = jsonFiles[0]

# Process output from Polaris CLI
with open(jsonFile) as f:
  data = json.load(f)

print("Reading incremental analysis results from " + jsonFile)
#if(debug): print("DEBUG: " + json.dumps(data, indent = 4, sort_keys=True) + "\n")

# Loop through found issues for specified merge keys, and build out output map
# TODO: Can there be multiple entries for the merge key? I think the right thing would be to list all of them.

sast_report = dict()
sast_report["version"] = "2.0"
vulnerabilities = []
azComments = []

for item in data["issues"]:
    checkerName = item["checkerName"]
    print("DEBUG: Checker " + checkerName)
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
    #if mergeKey in mergeKeysToMatch:
    # No longer need to filter by explicit merge keys, since Polaris can tell us what's new
    if 1:
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
url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/git/repositories/" \
  f"{BUILD_REPOSITORY_ID}/pullRequests/{SYSTEM_PULLREQUEST_PULLREQUESTID}" \
  "/threads?api-version=6.0"

accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')

headers = {
  'Accept': 'application/json',
  'Authorization': 'Basic '+ authorization
}

for comment in azComments:
  print("DEBUG: perform API Call to ADO" + url +" : " + json.dumps(comment, indent = 4, sort_keys=True) + "\n")
  r = requests.post(url=url, json=comment, headers=headers)
  if r.status_code == 200:
    print("DEBUG: Success")
  else:
    print("DEBUG: Failure")
    debugData = dump.dump_all(r)
    print("DEBUG: Data dump:\n" + debugData.decode('utf-8'))
    print(r.text)

