#!/usr/bin/python
import json
import os
import sys
import argparse
import re
import ssl
import linecache
import zlib
import base64

import requests

import defectreport

from urllib.parse import urlparse
from wscoverity import WebServiceClient, ConfigServiceClient, DefectServiceClient

from types import SimpleNamespace
from azure.devops.credentials import BasicAuthentication
from azure.devops.connection import Connection
from azure.devops.v5_1.work_item_tracking.models import Wiql

def get_coverity_work_items(context):
    wit_client = context.connection.clients.get_work_item_tracking_client()
    wiql = Wiql(
        query="""
        select [System.Id],
            [System.WorkItemType],
            [System.Title],
            [System.State],
            [System.AreaPath],
            [System.IterationPath],
            [System.Tags]
        from WorkItems
        where [System.Title] CONTAINS 'Coverity'
        and [System.State] == 'Active'
        order by [System.ChangedDate] desc"""
    )
    # We limit number of results to 30 on purpose
    wiql_results = wit_client.query_by_wiql(wiql, top=20).work_items

    work_item_keys = dict()

    if wiql_results != None:
        # WIQL query gives a WorkItemReference with ID only
        # => we get the corresponding WorkItem from id
        work_items = (
            wit_client.get_work_item(int(res.id)) for res in wiql_results
        )
        for work_item in work_items:
          if (debug): print("DEBUG: Matching in title=" + work_item.fields["System.Title"])
          match = re.search('\[(................................)\]', work_item.fields["System.Title"])
          if match:
            finding_key = match.group(1)
            if (debug): print(f"DEBUG: Found key: {finding_key}")
            work_item_keys[finding_key] = 1

    return work_item_keys

def getAzWorkItems():
  accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
  SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')

  context = SimpleNamespace()
  context.runner_cache = SimpleNamespace()

  # setup the connection
  context.connection = Connection(
    base_url=SYSTEM_COLLECTIONURI,
    creds=BasicAuthentication('PAT', accessToken),
    user_agent='synopsys-azure-tools/1.0')

  work_items_exported = get_coverity_work_items(context)

  return work_items_exported


def createAzWorkItem(title, body, assignedTo, workItemType, issue):
  accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
  authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')
  escaped_body = json.dumps(body)

  azTags = "COVERITY;" + issue['checkerName']
  azAssignedTo = assignedTo
  azBugTitle = title
  azArea = ""
  azWorkItemType = "issue"

  azJsonPatches = []

  azJsonPatch = dict()
  azJsonPatch['op'] = "add"
  azJsonPatch['path'] = "/fields/System.Title"
  azJsonPatch['value'] = azBugTitle
  azJsonPatches.append(azJsonPatch)

  azJsonPatch = dict()
  azJsonPatch['op'] = "add"
  azJsonPatch['path'] = "/fields/System.Description"
  azJsonPatch['value'] = body
  azJsonPatches.append(azJsonPatch)

  #System.AssignedTo
  if (assignedTo != None):
      azJsonPatch = dict()
      azJsonPatch['op'] = "add"
      azJsonPatch['path'] = "/fields/System.AssignedTo"
      azJsonPatch['value'] = assignedTo
      azJsonPatches.append(azJsonPatch)

  azJsonPatch = dict()
  azJsonPatch['op'] = "add"
  azJsonPatch['path'] = "/fields/System.Tags"
  azJsonPatch['value'] = azTags
  azJsonPatches.append(azJsonPatch)

  azJsonPatch = dict()
  azJsonPatch['op'] = "add"
  azJsonPatch['path'] = "/relations/"
  azHyperlink = dict()
  azHyperlink['rel'] = "Hyperlink"
  azHyperlink['url'] = issue['url']

  #azJsonPatch = dict()
  #azJsonPatch['op'] = "add"
  #azJsonPatch['path'] = "/fields/System.AreaPath"
  #azJsonPatch['value'] = ""
  #azJsonPatches.append(azJsonPatch)

  azPost = json.dumps(azJsonPatches)
  if (debug): print("DEBUG: azPost = " + azPost)


  # Ad commensts to PR
  SYSTEM_COLLECTIONURI = os.getenv('SYSTEM_COLLECTIONURI')
  SYSTEM_PULLREQUEST_PULLREQUESTID = os.getenv('SYSTEM_PULLREQUEST_PULLREQUESTID')
  SYSTEM_TEAMPROJECT = os.getenv('SYSTEM_TEAMPROJECT')
  BUILD_REPOSITORY_ID = os.getenv('BUILD_REPOSITORY_ID')

  url = f"{SYSTEM_COLLECTIONURI}{SYSTEM_TEAMPROJECT}/_apis/wit/workitems/" \
          f"$" + azWorkItemType + "?api-version=6.0"

  headers = {
    'Content-Type': 'application/json-patch+json',
    'Authorization': 'Basic '+ authorization
  }

  if (debug): print("DEBUG: perform API Call to ADO" + url +" : " + json.dumps(azJsonPatches, indent = 4, sort_keys=True) + "\n")
  r = requests.post(url, json=azJsonPatches, headers=headers)

  if r.status_code == 200:
    print(f"INFO: Success exporting '{title}' to Azure Boards")
    if (debug):
        print(r.text)
    return r.json()
  else:
    print(f"ERROR: Failure exporting '{title}' to Azure Boards: Error {r.status_code}")
    print(r.text)

# -----------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Report on analysis results")
    parser.add_argument('--url', dest='url', help="Connect server URL");
    parser.add_argument('--debug', default=0, help='set debug level [0-9]')

    group1 = parser.add_argument_group('required arguments')
    group1.add_argument('--dir', dest='dir', required=True, help="intermediate directory");
    group1.add_argument('--stream', dest='stream', required=True, help="STREAM containing recent analysis snapshot");
    group1.add_argument('--coverity-json', dest='coverity_json', required=True, help="File containing coverity-json-v7 results");

    args = parser.parse_args()

    cov_user = os.getenv("COV_USER")
    cov_passphrase = os.getenv("COVERITY_PASSPHRASE")

    coverity_json = args.coverity_json

    o = urlparse(args.url)
    host = o.hostname
    port = str(o.port)
    scheme = o.scheme
    if scheme == "https":
        do_ssl = True
    else:
        do_ssl = False

    debug = args.debug

    if host is None or port is None or cov_user is None or cov_passphrase is None:
        print("ERROR: Must specify Connect server and authentication details on command line or configuration file")
        parser.print_help()
        sys.exit(-1)

    # TODO Properly handle self-signed certificates, but this is challenging in Python
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        # Legacy Python that doesn't verify HTTPS certificates by default
        pass
    else:
        # Handle target environment that doesn't support HTTPS verification
        ssl._create_default_https_context = _create_unverified_https_context

    defectServiceClient = DefectServiceClient(host, port, do_ssl, cov_user, cov_passphrase)
    configServiceClient = ConfigServiceClient(host, port, do_ssl, cov_user, cov_passphrase)

    commitLogFilepath = args.dir + os.sep + 'commit-log.txt'
    if (not os.path.isfile(commitLogFilepath)):
        print("ERROR: unable to find " + commitLogFilepath)
        print("Ensure that cov-commit-defects output is redirected into a file")
        sys.exit(-1)

    print(f"INFO: Searching " + commitLogFilepath + " for snapshot ID... ")
    snapshotId = None
    commitLog = open(commitLogFilepath, 'r')
    for line in commitLog:
        match = re.search('New snapshot ID (\S+) added', line)
        if match:
            snapshotId = match.group(1)
            break
    commitLog.close()

    if (snapshotId is not None):
        print("INFO: extracted snapshot " + snapshotId)
    else:
        print("ERROR: could not find snapshot")
        sys.exit(-1)

    if debug: print(f"DEBUG: Fetching information about stream " + args.stream)
    streamDOs = configServiceClient.get_stream(args.stream)
    assert(len(streamDOs) == 1)
    streamDO = streamDOs[0]
    if debug: print("  stream name: " + streamDO.id.name)
    triageStoreName = streamDO.triageStoreId.name
    if debug: print("  triage store: " + triageStoreName)

    projectDOs = configServiceClient.get_project(streamDO.primaryProjectId.name)
    assert(len(projectDOs) == 1)
    projectDO = projectDOs[0]
    if debug: print("  primary project: " + projectDO.id.name + " (id:" + str(projectDO.projectKey) + ")")


    defects_in_baseline = dict()
    defects_in_current = dict()

    previous_snapshot = int(snapshotId) - 1
    if debug: print(f"DEBUG: Looking in shapshot id {snapshotId} compared to {previous_snapshot}")

    # Get defects in current snapshot
    mergedDefectDOs = defectServiceClient.get_merged_defects_for_snapshot(args.stream, snapshotId)
    for md in mergedDefectDOs:
        if (md['cid'] not in defects_in_current):
            defects_in_current[md['cid']] = []
        defects_in_current[md['cid']].append(md)

    # Get defects in previous snapshot
    mergedDefectDOs = defectServiceClient.get_merged_defects_for_snapshot(args.stream, str(previous_snapshot))
    for md in mergedDefectDOs:
        if (md['cid'] not in defects_in_baseline):
            defects_in_baseline[md['cid']] = []
        defects_in_baseline[md['cid']].append(md)

    print(defects_in_baseline.keys())
    print(defects_in_current.keys())

    # Calculate CIDs that are still present
    new_defects = dict()
    for cid in defects_in_current.keys():
        if debug: print(f"DEBUG: Is CID {cid} in baseline?")
        if (cid not in defects_in_baseline):
            print(defects_in_current[cid])
            defect = defects_in_current[cid][0]
            mergeKey = defect['mergeKey']
            if debug: print(f"DEBUG:    mergeKey={mergeKey} not in baseline")
            new_defects[mergeKey] = defect

    # Process output from Polaris CLI
    with open(coverity_json) as f:
        data = json.load(f)

    print("INFO: Reading Coverity incremental analysis results from " + coverity_json)
    if (debug): print("DEBUG: " + json.dumps(data, indent=4, sort_keys=True) + "\n")

    azWorkItemsCreated = []

    for issue in data["issues"]:
        mergeKey = issue['mergeKey']
        main_file = issue['strippedMainEventFilePathname']
        if mergeKey in new_defects:
            if debug: print(f"DEBUG: mergeKey={issue['mergeKey']} in new_defects")

            work_items_exported = getAzWorkItems()

            if (mergeKey in work_items_exported):
                if (debug): print(f"DEBUG: Skipping finding key {mergeKey} becsause it has already been exported")
                continue

            md = new_defects[mergeKey]

            start_line = issue['mainEventLineNumber']

            events = issue['events']
            remediation = None
            main_desc = None
            for event in events:
                print(f"DEBUG: event={event}")
                if event['remediation'] == True:
                    remediation = event['eventDescription']
                if event['main'] == True:
                    main_desc = event['eventDescription']

            checkerProps = issue['checkerProperties']
            comment_body = f"<h3>Coverity found issue: {checkerProps['subcategoryShortDescription']} - CWE-{checkerProps['cweCategory']}, {checkerProps['impact']} Severity</h3>\n\n"

            if (main_desc):
                comment_body += f"<b>{issue['checkerName']}</b>: {main_desc} {checkerProps['subcategoryLocalEffect']}<p>\n\n"
            else:
                comment_body += f"<b>{issue['checkerName']}</b>: {checkerProps['subcategoryLocalEffect']}\n\n"

            if remediation:
                comment_body += f"<b>How to fix:</b> {remediation}<p>\n"

            comment_body += "<h3>Data Flow Path</h3>\n\n"

            # Build map of lines
            event_tree_lines = dict()
            event_tree_events = dict()
            for event in events:
                event_file = event['strippedFilePathname']
                event_line = int(event['lineNumber'])

                if event_file not in event_tree_lines:
                    event_tree_lines[event_file] = dict()
                    event_tree_events[event_file] = dict()

                event_line_start = event_line - 3
                if (event_line_start < 0): event_line_start = 0
                event_line_end = event_line + 3
                for i in range(event_line_start, event_line_end):
                    event_tree_lines[event_file][i] = 1

                if event_line not in event_tree_events[event_file]:
                    event_tree_events[event_file][event_line] = []

                event_tree_events[event_file][event_line].append(
                    f"{event['eventNumber']}. {event['eventTag']}: {event['eventDescription']}")

            if debug: print(f"DEBUG: event_tree_lines={event_tree_lines}")
            if debug: print(f"DEBUG: event_tree_events={event_tree_events}")

            for filename in event_tree_lines.keys():
                comment_body += f"<b>From {filename}:</b>\n"

                comment_body += "<pre>\n"
                for i in event_tree_lines[filename].keys():
                    if (i in event_tree_events[filename]):
                        for event_str in event_tree_events[filename][i]:
                            comment_body += f"{event_str}\n"

                    code_line = linecache.getline(filename, i)
                    comment_body += f"%5d {code_line}" % i

                comment_body += "</pre>\n"

            # Tag with merge key
            comment_body += f"<!-- Coverity {issue['mergeKey']} -->"

            if debug: print(f"DEBUG: comment_body={comment_body}")

            title = "Coverity - " + issue['checkerName'] +" in " + main_file + " [" + mergeKey + "]"
            assignedTo = ""
            workItemType = "Issue"

            dsaValues = md.defectStateAttributeValues
            owner = None
            for dsaValue in dsaValues:
                if dsaValue.attributeDefinitionId.name == "Owner":
                    owner = dsaValue.attributeValueId.name
                    if debug: print(f"DEBUG found owner={owner}")

            if debug: print(f"DEBUG: issue owner={owner}")

            # XXX For test environment ignore siguser username
            if owner == "siguser":
                owner = None
            if owner == "Unassigned":
                owner = None

            assignedTo = owner

            # Synthesize URL
            url = args.url + "/reports.htm#v10300/" + "p" + str(projectDO.projectKey) + "/mergedDefectId=" + str(defect['cid'])
            issue['url'] = url

            wi = createAzWorkItem(title, comment_body, assignedTo, workItemType, issue)
            azWorkItem = dict()
            azWorkItem['name'] = issue['checkerName']
            azWorkItemsCreated.append(azWorkItem)
        else:
            if debug: print(f"DEBUG: mergeKey={issue['mergeKey']} NOT in new_defects")

    if len(azWorkItemsCreated) > 0:
        print(f"INFO: Found new issues and exported work items, exiting with code 1")
        sys.exit(1)
