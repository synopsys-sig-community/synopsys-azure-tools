#!/bin/python
'''
Copyright (c) 2020 Synopsys, Inc. All rights reserved worldwide. The information
contained in this file is the proprietary and confidential information of
Synopsys, Inc. and its licensors, and is supplied subject to, and may be used
only by Synopsys customers in accordance with the terms and conditions of a
previously executed license agreement between Synopsys and that customer.

Purpose: get issues for a given project & branch

Requires:
pip install jsonapi_requests pandas

getIssues.py [-h] [--debug DEBUG] [--url URL] [--token TOKEN] --project PROJECT [--branch BRANCH] [--compare COMPARE]
             [--all | --opened | --closed | --untriaged | --bugs | --dismissed | --new | --fixed | --date DATE | --age AGE]
             [--spec SPEC] [--csv] [--html] [--email EMAIL]
             [--exit1-if-issues]

get issues for a given project & branch

optional arguments:
  -h, --help         show this help message and exit
  --debug DEBUG      set debug level [0-9]
  --url URL          Polaris URL
  --token TOKEN      Polaris Access Token
  --project PROJECT  project name
  --branch BRANCH    branch name
  --compare COMPARE  comparison branch name for new or fixed
  --all              all issues in project
  --opened           open issues (default)
  --closed           closed / fixed issues
  --untriaged        untriaged issues
  --bugs             to-be-fixed issues
  --dismissed        dismissed issues
  --new              new issues relative to comparison branch
  --fixed            fixed issues relative to comparison branch
  --date DATE        issues newer than date YYYY-MM-DDTHH:MM:SS
  --age AGE          issues older than AGE days
  --spec SPEC        report specification
  --csv              output to CSV
  --html             output to HTML
  --email EMAIL      comma delimited list of email addresses
  --azworkitem       cretae Azure Boards work items for issues matching criteria
  --msteams          notify users of issues via MS Teans for issues matching criteria
  --exit1-if-issues  exit with error code 1 if issues found

where SPEC is a comma delimited list of one or more of the following:
  projectId         project id
  branchId          branch id
  issue-key         issue key
  finding-key       finding key
  checker           checker aka subtool
  severity          severity
  type              issue type
  local_effect      local effect
  name              checker description
  description       description
  path              file path
  state             state (open/closed)
  status            triage status
  first_detected    date first detected on
  closed_date       date issue was closed
  age               days since issue first detected
  ttr               time to resolution in days
  url               URL to issue on Polaris


Examples:

list open issues:
python getIssues.py --project cs-polaris-api-scripts

list closed (fixed + dismissed) issues:
python getIssues.py --project cs-polaris-api-scripts --closed

list dismissed issues:
python getIssues.py --project cs-polaris-api-scripts --dismissed

list issues detected after 2021-05-01 and output to csv:
python getIssues.py --project cs-polaris-api-scripts --date 2021-05-01T00:00:00 --csv

list issues older than 30 days and display owner:
python getIssues.py --project cs-polaris-api-scripts --age 30 --spec path,checker,name,first_detected,owner,age

list new issues since previous scan and send as email:
python getIssues.py --project chuckaude-hello-java --branch new --new --email aude@synopsys.com

break the build if any new issues are detected:
python getIssues.py --project chuckaude-hello-java --branch new --exit1-if-issues

list fixed issues since previous scan and display time to resolution
python getIssues.py --project chuckaude-hello-java --branch fixed --fixed --spec path,checker,name,ttr

list new issues compared to master and fail the merge request with email:
python getIssues.py --project chuckaude-hello-java --branch merge-request --compare master \
    --new --email aude@synopsys.com --exit1-if-issues
'''

import sys
import os
import argparse
import jsonapi_requests
import requests
import polaris
import pprint
import json
import re
import base64
import base64
import hmac
import hashlib

import pandas as pd
pd.set_option('display.max_rows', 100000)
pd.set_option('display.max_columns', 50)
pd.set_option('display.width', 1000)
pd.set_option('display.max_colwidth', 300)

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# -----------------------------------------------------------------------------

def makeSignature(body, secret):
  signature = None
  secret_key = bytes(secret, 'utf-8')
  total_params = bytes(body, 'utf-8')
  signature = hmac.new(secret_key, total_params, hashlib.sha256).hexdigest()
  print("signature = {0}".format(signature))
  return signature

def createAzWorkItem(title, body, assignedTo, workItemType, issue):
  accessToken = os.getenv('SYSTEM_ACCESSTOKEN')
  authorization = str(base64.b64encode(bytes(':' + accessToken, 'ascii')), 'ascii')
  escaped_body = json.dumps(body)

  azTags = "COVERITY;" + issue['name']
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
  print("DEBUG: azPost = " + azPost)


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

  print("DEBUG: perform API Call to ADO" + url +" : " + json.dumps(azJsonPatches, indent = 4, sort_keys=True) + "\n")
  r = requests.post(url, json=azJsonPatches, headers=headers)

  if r.status_code == 200:
    print("DEBUG: Success")
    print("text")
    print(r.text)
    return r.json()
  else:
    print("DEBUG: Failure")
    print("url")
    print(r.request.url)
    print("headers")
    print(r.request.headers)
    print("body")
    print(r.request.body)
    print("method")
    print(r.request.method)
    print("status_code")
    print(r.status_code)
    print("text")
    print(r.text)



def getEventsWithSource(url, headers, findingId, runId):
    endpoint = url + '/api/code-analysis/v0/events-with-source'
    filterPath = ""
    params = dict([
        ('run-id',runId),
        ('finding-key',findingId),
        ('occurrence-number',1),
        ('filter-path',filterPath),
        ('max-depth',10),
        ('Accept-Language','en')
        ])

    r = requests.get(endpoint, headers=headers, params=params )

    if r.status_code == 200:
      print("DEBUG: Success")
      print("url")
      print(r.request.url)
      print(r.text)
      return r.json()['data'][0]
    else:
      print("DEBUG: Failure")
      print("url")
      print(r.request.url)
      print("headers")
      print(r.request.headers)
      print("body")
      print(r.request.body)
      print("method")
      print(r.request.method)
      print("status_code")
      print(r.status_code)
      print("text")
      print(r.text)
      return None

def getSource(url, headers, runId, path):
    print("DEBUG: getSource(" + url + ", headers, " + runId + ", " + path + ")")
    endpoint = url + '/api/code-analysis/v0/source-code'
    params = dict([
        ('run-id',runId),
        ('path',path)
        ])

    r = requests.get(endpoint, headers=headers, params=params )

    if r.status_code == 200:
      print("DEBUG: Success")
      print(r.text)
    else:
      print("DEBUG: Failure")
      print(r.text)

    return r.text

def send_email(receiver_email):

    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = os.getenv('SMTP_PORT')
    smtp_username = os.getenv('SMTP_USERNAME')
    smtp_password = os.getenv('SMTP_PASSWORD')
    sender_email = os.getenv('SENDER_EMAIL')
    if not all([smtp_server,smtp_port,smtp_username,smtp_password,sender_email]):
        print('FATAL: SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL must be set to send email')
        sys.exit(1)

    message = MIMEMultipart('alternative')
    message['Subject'] = 'issue report for ' + project + '/' + branch
    if new: message['Subject'] = 'new ' + message['Subject']
    if fixed: message['Subject'] = 'fixed ' + message['Subject']
    message['From'] = sender_email
    message['To'] = receiver_email

    # Create the plain-text and HTML version of your message
    text = str(df)
    html = '<html>\n<body>\n' + df.to_html(escape=False) + '\n</body>\n</html>\n'

    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(part1)
    message.attach(part2)

    try:
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        server.ehlo()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.close()
        print('email sent')
    except:
        print('email failure')

# -----------------------------------------------------------------------------

if __name__ == '__main__':

    url = os.getenv('POLARIS_SERVER_URL')
    token = os.getenv('POLARIS_ACCESS_TOKEN')

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='get issues for a given project & branch',
        epilog='''
where SPEC is a comma delimited list of one or more of the following:
  projectId         project id
  branchId          branch id
  issue-key         issue key
  finding-key       finding key
  checker           checker aka subtool
  severity          severity
  type              issue type
  local_effect      local effect
  name              checker description
  description       description
  path              file path
  state             state (open/closed)
  status            triage status
  first_detected    date first detected on
  closed_date       date issue was closed
  age               days since issue first detected
  ttr               time to resolution in days
  url               URL to issue on Polaris
        ''')
    parser.add_argument('--debug', default=0, help='set debug level [0-9]')
    parser.add_argument('--url', default=url, help='Polaris URL')
    parser.add_argument('--token', default=token, help='Polaris Access Token')
    parser.add_argument('--project', required=True, help='project name')
    parser.add_argument('--branch', default='master', help='branch name')
    parser.add_argument('--compare', help='comparison branch name for new or fixed')

    # issue filter options
    filter = parser.add_mutually_exclusive_group(required=False)
    filter.add_argument('--all', action='store_true', help='all issues in project')
    filter.add_argument('--opened', action='store_true', help='open issues (default)')
    filter.add_argument('--closed', action='store_true', help='closed / fixed issues')
    filter.add_argument('--untriaged', action='store_true', help='untriaged issues')
    filter.add_argument('--bugs', action='store_true', help='to-be-fixed issues')
    filter.add_argument('--dismissed', action='store_true', help='dismissed issues')
    filter.add_argument('--new', action='store_true', help='new issues relative to comparison branch')
    filter.add_argument('--fixed', action='store_true', help='fixed issues relative to comparison branch')
    filter.add_argument('--date', help='issues newer than date YYYY-MM-DDTHH:MM:SS')
    filter.add_argument('--age', help='issues older than AGE days')

    # output options
    parser.add_argument('--spec', default='path,checker,name,severity,first_detected', help='report specification')
    parser.add_argument('--csv', action='store_true', help='output to CSV')
    parser.add_argument('--html', action='store_true', help='output to HTML')
    parser.add_argument('--azworkitem', action='store_true', help='output to Azure Work Items')
    parser.add_argument('--msteams', action='store_true', help='output to MS Teams')
    parser.add_argument('--email', help='comma delimited list of email addresses')
    parser.add_argument('--exit1-if-issues', action='store_true', help='exit with error code 1 if issues found')
    parser.add_argument('--az-work-items', action='store_true', help='Export findings to Azure work items')

    args = parser.parse_args()

    polaris.debug = debug = int(args.debug)
    reportSpec = args.spec.split(',')
    if debug: print(args)

    if ((args.url == None) or (args.token == None)):
        print('FATAL: POLARIS_SERVER_URL and POLARIS_ACCESS_TOKEN must be set via environment variables or the CLI')
        sys.exit(1)


    # convert token to JWT and configure jsonapi_requests
    #polaris.token = polaris.getJwt(args.url, args.token)
    #polaris.api = polaris.configApi(args.url)
    polaris.baseUrl, polaris.jwt, polaris.session = polaris.createSession(args.url, args.token)

    projectId, branchId = polaris.getProjectAndBranchId(args.project, args.branch)
    if debug: print("projectId = " + projectId)
    if debug: print("branchId = " + branchId)

    if any(column in args.spec for column in ['owner','status','comment','jira','closed_data']):
        getTriage = True
    else: getTriage = False

    print("BEFORE GETRUNS")
    runs = polaris.getRuns(projectId, branchId)
    print("AFTER GETRUNS")
    currRunId = runs[0]['runId']

    if args.new or args.fixed: # run comparison use cmpIssuesForRuns
        code_snip_runid = currRunId

        if debug: print ('currRunId = ' + currRunId)
        if (args.compare == None):
            try: cmpRunId = runs[1]['runId']
            # if no previous run, compare with self
            except: cmpRunId = currRunId
        else:
            compareId = polaris.getBranchId(projectId, args.compare)
            if debug: print('compare = ' + args.compare + '\ncompareId = ' + compareId)
            print("BEFORE GETRUNS2")
            runs = polaris.getRuns(projectId, compareId)
            print("AFTER GETRUNS2")
            cmpRunId = runs[0]['runId']

            code_snip_runid = cmpRunId

        if debug: print ('cmpRunId = ' + cmpRunId)
        new_issues_df, fixed_issues_df = \
          polaris.cmpIssuesForRuns(projectId, currRunId, cmpRunId, getTriage)
        if args.new: issues = new_issues_df
        if args.fixed: issues = fixed_issues_df
    else: # no comparison, set a filter and use getIssues
        if args.all:
            filter = None
        elif args.closed:
            filter=dict([('filter[issue][status][eq]', 'closed')])
        elif args.untriaged:
            filter=dict([('filter[issue][triage-status][eq]','not-triaged')])
        elif args.bugs:
            filter=dict([('filter[issue][triage-status][eq]','to-be-fixed')])
        elif args.dismissed:
            filter=dict([('filter[issue][triage-status][in]',
                '[dismiss-requested,dismissed-false-positive,dismissed-intentional,dismissed-other]')])
        elif args.date:
            filter=dict([('filter[issue][status-opened-date][gte]', str(args.date) + 'Z')])
        else: # args.opened
            filter=dict([('filter[issue][status][eq]', 'opened')])
        if debug: print(filter)
        print("BEFORE GETISSUES")
        issues = polaris.getIssues(projectId, branchId, currRunId, polaris.MAX_LIMIT, filter, getTriage, True)
        print("AFTER GETISSUES")
    if (debug > 3):
        print(issues)

    # Loop through found issues
    print("=============\n")

    jwt = polaris.getJwt(args.url, args.token)
    headers = { 'Authorization' : 'Bearer ' + jwt, 'Content-Type' : 'application/vnd.api+json', 'Accept' : 'application/json' }

    if (len(issues)>0):
      notification_body = "# New Issues]\n"
      num_issues = str(len(issues))
      notification_body = "Coverity found " + num_issues + " in project **" + args.project + "** branch **" + args.branch + "**"
      notification_body = notification_body + "\n"

    if args.az_work_items:
        azWorkItemsCreated = []

        print("DEBUG: For each issue matching criteria...")
        print("==========")
        print(issues)
        print("==========")
        for issue in issues:
            print(issue)
            event_tree = getEventsWithSource(args.url, headers, issue['finding-key'], code_snip_runid)
            if (event_tree == None):
                print("DEBUG: Issue " + issue['finding-key'] + " not found in run " + code_snip_runid + ", skipping")
                continue
            events = event_tree['events']

            main_file = event_tree['main-event-file-path'][-1]
            main_loc = str(event_tree['main-event-line-number'])

            ticket_body = ""
            ticket_body = ticket_body + "<h3>Coverity - " + issue['name'] + " (CWE " + issue['cwe'] + ") in " +  main_file + "</h3>\n"
            ticket_body = ticket_body + issue['description'] + " " + issue['local_effect'] + "<br>"
            first_detected = str(issue['first_detected']) + "<br>"
            ticket_body = ticket_body + "The issue was first detected on " + first_detected + "<br>"
            ticket_body = ticket_body + "<br>"

            print("DEBUG: events=" + json.dumps(events, indent = 4, sort_keys=True))

            ## First sort events
            #events_sorted = len(events) * [None]
            #event_index = 0
            #for event in events:
            #    event_index = event['event-number'] - 1
            #    events_sorted[event_index] = event

            currentFile = ""
            for event in events:
                eventNumber = str(event['event-number'])
                if (event['path'][-1] == currentFile):
                    currentFile = event['path'][-1]
                else:
                    ticket_body = ticket_body + "From " + event['path'][-1] + ": <br>"
                    currentFile = event['path'][-1]
                currentFile = event['path'][-1]
                print("DEBUG: Event " + event['event-tag'] + " #" + eventNumber + " in " + event['filePath'])
                #sourceReturn = getSource(args.url, headers, code_snip_runid, event['filePath'])

                #if (event['event-tag'] == "remediation"):
                #    ticket_body = ticket_body + "#" + eventNumber + ": " + event['event-tag']
                #if (('source-before' in event and event['source-before']) or ('source-after' in event and event['source-after'])):
                #  ticket_body = ticket_body + "From " + event['path'][-1] + ":" + str(event['line-number']) + ": <br>"

                if ('source-before' in event and event['source-before']):
                    separate_lines = event['source-before']['source-code'].splitlines()
                    ticket_body = ticket_body + "<pre>\n"
                    current_line_no = event['source-before']['start-line']
                    for line in separate_lines:
                        pre_line = "%5d %s\n" % (current_line_no, line)
                        current_line_no = current_line_no + 1
                        ticket_body = ticket_body + pre_line
                    ticket_body = ticket_body + "\n</pre>\n"
                if (event['event-type'] == "MAIN"):
                    ticket_body = ticket_body + "<FONT COLOR=\"@ff0000\">" + "<b>" + "#" + eventNumber + ": " + event['event-tag'] + ": " + event['event-description'] + "</b>" + "</font><br>\n"
                elif (event['event-tag'] == "remediation"):
                    ticket_body = ticket_body + "<b>" + "#" + eventNumber + ": " + event['event-tag'] + ": " + event['event-description'] + "</b>" + "<br>\n"
                else:
                    ticket_body = ticket_body + "<b>" + "#" + eventNumber + ": " + event['event-tag'] + ": " + event['event-description'] + "</b><br>\n"
                if ('source-after' in event and event['source-after']):
                    separate_lines = event['source-after']['source-code'].splitlines()
                    ticket_body = ticket_body + "<pre>\n"
                    current_line_no = event['source-after']['start-line']
                    for line in separate_lines:
                        pre_line = "%5d %s\n" % (current_line_no, line)
                        current_line_no = current_line_no + 1
                        ticket_body = ticket_body + pre_line
                    ticket_body = ticket_body + "\n</pre>\n"

            print("DEBUG: ticket body=\n" + ticket_body)
            title = "Coverity - " + issue['name'] +"  in " + main_file
            assignedTo = ""
            workItemType = "Issue"

            wi = createAzWorkItem(title, ticket_body, assignedTo, workItemType, issue)
            azWorkItem = dict()
            azWorkItem['name'] = issue['name']
            azWorkItem['cwe'] = issue['cwe']
            azWorkItem['main_file'] = main_file
            azWorkItem['url'] = wi['_links']['html']['href']
            azWorkItemsCreated.append(azWorkItem)

            print(azWorkItemsCreated)
            print("EXIT EARLY...")
            #sys.exit(0)
            print("=============\n")

    # create a dataframe from issues dictionary
    df = pd.DataFrame(issues)

    # get issue count. exit if nothing returned
    count = len(df.index)
    if (count == 0):
        print ('no issues')
        sys.exit(0)

    # calculate mean ttr if reporting on only closed / fixed issues
    if ("ttr" in args.spec) and (args.closed or args.fixed):
        df["ttr_tmp"] = pd.to_numeric(df["ttr"], errors='coerce')
        mtr = pd.to_timedelta(df["ttr_tmp"].mean())
        print("\nMean time to resolution: " + str(mtr) + "\n")

    # convert age and ttr to days
    if ("age" in args.spec): df['age'] = df['age'].dt.floor('d')
    if ("ttr" in args.spec): df['ttr'] = df['ttr'].dt.floor('d')

    # link path to url
    if args.email or args.html: df['path'] = '<a href=' + df['url'] + '>' + df['path'] + '</a>'

    # limit to issues older than age if requested
    if args.age: df = df[df.age.dt.days > int(args.age)]

    # select what we want from the dataframe
    df = df[reportSpec]

    # display the report
    if args.csv: df.to_csv(sys.stdout)
    elif args.html: df.to_html(sys.stdout, escape=False)
    elif args.email: send_email(email)
    else: print(df)

    if args.exit1_if_issues: sys.exit(1)
    else: sys.exit(0)

# ---------------------------

