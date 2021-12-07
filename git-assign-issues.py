#!/usr/bin/python
'''
Copyright (c) 2020 Synopsys, Inc. All rights reserved worldwide. The information
contained in this file is the proprietary and confidential information of
Synopsys, Inc. and its licensors, and is supplied subject to, and may be used
only by Synopsys customers in accordance with the terms and conditions of a
previously executed license agreement between Synopsys and that customer.

Purpose: uses git blame info to automatically assign defects

Requires:
pip install requests pandas

Usage:
gitAssignDefects.py [-h] [--debug DEBUG] --url URL --token TOKEN --project PROJECT
             --branch BRANCH

arguments:
  -h, --help         show this help message and exit
  --debug DEBUG      set debug level [0-9]
  --url URL          Polaris URL
  --token TOKEN      Polaris Access Token
  --project PROJECT  project name
  --branch BRANCH    branch name
'''

import sys
import os
import argparse
from os.path import exists

import polaris
import pandas as pd
pd.set_option('display.max_rows', 100000)
pd.set_option('display.max_columns', 50)
pd.set_option('display.width', 1000)

import subprocess
import re
import time
from shutil import which

# -----------------------------------------------------------------------------

def findOwnerEmail(line, filepath):
    line_range = str(line) + ',' + str(line)

    if (not exists(filepath)):
        print(f"WARNING: File '{filepath}' does not exist")
        return None, None

    try:
        output = subprocess.check_output(['git', 'blame', '-p', '-L', line_range, filepath])
    except subprocess.CalledProcessError as grepexc:
        print(f"WARNING: Git blame failed: {grepexc}")
        return None, None

    author_email = None
    author_name = None

    for line in output.splitlines():
        line = str(line)
        if 'author-mail' in line:
            sline = line.split()
            author_email = re.sub('[<>\']', '', sline[1]) if sline[1] else None
            if author_email is None:
                print('WARNING: No owner found for line ' + str(line) + ' in file ' + filepath)
            break
        if 'author ' in line:
            sline = line.split(" ", 1)
            author_name = re.sub('[<>\']', '', sline[1]) if sline[1] else None
            if author_name is None:
                print('WARNING: No owner found for line ' + str(line) + ' in file ' + filepath)
            break

    if debug: print(f"DEBUG: findOwnerEmail returning {author_email} and {author_name}")
    return author_email, author_name

# -----------------------------------------------------------------------------

if __name__ == '__main__':

    git_ex = which('git')
    git_root = os.path.exists('.git')
    if not git_ex or not git_root:
        print('ERROR: no git executable was found on your path, or the current working directory is missing the .git folder.')
        sys.exit(1)

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description='Automatically assign issues based on git blame info')
    parser.add_argument('--debug', default=0, help='set debug level [0-9]')
    parser.add_argument('--url', default=os.getenv('POLARIS_SERVER_URL'), help='Polaris URL')
    parser.add_argument('--token', default=os.getenv('POLARIS_ACCESS_TOKEN'), help='Polaris Access Token')
    parser.add_argument('--project', required=True, help='project name')
    parser.add_argument('--branch', default='master', help='branch name')
    parser.add_argument('--force', action='store_true', help='force reassignment if already assigned')
    parser.add_argument('--dry-run', action='store_true', help='test assignment without changing anything')
    args = parser.parse_args()

    polaris.debug = debug = int(args.debug)
    dry_run = args.dry_run
    if debug: print(args)

    if ((args.url == None) or (args.token == None)):
        print('FATAL: POLARIS_SERVER_URL and POLARIS_ACCESS_TOKEN must be set via environment variables or the CLI')
        sys.exit(1)

    # convert token to JWT and create a requests session
    polaris.baseUrl, polaris.jwt, polaris.session = polaris.createSession(args.url, args.token)

    projectId, branchId = polaris.getProjectAndBranchId(args.project, args.branch)
    if debug: print("DEBUG: projectId = " + projectId)
    if debug: print("DEBUG: branchId = " + branchId)

    # get enabled user accounts
    filter=([('filter[users][enabled]', 'true')])
    start = time.time()
    users = pd.DataFrame(polaris.getUsers(None, filter, False))
    end = (time.time() - start)
    if debug: print("DEBUG: Total time taken by getUsers: " + str(end))
    if (debug): print(users)

    start = time.time()
    runs = polaris.getRuns(projectId, branchId, polaris.MAX_LIMIT)
    end = (time.time() - start)
    if debug: print("DEBUG: Total time taken by getRuns: " + str(end))
    runId = runs[0]['runId']
    issues = polaris.getIssues(projectId, branchId, runId, polaris.MAX_LIMIT, None, True, True)
    if (debug > 5): print(issues)

    if dry_run:
        print('~~~~~~~~DRY RUN~~~~~~~~')
    count = 0
    start = time.time()
    for issue in issues:
        if (debug): print(f"DEBUG: Issue checker={issue['checker']} owner={issue['owner']}")
        if issue['owner'] == 'Unassigned' or issue['owner'] == None or args.force:
            if (debug): print(f"DEBUG: Find owner for {issue['path']}:{issue['line']}")
            email, name = findOwnerEmail(issue['line'], issue['path'])
            if email is None and name is None:
                print('WARNING: No blame info found for line ' + str(issue['line']) + ' at path ' + str(issue['path']))
                continue

            # Try by user ID first
            try:
                userid = users.loc[users['email'] == email]['id'].values[0]
                username = users.loc[users['email'] == email]['username'].values[0]
            except:
                try:
                    userid = users.loc[users['name'] == name]['id'].values[0]
                    username = users.loc[users['name'] == name]['username'].values[0]
                except:
                    print('WARNING: no User ID found in Polaris, skipping...')
                    continue

            print('INFO: Setting defect ' + str(issue['issue-key'] + ' to owner ' + username))
            triage_dict = {'OWNER': userid}
            if not dry_run:
                try:
                    response = polaris.setTriage(projectId, issue['issue-key'], triage_dict)
                except Exception as e:
                    print(f"ERROR: Error setting triage: {e}")
                    polaris.printError(e)
            count += 1

    end = (time.time() - start)
    if debug: print(f"INFO: Total time taken by setTriage (all issues): " + str(end))

    print('INFO: Finished assigning ownership for ' + str(count) + ' issues.')
    if dry_run:
        print('~~~~~~~~DRY RUN~~~~~~~~')

    sys.exit(0)

