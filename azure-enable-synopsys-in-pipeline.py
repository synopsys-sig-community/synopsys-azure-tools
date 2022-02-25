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
import random
from datetime import date

import azure
import requests
from azure.devops.v6_0.git import GitPushRef, GitRefUpdate, GitPush, GitCommitRef, GitPullRequest

import defectreport

from urllib.parse import urlparse
from wscoverity import WebServiceClient, ConfigServiceClient, DefectServiceClient

from types import SimpleNamespace
from azure.devops.credentials import BasicAuthentication
from azure.devops.connection import Connection
from azure.devops.v5_1.work_item_tracking.models import Wiql

azure_access_token = ''

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


def azure_create_branch(base_url, access_token, repo, from_ref, branch_name):
  authorization = str(base64.b64encode(bytes(':' + access_token, 'ascii')), 'ascii')

  url = f"{base_url}/_apis/git/repositories/{repo.id}/refs?api-version=6.0"

  headers = {
    'Authorization': 'Basic '+ authorization
  }

  body = [
      {
          'name': f"refs/heads/{branch_name}",
          'oldObjectId': '0000000000000000000000000000000000000000',
          'newObjectId': from_ref
      }
  ]

  if (debug): print("DEBUG: perform API Call to ADO: " + url +" : " + json.dumps(body, indent = 4, sort_keys=True) + "\n")
  r = requests.post(url, json=body, headers=headers)

  if r.status_code == 200:
    print(f"INFO: Success creating branch")
    if (debug):
        print(r.text)
    return r.json()
  else:
    print(f"ERROR: Failure creating branch: Error {r.status_code}")
    print(r.text)


def azure_find_project(azure_connection, project_name):
    core_client = azure_connection.clients.get_core_client()
    projects = core_client.get_projects()

    for project in projects.value:
        if project.name == project_name:
            if debug: print(f"DEBUG: Found Project '{project.name}' id={project.id}")
            return project

    print(f"ERROR: Unable to find project '{project_name}")
    sys.exit(1)

def azure_find_repos(azure_connection, project, repo_name):
    core_client = azure_connection.clients.get_core_client()
    azure_git_client = azure_connection.clients.get_git_client()

    repos = azure_git_client.get_repositories(project.id)
    for repo in repos:
        if repo.name == repo_name:
            if debug: print(f"DEBUG: Found repo '{repo.name}'")
            return repo

    print(f"ERROR: Unable to find repo '{repo_name}' in project '{project.name}'")
    sys.exit(1)


def azure_get_refs(azure_connection, repo):
    azure_git_client = azure_connection.clients.get_git_client()

    refs = azure_git_client.get_refs(repo.id, repo.project.id)

    for ref in refs.value:
        if debug: print(f"DEBUG: Ref: {ref.name}: {ref.object_id}")

    return refs


def azure_get_file(azure_connection, repo, project, ref, scope_path):
    azure_git_client = azure_connection.clients.get_git_client()

    items = azure_git_client.get_items(repo.id, project=project.id, scope_path=scope_path, download=True)

    if len(items) == 0:
        print(f"ERROR: Did not receive any items from azure_git_client.get_items()")
        sys.exit(1)

    item = items[0]
    print(f"DEBUG: item={item}")

    download_url = item.url
    download_url = download_url.replace("versionType=Branch", "versionType=Commit")
    download_url += f"&version={ref}"
    print(f"INFO: Download '{scope_path}' from '{download_url}'")

    authorization = str(base64.b64encode(bytes(':' + azure_access_token, 'ascii')), 'ascii')

    headers = {
        'Authorization': 'Basic ' + authorization
    }

    r = requests.get(download_url, headers=headers)

    if r.status_code == 200:
        print(f"INFO: Success downloading file '{scope_path}'")
        if (debug):
            print(r.text)
        return r.text
    else:
        print(f"ERROR: Failure downloading file '{scope_path}': Error {r.status_code}")
        print(r.text)

    sys.exit(1)


def azure_commit_file(azure_connection, repo, project, branch, ref, filename, contents):
    azure_git_client = azure_connection.clients.get_git_client()

    gitRefUpdate = GitRefUpdate()
    gitRefUpdate.name = f"refs/heads/{branch}"
    gitRefUpdate.old_object_id = ref

    gitCommitRef = GitCommitRef()
    gitCommitRef.comment = "Added Synopsys pipeline template"
    gitCommitRef.changes = [
        {
            'changeType': 'edit',
            'item': {
                'path': filename
            },
            'newContent': {
                'content': contents,
                'contentType': 'rawText'
            }
        }
    ]

    gitPush = GitPush()
    gitPush.commits = [ gitCommitRef ]
    gitPush.ref_updates = [ gitRefUpdate ]

    push = azure_git_client.create_push(gitPush, repo.id, project=project.id)

    if not push:
        print(f"ERORR: Create push failed")
        sys.exit(1)

    return push


def azure_create_pull(azure_connection, repo, project, new_branch_name, to_branch, title, description):
    azure_git_client = azure_connection.clients.get_git_client()

    gitPullRequest = GitPullRequest()
    gitPullRequest.source_ref_name = f"refs/heads/{new_branch_name}"
    gitPullRequest.target_ref_name = f"refs/heads/{to_branch}"
    gitPullRequest.title = title
    gitPullRequest.description = description

    pull = azure_git_client.create_pull_request(gitPullRequest, repo.id, project=project.id)

    if not pull:
        print(f"ERROR: Create pull request failed")
        sys.exit(1)

    return pull


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Report on analysis results")
    parser.add_argument('--debug', default=0, help='set debug level [0-9]')

    group1 = parser.add_argument_group('required arguments')
    group1.add_argument('--template', dest='template', required=True, help="Configuration as code to APpend to azure-pipelines.yml")
    group1.add_argument('--template-pre', dest='template_pre', required=True, help="Configuration as code to PREpend to azure-pipelines.yml")
    group1.add_argument('--azure-url', dest='azure_url', required=True, help="Azure Base URL")
    group1.add_argument('--from-ref', dest='from_ref', required=True, help="Reference to branch from")
    group1.add_argument('--to-branch', dest='to_branch', required=True, help="Branch to submit change to")
    group1.add_argument('--project', dest='azure_project', required=True, help="Azure Project Name")
    group1.add_argument('--repo', dest='azure_repo', required=True, help="Azure Repo Name")

    azure_token = os.getenv("AZURE_API_TOKEN")
    if azure_token == None:
        print(f"ERROR: Must define AZURE_API_TOKEN")
        sys.exit(1)

    args = parser.parse_args()
    template = args.template
    template_pre = args.template_pre
    debug = args.debug
    azure_url = args.azure_url
    from_ref = args.from_ref
    to_branch = args.to_branch
    azure_project = args.azure_project
    azure_repo = args.azure_repo

    print(f"INFO: Preparing to on-board configuration template in '{template}' to '{azure_url}/_git/{azure_project}'")

    credentials = BasicAuthentication('', azure_token)
    azure_connection = azure.devops.connection.Connection(base_url=azure_url, creds=credentials)
    azure_access_token = azure_token

    if debug: print(f"DEBUG: Connected to Azure DevOps at '{azure_url}'")

    # Get a client (the "core" client provides access to projects, teams, etc)
    azure_git_client = azure_connection.clients.get_git_client()

    project = azure_find_project(azure_connection, azure_project)
    repo = azure_find_repos(azure_connection, project, azure_repo)
    refs = azure_get_refs(azure_connection, repo)

    if debug: print(f"DEBUG: repo={repo}")

    new_branch_seed = '%030x' % random.randrange(16 ** 30)
    new_branch_name = f"synopsys-enablement-{new_branch_seed}"

    print(f"INFO: Creating new ref 'refs/heads/{new_branch_name}'")
    azure_create_branch(azure_url, azure_token, repo, from_ref, new_branch_name)

    azure_pipelines_contents = azure_get_file(azure_connection, repo, project, from_ref, "/azure-pipelines.yml")
    azure_pipelines_contents_new = azure_pipelines_contents

    print(azure_pipelines_contents_new)

    today = date.today()
    if (template_pre):
        with open(template_pre) as template_pre_file:
            template_pre_lines = template_pre_file.readlines()
        azure_pipelines_contents_new = f"\n\n# Synopsys configuration template added on {today}\n\n" + "".join(template_pre_lines) + "\n\n" + azure_pipelines_contents

    azure_pipelines_contents_new += f"\n\n# Synopsys configuration template added on {today}\n\n"
    with open(template) as template_file:
        template_lines = template_file.readlines()
    azure_pipelines_contents_new += "".join(template_lines)

    if debug: print(f"DEBUG: New azure-pipelines.yml contains:\n\n{azure_pipelines_contents_new}")

    push = azure_commit_file(azure_connection, repo, project, new_branch_name, from_ref, "/azure-pipelines.yml",
                             azure_pipelines_contents_new)

    print(f"INFO: Committed changes to branch {new_branch_name}")

    pull = azure_create_pull(azure_connection, repo, project, new_branch_name, to_branch, "Enable Synopsys Security Testing", "Enable Synopsys Security Testing")

    print(f"INFO: Successfully created pull request: {pull.url}")



