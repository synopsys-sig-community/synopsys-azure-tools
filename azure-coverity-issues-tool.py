#!/usr/bin/python

import os
import sys
import argparse
import re
import ssl
import zlib
import base64


from urllib.parse import urlparse

from wscoverity import WebServiceClient, ConfigServiceClient, DefectServiceClient

def generateDefectReportForMergedDefect(defectService, mergedDefect, streamName, doHtml):
    defectReportHtml = ""

    cids = []
    cids.append(mergedDefect['cid'])
    streamDefects = []

    print(f"DEBUG: Get for {cid} and {streamName}")
    streamDefects = defectService.get_stream_defects(mergedDefect['cid'], [streamName])

    print(f"DEBUG: StreamDefects:")
    print(streamDefects)

    sd = streamDefects[0]
    di = sd['defectInstances'][0]
    for event in di.events:
        if event.main:
            break

    mainEvent = event
    mainFileId = mainEvent['fileId']

    fileId = event['fileId']

    # Find multiple-file events
    multiFileEvents = []
    mainFileEvents = []
    multiFileEventsByFile = dict()
    for event in di.events:
        if event['eventKind'] == "MULTI":
            multiFileEvents.append(event)
            if event['fileId']['filePathname'] not in multiFileEventsByFile:
                multiFileEventsByFile['filePathname'] = []
            multiFileEventsByFile['filePathname'].append(event)
        else:
            mainFileEvents.append(event)

    defectReportBuf = ""
    if (doHtml):
        defectReportBuf = "<span class=\"trough\">"
        defectReportBuf += "</span>"
        defectReportBuf += "<span class=\"filename\">"
        defectReportBuf += "From " + mainFileId['filePathname']
        defectReportBuf += ":<span>\n"
        defectReportBuf += "\n"
        defectReportBuf += generateDefectReportForEvents(defectService, sd, mainFileId, mainFileEvents, 0, doHtml)
    else:
        defectReportBuf = "From "
        defectReportBuf += mainFileId['filePathname']
        defectReportBuf += ":\n"
        defectReportBuf += "\n"
        defectReportBuf += generateDefectReportForEvents(defectService, sd, mainFileId, mainFileEvents, 0, doHtml)

    # TODO: Come back to related events

    print(f"DEBUG: defectReportBuf={defectReportBuf}")

    return


def decode_base64_and_inflate( b64string ):
    decoded_data = base64.b64decode( b64string )
    return zlib.decompress( decoded_data )


def deflate_and_base64_encode( string_val ):
    zlibbed_str = zlib.compress( string_val )
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode( compressed_string )


def inflateSourceFile(defectService, fileId, streamId):

    print("inflateSourceFile")
    print(streamId)

    fileContents = defectService.get_file_contents(streamId['name'], fileId)
    inflatedFileContents = str(decode_base64_and_inflate(fileContents['contents']))

    print(fileContents)
    print(inflatedFileContents)
    return ""


def generateDefectReportForEvents(defectService, sd, fileId, fileEvents, indent, doHtml, doMulti = False):
    defectReportBuf = ""

    indentStr = ""
    for i in range(0, indent, 1):
        indentStr += "    "

    mainFileContents = inflateSourceFile(defectService, fileId, sd['streamId'])

    return ""

# -----------------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Report on analysis results")
    parser.add_argument('--url', dest='url', help="Connect server URL");
    parser.add_argument('--build-url', dest='buildUrl', help="url to CI build", );
    parser.add_argument('--max-prior', dest='maxPrior', help="max prior outstanding defects to list", );
    parser.add_argument('--max-files', dest='maxFiles', help="max files analyzed to list", );

    group1 = parser.add_argument_group('required arguments')
    group1.add_argument('--dir', dest='dir', required=True, help="intermediate directory");
    group1.add_argument('--stream', dest='stream', required=True, help="STREAM containing recent analysis snapshot");

    args = parser.parse_args()

    cov_user = os.getenv("COV_USER")
    cov_passphrase = os.getenv("COVERITY_PASSPHRASE")

    o = urlparse(args.url)
    host = o.hostname
    port = str(o.port)
    scheme = o.scheme
    if scheme == "https":
        do_ssl = True
    else:
        do_ssl = False

    if host is None or port is None or cov_user is None or cov_passphrase is None:
        print("Must specify Connect server and authentication details on command line or configuration file")
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
        print("Error: unable to find " + commitLogFilepath)
        print("Ensure that cov-commit-defects output is redirected into a file")
        sys.exit(-1)

    sys.stdout.write("Searching " + commitLogFilepath + " for snapshot ID... ")
    snapshotId = None
    commitLog = open(commitLogFilepath, 'r')
    for line in commitLog:
        match = re.search('New snapshot ID (\S+) added', line)
        if match:
            snapshotId = match.group(1)
            break
    commitLog.close()

    if (snapshotId is not None):
        print("extracted snapshot " + snapshotId)
    else:
        print("Error: could not find snapshot")
        sys.exit(-1)

    print("Fetching information about stream " + args.stream)
    streamDOs = configServiceClient.get_stream(args.stream)
    assert(len(streamDOs) == 1)
    streamDO = streamDOs[0]
    print("  stream name: " + streamDO.id.name)
    triageStoreName = streamDO.triageStoreId.name
    print("  triage store: " + triageStoreName)

    projectDOs = configServiceClient.get_project(streamDO.primaryProjectId.name)
    assert(len(projectDOs) == 1)
    projectDO = projectDOs[0]
    print("  primary project: " + projectDO.id.name + " (id:" + str(projectDO.projectKey) + ")")

    defects_in_baseline = dict()
    defects_in_current = dict()

    previous_snapshot = int(snapshotId) - 1
    print(f"DEBUG: Looking in shapshot id {snapshotId} compared to {previous_snapshot}")

    # Get defects in current snapshot
    mergedDefectDOs = defectServiceClient.get_merged_defects_for_snapshot(args.stream, snapshotId)
    for md in mergedDefectDOs:
        if (md['cid'] not in defects_in_current):
            defects_in_current[md['cid']] = []
        defects_in_current[md['cid']].append(md)

    # Get defects in current snapshot
    mergedDefectDOs = defectServiceClient.get_merged_defects_for_snapshot(args.stream, str(previous_snapshot))
    for md in mergedDefectDOs:
        if (md['cid'] not in defects_in_baseline):
            defects_in_baseline[md['cid']] = []
        defects_in_baseline[md['cid']].append(md)

    # Calculate CIDs that are still present
    new_defects = dict()
    for cid in defects_in_current.keys():
        if (cid not in defects_in_baseline):
            new_defects[cid] = defects_in_current[cid]

    for cid in new_defects.keys():
        for md in new_defects[cid]:
            print(f"DEBUG: CID {cid} is unique")
            generateDefectReportForMergedDefect(defectServiceClient, md, args.stream, True)

