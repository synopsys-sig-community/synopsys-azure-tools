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

debug = 0

def generateDefectReportForMergedDefect(defectService, mergedDefect, streamName, doHtml):
    defectReportHtml = ""

    cids = []
    cids.append(mergedDefect['cid'])
    streamDefects = []

    if debug: print(f"DEBUG: Get for {cid} and {streamName}")
    streamDefects = defectService.get_stream_defects(mergedDefect['cid'], [streamName])

    if debug: print(f"DEBUG: StreamDefects:")
    if debug: print(streamDefects)

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
        #defectReportBuf += "\n"
        defectReportBuf += generateDefectReportForEvents(defectService, sd, mainFileId, mainFileEvents, 0, doHtml)
    else:
        defectReportBuf = "From "
        defectReportBuf += mainFileId['filePathname']
        defectReportBuf += ":\n"
        #defectReportBuf += "\n"
        defectReportBuf += generateDefectReportForEvents(defectService, sd, mainFileId, mainFileEvents, 0, doHtml)

    # TODO: Come back to related events

    if debug: print(f"DEBUG: generateDefectReportForMergedDefect: defectReportBuf={defectReportBuf}")

    return defectReportBuf

    return


def decode_base64_and_inflate( b64string ):
    decoded_data = base64.b64decode( b64string )
    return zlib.decompress( decoded_data )


def deflate_and_base64_encode( string_val ):
    zlibbed_str = zlib.compress( string_val )
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode( compressed_string )


def inflateSourceFile(defectService, fileId, streamId):

    fileContents = defectService.get_file_contents(streamId['name'], fileId)
    if fileContents == None:
        print("ERROR: Unable to get file contents for streamId={streamId['name'] and fileId={fileId['filePathname']}")
        sys.exit(1)

    inflatedFileContents = decode_base64_and_inflate(fileContents['contents'])

    return inflatedFileContents


def generateSourceMap(fileContents):
    sourceMap = dict()

    sourceByLine = fileContents.split("\n")
    for i in range(0, len(sourceByLine), 1):
        if debug: print(f"DEBUG: Line {i}: {sourceByLine[i]}")
        sourceMap[i] = sourceByLine[i]

    return sourceMap

def generateDefectReportForEvents(defectService, sd, fileId, fileEvents, indent, doHtml, doMulti = False):
    defectReportBuf = ""

    indentStr = ""
    for i in range(0, indent, 1):
        indentStr += "    "

    mainFileContents = inflateSourceFile(defectService, fileId, sd['streamId'])

    sourceMap = generateSourceMap(mainFileContents.decode("utf-8"))

    eventsForLine = dict()
    pathEventsForLine = dict()
    modelFilenames = []
    modelIndentStrs = []
    modelCodeForLine = dict()
    linesToPrint = dict()

    if debug: print(f"DEBUG: generateDefectReportForEvents() looping through events")
    for event in fileEvents:
        if debug: print(f"DEBUG: event={event}")
        if event['eventKind'] == "NORMAL":
            if (debug): print("DEBUG: Event {event['eventTag']} is NORMAL")
            if (event['lineNumber'] not in eventsForLine):
                eventsForLine[event['lineNumber']] = []
            if event['main']:
                if (debug): print("DEBUG: Event {event['eventTag']} is main")
                mainEventStr = f"CID {sd['cid']} ({sd['checkerName']})"
                eventsForLine[event['lineNumber']].append(mainEventStr)

            if (event['eventNumber'] == 0):
                eventStr = f"{event['eventDescription']}"
            else:
                eventStr = f"{event['eventNumber']}. {event['eventDescription']}"
            eventsForLine[event['lineNumber']].append(eventStr)

            lineNumber = event['lineNumber']
            if debug: print(f"DEBUG: lineNumber={lineNumber} len(sourceMap)={len(sourceMap)}")
            startLine = lineNumber - 4
            if startLine < 1: startLine = 1
            endLine = lineNumber + 3
            if endLine > len(sourceMap): endLine = len(sourceMap)
            if debug: print(f"DEBUG: startLine={startLine} endLine={endLine}")

            for i in range(startLine, endLine, 1):
                linesToPrint[i] = True
        elif event['eventKind'] == "MODEL":
            if (debug):
                if debug: print("DEBUG: Event {event['eventTag']} is MODEL")

                if (event['lineNumber'] not in eventsForLine):
                    eventsForLine[event['lineNumber']] = []

                if event['main']:
                    if (debug): print("DEBUG: Event {event['eventTag']} is main")
                    mainEventStr = f"CID {sd['cid']} ({sd['checkerName']})"
                    eventsForLine[event['lineNumber']].append(mainEventStr)

                eventStr = f"{event['eventNumber']}. {event['eventTag']}: {event['eventDescription']}"
                eventsForLine[event['lineNumber']].append(eventStr)

                if len(event['events']) > 0:

                    if event['lineNumber'] not in modelCodeForLine:
                        modelCodeForLine[event['lineNumber']] = []

                    modelFilename = event['events'][0]['fileId']['filePathname']
                    modelFilenames.append(modelFilename)
                    modelIndentStrs.append(indentStr)

                    eventStr = generateDefectReportForEvents(defectService, sd, event['events'][0]['fileId'], event['events'], indent + 1, doHtml)
                    modelCodeForLine[event['lineNumber']].append(eventStr)

                    lineNumber = event['lineNumber']
                    if debug: print(f"DEBUG: lineNumber={lineNumber} len(sourceMap)={len(sourceMap)}")
                    startLine = lineNumber - 4
                    if startLine < 1: startLine = 1
                    endLine = lineNumber + 3
                    if endLine > len(sourceMap): endLine = len(sourceMap)
                    if debug: print(f"DEBUG: startLine={startLine} endLine={endLine}")

                    for i in range(startLine, endLine, 1):
                        linesToPrint[i] = True

        elif event['eventKind'] == "PATH":
            if (debug): print("DEBUG: Event {event['eventTag']} is NORMAL")
            if (event['lineNumber'] not in eventsForLine):
                eventsForLine[event['lineNumber']] = []

            eventStr = f"{event['eventNumber']}. {event['eventDescription']}"
            eventsForLine[event['lineNumber']].append(eventStr)

            lineNumber = event['lineNumber']
            if debug: print(f"DEBUG: lineNumber={lineNumber} len(sourceMap)={len(sourceMap)}")
            startLine = lineNumber - 4
            if startLine < 1: startLine = 1
            endLine = lineNumber + 3
            if endLine > len(sourceMap): endLine = len(sourceMap)
            if debug: print(f"DEBUG: startLine={startLine} endLine={endLine}")

            for i in range(startLine, endLine, 1):
                linesToPrint[i] = True

        elif event['eventKind'] == "MULTI":
            if (debug):
                print("DEBUG: Event {event['eventTag']} is MULTI")
                sys.exit(1)

        elif event['eventKind'] == "REMEDIATION":
            if (debug): print("DEBUG: Event {event['eventTag']} is REMEDIATION")
            if (event['lineNumber'] not in eventsForLine):
                eventsForLine[event['lineNumber']] = []

            eventStr = f"How to fix: {event['eventDescription']}"
            eventsForLine[event['lineNumber']].append(eventStr)

            lineNumber = event['lineNumber']
            if debug: print(f"DEBUG: lineNumber={lineNumber} len(sourceMap)={len(sourceMap)}")
            startLine = lineNumber - 4
            if startLine < 1: startLine = 1
            endLine = lineNumber + 3
            if endLine > len(sourceMap): endLine = len(sourceMap)
            if debug: print(f"DEBUG: startLine={startLine} endLine={endLine}")

            for i in range(startLine, endLine, 1):
                linesToPrint[i] = True
        else:
            if (debug): print("DEBUG: Event {event['eventTag']} is DEFAULT")
            sys.exit(1)

    if (debug):
        print(f"DEBUG: eventsForLine={eventsForLine}")
        print(f"DEBUG: linesToPrint={linesToPrint}")


    # Print ellipsis if we don't have a first line
    if 1 not in linesToPrint:
        if doHtml:
            defectReportBuf += f"<span class=\"trough\">{indentStr}</span>...\n"
        else:
            defectReportBuf += f"{indentStr}...\n"

    for lineNumber in linesToPrint.keys():
        # Print normal events first
        if lineNumber in eventsForLine:
            for eventForLine in eventsForLine[lineNumber]:
                if doHtml:
                    defectReportBuf += f"<span class=\"trough\">{indentStr}</span><span class=\"event\">{eventForLine}</span>\n"
                else:
                    defectReportBuf += f"{indentStr}{eventForLine}\n"

        # Print path events second
        if lineNumber in pathEventsForLine:
            for eventForLine in pathEventsForLine[lineNumber]:
                if doHtml:
                    defectReportBuf += f"<span class=\"trough\">{indentStr}</span><span class=\"path\">{eventForLine}</span>\n"
                else:
                    defectReportBuf += f"{indentStr}{eventForLine}\n"

        # Print line of code
        if doHtml:
            lineNumberStr = "<b>%5d</b>&nbsp;\n" % lineNumber
            defectReportBuf += f"<span class=\"trough\">{indentStr}{lineNumberStr}</span>{sourceMap[lineNumber]}\n"
        else:
            lineNumberStr = "%5d" % lineNumber
            defectReportBuf += f"{indentStr}{lineNumberStr} {sourceMap[lineNumber]}\n"

        # if modelCodeForLine
        if lineNumber in modelCodeForLine:
            for modelEventForLine in modelCodeForLine[lineNumber]:
                modelFilename = modelFilenames.pop()
                modelIndentStr = modelIndentStrs.pop()
                indenStr = modelIndentStr

                if doHtml:
                    defectReportBuf += f"<span class=\"trough\">{indentStr}</span><span class=\"filename\">From {modelIndentStr}{modelFilename}:</span>\n"
                else:
                    defectReportBuf += f"{modelIndentStr}From {modelFilename}:\n"

                defectReportBuf += f"{modelEventForLine}\n"

                if debug: print(f"DEBUG: end of modelCodeForLine {defectReportBuf}")

        # Print ellipsis if there is a gap in coverage
        if (lineNumber != len(sourceMap) and (lineNumber + 1) not in linesToPrint):
            if doHtml: defectReportBuf += f"{indentStr}<b>...</b>\n"
            else: defectReportBuf += f"{indentStr}...\n"

    if (debug):
        print(f"DEBUG: eventsForLine={eventsForLine}")
        print(f"DEBUG: linesToPrint={linesToPrint}")

    return defectReportBuf