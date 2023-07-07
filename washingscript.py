import sys
import traceback
import zipfile
from array import *
import re as regEx
import random
import socket
import struct
import ipaddress
import subprocess
import os
from datetime import datetime
import time
import logging


# Regex strings for all it should search for in the files
ipv4Pattern = regEx.compile(r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]'
                            r'[0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|'
                            r'1[0-9]{2}|[1-9][0-9]|[0-9])')

ipv6Pattern = regEx.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:)'
                            r'{1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]'
                            r'{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
                            r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4})'
                            r'{1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::'
                            r'(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|'
                            r'(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9])'
                            r'{0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')

imsiPattern = regEx.compile(r'[0-9]{13,17}')

imsiHexPattern = regEx.compile(r'(IMSI :   { |IMSI : )(\d{2}\ |\d[A-Z]\ |[A-Z]\d\ )(\d{2}\ |\d[A-Z]\ |[A-Z]\d\ )'
                               r'(\d{2}\ |\d[A-Z]\ |[A-Z]\d\ )(\d{2}\ |\d[A-Z]\ |[A-Z]\d\ )(\d{2}\ |\d[A-Z]\ |'
                               r'[A-Z]\d\ )(\d{2}\ |\d[A-Z]\ |[A-Z]\d\ )(\d{2}\ |\d[A-Z]\ |[A-Z]\d\ )(\d{2}\ |'
                               r'\d[A-Z]\ |[A-Z]\d\ )(\d{2}|\d[A-Z]|[A-Z]\d)')

macPattern = regEx.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})')

hostnamePattern = regEx.compile(r'(?i)epcgw')

usernamePattern = regEx.compile(r'(?i)serviceuser')

urlPattern = regEx.compile(r'(?i)splunk')

hostnameMatches = {}

usernameMatches = {}

urlMatches = {}


# Dictionaries and lists for all matches found during the washing
ipv4AddressMatches = {}
ipv6AddressMatches = {}
imsiMatches = {}
imsiHexMatches = {}
macMatches = {}
urlFound = []
hostnameFound = []
usernameFound = []

# Different variables needed throughout the script
inboxLocation = '/nfs/data/inbox/'
folderLocation = '/nfs/data/'
tmpLocation = '/nfs/data/tmp/'
folder_dt = datetime.now()
dt_string = folder_dt.strftime('%y-%m-%d-%H.%M')
outboxLocation = folderLocation + '/outbox/'
outboxDirname = 'washed-' + dt_string
outboxDir = folderLocation + '/outbox/' + outboxDirname
tmpDir = tmpLocation + outboxDirname
script_log = '/nfs/data/cron-script.log'
washing_log = '/local/scramble/washing-script/log/washing-script.log'
zipEnd = '.zip'
zipLogEnd = '.log.zip'
gzEnd = '.gz'
gzLogEnd = '.log.gz'
tarEnd = '.tar'
tarLogEnd = '.log.tar'
targzEnd = '.tar.gz'
targzLogEnd = '.log.tar.gz'


def replaceCharsInTuple(tuple):
    try:
        # Clean up IP-addresses in tuple and return as string
        tupleToReturn = tuple.replace(',', '.').replace('(', '').replace(')', '').replace(' ', '').replace('\'', '')
        return ''.join(tupleToReturn)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def replaceIpv6Tuple(tuple):
    try:
        ipv6TupleToReturn = tuple[0]
        return ipv6TupleToReturn
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def InsertSpaceInTupleImsiHex(tuple):
    try:
        # Clean up IMSI hex in tuple and return as string
        tupleToReturn = tuple.replace(',', '').replace('(', '').replace(')', '').replace('\'', '') \
            .replace('IMSI : ', '').replace('IMSI :   { ', '').replace(':', '').replace('{', '').replace('   ', '') \
            .replace('  ', ' ')
        return ''.join(tupleToReturn)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def checkIfIpv4ExistsAndReplace(match):
    try:
        # If match not found in dictionary, generate a new IPv4 address with the first two octates as x
        if ipv4AddressMatches.get(match) == None:
            ipv4List = ['x', 'x']
            ipv4List.append(str(random.randint(1, 255)))
            ipv4List.append(str(random.randint(1, 255)))
            ipv4AddressMatches[match] = '.'.join(ipv4List)
        return ipv4AddressMatches.get(match)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def checkIfIpv6ExistsAndReplace(match):
    try:
        # If match not found in dictionary, generate a new IPv6 address
        false_ipv6 = regEx.compile(r'[a-fA-F]{1,3}::|::[a-fA-F]{1,3}| ::|:: | :: ')
        false_match = regEx.findall(false_ipv6, match)
        socket_match = socket.inet_pton(socket.AF_INET6, match)
        if True:
            if match != '::':
                if len(false_match) == 0:
                    if ipv6AddressMatches.get(match) == None:
                        ipv6AddressMatches[match] = ipaddress.IPv6Address(
                            random.randint(0, 2 ** 128 - 1))  # Add random IPv6
                    return ipv6AddressMatches.get(match)
                if len(false_match) <= 1:
                    ipv6AddressMatches[match] = false_match[0]
                    return ipv6AddressMatches.get(match)
            if match == '::':
                ipv6AddressMatches[match] = '::'
                return ipv6AddressMatches.get(match)
        if False:
            ipv6AddressMatches[match] = false_match[0]
            return ipv6AddressMatches.get(match)

    except socket.error:
        ipv6AddressMatches[match] = false_match[0]
        return ipv6AddressMatches.get(match)

def checkIfMacExistsAndReplace(match):
    try:
        # If match not found in dictionary, generate a new mac address
        if macMatches.get(match) == None:
            macMatches[match] = '%02x:%02x:%02x:%02x:%02x:%02x' % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255))
        return macMatches.get(match)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def checkIfImsiExistsAndReplace(match):
    try:
        # If match not found in dictionary, generate a new random number with xxxxxx in front
        if imsiMatches.get(match) == None:
            imsiList = ['xxxxx']
            imsiList.append(str(random.randint(1000000000, 9999999999)))
            imsiMatches[match] = ''.join(imsiList)
        return imsiMatches.get(match)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def checkIfImsiHexExistsAndReplace(match):
    try:
        # If match not found in dictionary, generate a new random number with xx on part of the hex
        if imsiHexMatches.get(match) == None:
            imsiHexList = ['xx ', 'xx ', 'xx ', 'xx ']
            imsiHexList.append(str(random.randint(10, 99)) + ' ' + str(random.randint(10, 99)) + ' ' +
                               str(random.randint(10, 99)) + ' ' + str(random.randint(10, 99)) + ' ' +
                               str(random.randint(0, 9)) + 'F')
            imsiHexMatches[match] = str(''.join(imsiHexList))
        return imsiHexMatches.get(match)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def checkIfHostnameExistsAndReplace(match):
    try:
        # If match not found in dictionary, replace it. If found replace item listed in the dictionary
        if hostnameMatches.get(match) == None:
            logger.warning(current_time() + ' - !!!!!!!!!!' + match + ' not found in hostname list!!!!!!!!!!\n'
                                                                       'Match removed from file')
            hostnameMatches[match] = str('xxxxxxx')
        return hostnameMatches.get(match)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def checkIfUsernameExistsAndReplace(match):
    try:
        # If match not found in dictionary, replace it. If found replace item listed in the dictionary
        if usernameMatches.get(match) == None:
            usernameMatches[match] = str('xxxxxxxxx')
        return usernameMatches.get(match)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def checkIfUrlExistsAndReplace(match):
    try:
        # If match not found in dictionary, replace it. If found replace item listed in the dictionary
        if urlMatches.get(match) == None:
            logger.warning(current_time() + ' - !!!!!!!!!!' + match + ' not found in URL list!!!!!!!!!!\n'
                                                                       'Match removed from file')
            urlMatches[match] = str('xxxxx')
        return urlMatches.get(match)
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def current_time():
    return time.strftime('%d-%m-%y %H:%M:%S', time.localtime())

logging.basicConfig(filename=washing_log,
                    format='%(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def wash_filename(item):
    try:
        global washed_filename
        current_filename = str(item)
        filename_ipv4Match = regEx.findall(ipv4Pattern, item)
        filename_ipv6Match = regEx.findall(ipv6Pattern, item)
        filename_imsiMatch = regEx.findall(imsiPattern, item)
        filename_imsiHexMatch = regEx.findall(imsiHexPattern, item)
        filename_hostnameMatch = regEx.findall(hostnamePattern, item)
        filename_macMatch = regEx.findall(macPattern, item)
        filename_usernameMatch = regEx.findall(usernamePattern, item)
        filename_urlMatch = regEx.findall(urlPattern, item)
        filename_ipv4Array = []
        filename_ipv6Array = []
        filename_imsiArray = []
        filename_imsiHexArray = []
        filename_macArray = []
        filename_hostnameArray = []
        filename_usernameArray = []
        filename_urlArray = []
        for i in range(len(filename_ipv4Match)):
            filename_ipv4Array.append(replaceCharsInTuple(str(filename_ipv4Match[i])))
        for i in range(len(filename_ipv6Match)):
            filename_ipv6Array.append(replaceIpv6Tuple(filename_ipv6Match[i]))
        for i in range(len(filename_macMatch)):
            filename_macArray.append(filename_macMatch[i])
        for i in range(len(filename_imsiMatch)):
            filename_imsiArray.append(filename_imsiMatch[i])
        for i in range(len(filename_imsiHexMatch)):
            filename_imsiHexArray.append(InsertSpaceInTupleImsiHex(str(filename_imsiHexMatch[i])))
        for i in range(len(filename_hostnameMatch)):
            filename_hostnameArray.append(filename_hostnameMatch[i])
        for i in range(len(filename_usernameMatch)):
            filename_usernameArray.append(filename_usernameMatch[i])
        for i in range(len(filename_urlMatch)):
            filename_urlArray.append(filename_urlMatch[i])
        for ipv4 in filename_ipv4Array:
            replacedIpv4Address = checkIfIpv4ExistsAndReplace(ipv4)
            new_filename = item.replace(ipv4, replacedIpv4Address)
            washed_filename = new_filename  # Overwrite current filename with new filename
        for ipv6 in filename_ipv6Array:
            replacedIpv6Address = checkIfIpv6ExistsAndReplace(ipv6)
            new_filename = item.replace(ipv6, str(replacedIpv6Address))
            washed_filename = new_filename  # Overwrite current filename with new filename
        for mac in filename_macArray:
            replacedMacAddress = checkIfMacExistsAndReplace(mac.lower())
            new_filename = item.replace(mac, replacedMacAddress)
            washed_filename = new_filename  # Overwrite current filename with new filename
        for imsi in filename_imsiArray:
            replacedImsiAddress = checkIfImsiExistsAndReplace(imsi)
            new_filename = item.replace(imsi, replacedImsiAddress)
            washed_filename = new_filename  # Overwrite current filename with new filename
        for imsiHex in filename_imsiHexArray:
            replacedImsiHexAddress = checkIfImsiHexExistsAndReplace(imsiHex)
            new_filename = item.replace(imsiHex, replacedImsiHexAddress)
            washed_filename = new_filename  # Overwrite current filename with new filename
        for hostname in filename_hostnameArray:
            if hostname.lower() not in hostnameFound:
                hostnameFound.append(hostname.lower())
            replacedHostnameAddress = checkIfHostnameExistsAndReplace(hostname.lower())
            new_filename = item.replace(hostname, replacedHostnameAddress)
            washed_filename = new_filename  # Overwrite current filename with new filename
        for username in filename_usernameArray:
            if username.lower() not in usernameFound:
                usernameFound.append(username.lower())
            replacedUsernameAddress = checkIfUsernameExistsAndReplace(username.lower())
            new_filename = item.replace(username, str(replacedUsernameAddress))
            washed_filename = new_filename  # Overwrite current filename with new filename
        for url in filename_urlArray:
            if url.lower() not in urlFound:
                urlFound.append(url.lower())
            replacedurlAddress = checkIfUrlExistsAndReplace(url.lower())
            new_filename = item.replace(url, replacedurlAddress)
            washed_filename = new_filename  # Overwrite current filename with new filename
        if current_filename == str(washed_filename):
            return washed_filename
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def unzipFiles():
    try:
        os.chdir(tmpLocation)
        os.getcwd()
        # Walk down the tmp folder and find/unzip all zipped files
        # If there is a zipped file, it will start over to walk into the unzipped files aswell
        for root, dirs, files in os.walk(tmpLocation):
            for item in files:
                itemLocation = root + '/' + item
                # Unzip files ending with .gz, .zip or .tar, then delete the zipped version
                if os.path.exists(itemLocation):
                    if item.endswith(zipEnd):
                        logger.info(current_time() + ' - Unzipping: "' + root + '"/"' + item + '"')
                        newZipName = item.replace('.zip', '')
                        os.system('mkdir "' + str(root) + '"/"' + str(newZipName) + '"')
                        os.system('unzip -o -qq "' + str(root) + '"/"' + str(item) + '" -d "' + str(root) + '"/"' +
                                  str(newZipName) + '"')
                        os.system('rm -rf "' + str(root) + '"/"' + str(item) + '"')
                        unzipFiles()
                    if item.endswith(zipLogEnd):
                        logger.info(current_time() + ' - Unzipping: "' + root + '"/"' + item + '"')
                        newZipName = item.replace('.zip', '')
                        os.system('mkdir "' + str(root) + '"/"' + str(newZipName) + '"')
                        os.system('unzip -o -qq "' + str(root) + '"/"' + str(item) + '" -d "' + str(root) + '"/"' +
                                  str(newZipName) + '"')
                        os.system('rm -rf "' + str(root) + '"/"' + str(item) + '"')
                    if item.endswith(targzEnd) or item.endswith(tarEnd):
                        logger.info(current_time() + ' - Unzipping tar file: "' + root + '"/"' + str(item) + '"')
                        newTarName1 = item.replace('.gz', '')
                        newTarName2 = newTarName1.replace('.tar', '')
                        os.system('mkdir "' + str(root) + '"/"' + newTarName2 + '"')
                        os.system('tar -xf "' + str(root) + '"/"' + str(item) + '" -C "' + str(root) + '"/"' +
                                  str(newTarName2) + '"')
                        os.system('rm -rf "' + str(root) + '"/"' + str(item) + '"')
                        unzipFiles()
                    if item.endswith(targzLogEnd) or item.endswith(tarLogEnd):
                        logger.info(current_time() + ' - Unzipping tar file: "' + root + '"/"' + str(item) + '"')
                        newTarName1 = item.replace('.gz', '')
                        newTarName2 = newTarName1.replace('.tar', '')
                        os.system('mkdir "' + str(root) + '"/"' + newTarName2 + '"')
                        os.system('tar -xf "' + str(root) + '"/"' + str(item) + '" -C "' + str(root) + '"/"' +
                                  str(newTarName2) + '"')
                        os.system('rm -rf "' + str(root) + '"/"' + str(item) + '"')
                    if item.endswith(gzEnd):
                        logger.info(current_time() + ' - Unzipping gz file: "' + root + '"/"' + item + '"')
                        os.system('gzip -fd "' + str(root) + '"/"' + str(item) + '"')
                        unzipFiles()
                    if item.endswith(gzLogEnd):
                        logger.info(current_time() + ' - Unzipping gz file: "' + root + '"/"' + item + '"')
                        os.system('gzip -fd "' + str(root) + '"/"' + str(item) + '"')
        walking_file()
    except Exception as err:
        with open(script_log, 'a') as f:
            f.write(current_time() + ' - An error occurred\n' + traceback.format(err))
        logger.error(current_time() + ' - An error occurred\n' + traceback.format(err))
        quit()

def walking_file():
    try:
        global washed_filename
        tmp_dirs = os.listdir(tmpLocation)
        for folder in tmp_dirs:
            for root, dirs, files in os.walk(folder):
                for i in dirs:
                    washed_filename = ''
                    wash_filename(str(i))
                    if str(i) != washed_filename and washed_filename != '':
                        os.system('mv "' + root + '"/"' + str(i) + '" "' + root + '"/"' + washed_filename + '"')
                        walking_file()
            for root, dirs, files in os.walk(folder):
                for file in files:
                    washed_filename = ''
                    wash_filename(str(file))
                    if str(file) != washed_filename and washed_filename != '':
                        os.system('mv "' + root + '"/"' + file + '" "' + root + '"/"' + washed_filename + '"')
        washFiles()
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def washFiles():
    try:
        with open(script_log, 'a') as f:
            f.write(current_time() + ' - Done unzipping all folders\n')
        logger.info(current_time() + ' - Done unzipping all folders')
        tmp_dirs = os.listdir(tmpLocation)
        for directory in tmp_dirs:
            # Walking down the file structure in the inbox file and washing each file
            for root, dirs, files in os.walk(directory):
                for file in files:
                    logger.info(current_time() + ' - Now washing ' + file)
                    newFileContent = ''
                    with open(root + '/' + file, 'r+') as logFile:
                        for line in logFile:
                            # Going through each line in the file and finding regex mathes
                            currentLine = line.strip()
                            ipv4MatchesInLine = regEx.findall(ipv4Pattern, line)
                            ipv6MatchesInLine = regEx.findall(ipv6Pattern, line)
                            imsiMatchesInLine = regEx.findall(imsiPattern, line)
                            imsiHexMatchesInLine = regEx.findall(imsiHexPattern, line)
                            macMatchesInLine = regEx.findall(macPattern, line)
                            hostnameMatchesInLine = regEx.findall(hostnamePattern, line)
                            usernameMatchesInLine = regEx.findall(usernamePattern, line)
                            urlMatchesInLine = regEx.findall(urlPattern, line)
                            ipv4Array = []
                            ipv6Array = []
                            imsiArray = []
                            imsiHexArray = []
                            macArray = []
                            hostnameArray = []
                            usernameArray = []
                            urlArray = []
                            # Add all matches to their respective array
                            for i in range(len(ipv4MatchesInLine)):
                                ipv4Array.append(replaceCharsInTuple(str(ipv4MatchesInLine[i])))
                            for i in range(len(ipv6MatchesInLine)):
                                ipv6Array.append(replaceIpv6Tuple(ipv6MatchesInLine[i]))
                            for i in range(len(macMatchesInLine)):
                                macArray.append(macMatchesInLine[i])
                            for i in range(len(imsiMatchesInLine)):
                                imsiArray.append(imsiMatchesInLine[i])
                            for i in range(len(imsiHexMatchesInLine)):
                                imsiHexArray.append(InsertSpaceInTupleImsiHex(str(imsiHexMatchesInLine[i])))
                            for i in range(len(hostnameMatchesInLine)):
                                hostnameArray.append(hostnameMatchesInLine[i])
                            for i in range(len(usernameMatchesInLine)):
                                usernameArray.append(usernameMatchesInLine[i])
                            for i in range(len(urlMatchesInLine)):
                                urlArray.append(urlMatchesInLine[i])
                            # Replace all matches found with the other entry in the dictionary
                            for ipv4 in ipv4Array:
                                replacedIpv4Address = checkIfIpv4ExistsAndReplace(ipv4)
                                newLine = currentLine.replace(ipv4, replacedIpv4Address)
                                currentLine = newLine  # Overwrite current line with newLine to reflect changes made
                            for ipv6 in ipv6Array:
                                replacedIpv6Address = checkIfIpv6ExistsAndReplace(ipv6)
                                newLine = currentLine.replace(ipv6, str(replacedIpv6Address))
                                currentLine = newLine  # Overwrite current line with newLine to reflect changes made
                            for mac in macArray:
                                replacedMacAddress = checkIfMacExistsAndReplace(mac.lower())
                                newLine = currentLine.replace(mac, replacedMacAddress)
                                currentLine = newLine  # Overwrite current line with newLine to reflect changes made
                            for imsi in imsiArray:
                                replacedImsiAddress = checkIfImsiExistsAndReplace(imsi)
                                newLine = currentLine.replace(imsi, replacedImsiAddress)
                                currentLine = newLine  # Overwrite current line with newLine to reflect changes made
                            for imsiHex in imsiHexArray:
                                replacedImsiHexAddress = checkIfImsiHexExistsAndReplace(imsiHex)
                                newLine = currentLine.replace(str(imsiHex), str(replacedImsiHexAddress))
                                currentLine = newLine  # Overwrite current line with newLine to reflect changes made
                            for hostname in hostnameArray:
                                if hostname.lower() not in hostnameFound:
                                    hostnameFound.append(hostname.lower())
                                replacedHostnameAddress = checkIfHostnameExistsAndReplace(hostname.lower())
                                newLine = currentLine.replace(hostname, replacedHostnameAddress)
                                currentLine = newLine  # Overwrite current line with newLine to reflect changes made
                            for username in usernameArray:
                                if username.lower() not in usernameFound:
                                    usernameFound.append(username.lower())
                                replacedUsernameAddress = checkIfUsernameExistsAndReplace(username.lower())
                                newLine = currentLine.replace(username, str(replacedUsernameAddress))
                                currentLine = newLine  # Overwrite current line with newLine to reflect changes made
                            for url in urlArray:
                                if url.lower() not in urlFound:
                                    urlFound.append(url.lower())
                                replacedurlAddress = checkIfUrlExistsAndReplace(url.lower())
                                newLine = currentLine.replace(url, replacedurlAddress)
                                currentLine = newLine  # Overwrite current line with newLine to reflect changes made
                            newFileContent += currentLine + '\n'
                        logFile.truncate(0)  # Remove old content of file
                        logFile.seek(0)  # Start writing from index 0
                        logFile.write(newFileContent)
                    logger.info(current_time() + ' - ###Done washing ' + file + '###')
            os.system('touch ' + directory + '/washingreport.txt')
            # Making a file which contains all matches found and what they are changed to
            with open(directory + '/washingreport.txt', 'r+') as reportfile:
                stringToWrite = ('########################\nResult from washing\n########################\n\n' +
                                 'Ipv4 dictionary:\n' + str(ipv4AddressMatches) +
                                 '\n\nIpv6 dictionary:\n' + str(ipv6AddressMatches) +
                                 '\n\nImsi dictionary:\n' + str(imsiMatches) +
                                 '\n\nImsi hex dictionary:\n' + str(imsiHexMatches) +
                                 '\n\nMac address dictionary:\n' + str(macMatches) +
                                 '\n\nUsernames found:\n' + str(usernameFound) +
                                 '\n\nHostnames found:\n' + str(hostnameFound) +
                                 '\n\nUrl found:\n' + str(urlFound) + '\n')
                reportfile.write(stringToWrite)
            # Move all files washed in tmp folder to the respective outbox folder
            os.system('chmod 777 ' + directory)
            os.system('mv ' + directory + ' ' + outboxLocation)
            logger.info('\n\n' + current_time() + '\n########################\nMoved files to: ' + outboxLocation + directory +
                  '\n########################\n')
        with open(script_log, 'a') as f:
            f.write(str(current_time()) + ' - Washing is complete\n')
        logger.info(current_time() + ' - Washing is complete\n')
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def move_files():
    try:
        content_inbox = os.listdir(inboxLocation)
        content_tmp = os.listdir(tmpLocation)
        logger.info(current_time() + ' - Script starting')
        if len(content_inbox) == 0 and len(content_tmp) == 0:
            quit()
        if len(content_inbox) != 0 and len(content_tmp) == 0:
            while True:
                sftp_files = subprocess.check_output('du -H -d1 /nfs/data/inbox/', shell=True).decode()
                time.sleep(2)
                sftp_files_2 = subprocess.check_output('du -H -d1 /nfs/data/inbox/', shell=True).decode()
                if str(sftp_files) == str(sftp_files_2):
                    break
                if str(sftp_files) != str(sftp_files_2):
                    with open(script_log, 'a') as f:
                        f.write(str(current_time()) + ' - Files are still being transferred, will wait to start script\n')
                    logger.warning(current_time() + ' - Files are still being transferred, will wait to start script')
                    time.sleep(2)
            # Make a new directory in /tmp with date and time
            os.system('mkdir ' + tmpDir)
            os.system('cp -r ' + inboxLocation + '* ' + tmpDir)
            os.system('rm -rf ' + inboxLocation + '*')
            os.system('chmod -R 777 ' + tmpDir)
            tmp_folder_content = os.listdir(tmpDir)
            for folder in tmp_folder_content:
                if folder.endswith(zipEnd):
                    logger.info(current_time() + ' - Unzipping: ' + tmpDir + '/"' + folder + '"')
                    newZipName = folder.replace('.zip', '')
                    os.system('mkdir ' + str(tmpDir) + '/"' + str(newZipName) + '"')
                    os.system('unzip -o -qq ' + str(tmpDir) + '/"' + str(folder) + '" -d ' + str(tmpDir) + '/"' +
                              newZipName + '"')
                    os.system('rm -rf ' + str(tmpDir) + '/"' + str(folder) + '"')
                if folder.endswith(gzEnd):
                    logger.info(current_time() + ' - Unzipping gz file: ' + tmpDir + '/"' + folder + '"')
                    os.system('gzip -fd ' + str(tmpDir) + '/"' + str(folder) + '"')
                if folder.endswith(targzEnd) or folder.endswith(tarEnd):
                    logger.info(current_time() + ' - Unzipping tar file: ' + tmpDir + '/"' + folder + '"')
                    newTarName1 = folder.replace('.gz', '')
                    newTarName2 = newTarName1.replace('.tar', '')
                    os.system('mkdir ' + str(tmpDir) + '/"' + newTarName2 + '"')
                    os.system('tar -xf ' + str(tmpDir) + '/"' + str(folder) + '" -C ' + str(tmpDir) + '/"' +
                              newTarName2 + '"')
                    os.system('rm -rf ' + str(tmpDir) + '/"' + folder + '"')
            with open(script_log, 'a') as f:
                f.write(str(current_time()) + ' - Done unzipping root folder\n')
            logger.info(current_time() + ' - Done unzipping root folder')
            check_folder()
        if len(content_tmp) != 0 and len(content_inbox) == 0:
            check_folder()
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def check_folder():
    try:
        num_gz = subprocess.check_output('find ' + tmpLocation + ' -name "*gz"', shell=True).decode()
        num_gz = num_gz.split('\n')
        num_zipped = subprocess.check_output('find ' + tmpLocation + ' -name "*zip"', shell=True).decode()
        num_zipped = num_zipped.split('\n')
        num_tar = subprocess.check_output('find ' + tmpLocation + ' -name "*tar"', shell=True).decode()
        num_tar = num_tar.split('\n')
        total_zipped = len(num_gz) + len(num_zipped) + len(num_tar) - 3
        if total_zipped >= 500:
            new_limit = total_zipped * 3
            sys.setrecursionlimit(new_limit)
            limit = str(new_limit)
            with open(script_log, 'a') as f:
                f.write(str(current_time()) + ' - Amount of zipped files will exceed max amount of calls, will change '
                                              'recursion limit to: ' + limit + '\n')
            logger.warning(current_time() + ' - Amount of zipped files will exceed max amount of calls, will change '
                                             'recursion limit to: ' + limit)
            unzipFiles()
        if total_zipped <= 500:
            unzipFiles()
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

if __name__ == '__main__':
    move_files()