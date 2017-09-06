
#Copyright 2016 Ruth Ogunnaike

"""
sshscanner, this code runs 462 combinations of common weak/default usernames  and passwords against port 22 in order
to have a login access into the host. It includes method to change user's password

Procedures
runScan(IP_Address),this method initiates and run the default/weak vulnerability scanner password. The parameter
ip_address is passed as a string value.

getStatus(), this function returns the login status of the scan. The return values are Success Scan Error and Failed
. Success and Scan Error should flag the host vulnerable and the Failed status flags the host as not-vulnerable.

launchMiraiScan(IP_Address), this sends the command to run the IotSeeker program and scans for devices that still has defaults credentials
"""


from __future__ import print_function

from __future__ import absolute_import
from pexpect import pxssh
import pexpect
import os
import socket
import time
import string
# from scanserver \
import DBModel


COMMAND_PROMPT = '[$#] '
TERMINAL_PROMPT = r'Terminal type\?'
TERMINAL_TYPE = 'vt100'
SSH_NEWKEY = r'Are you sure you want to continue connecting \(yes/no\)\?'
#
# try:
#     import urllib.request as urllib2
# except ImportError:
#     import urllib2
#
# url = 'https://localhost:8834'
#
#
# class sshscanner(object):
#     def built_url(self, resource):
#         return '{0}{1}'.format(url, resource)


def set_status(value):
    global status
    status = value


def get_status():
    return status


def launch_mirai_can(ip, device_id):
    global status, vulnerability_status, scan_time
    starttime = time.time()
    cmd = 'perl iotScanner.pl %s' % ip
    start_time = time.time()
    vulnerability_id = 0
    # Log Scan
    txt = "\n***************************\nRunning Mirai Scan: %s (Scanning your device for default passwords) \n" % (ip)
    print(txt)

    m_child = pexpect.spawn('/bin/bash', ['-c', cmd], timeout=600)

    i = m_child.expect(['failed to establish TCP connection', 'doesnot have any password',
                       'still has default password', 'still has default passwd', 'has changed',
                        'didnot find dev type after trying all devices',
                       'due to 404 response', 'failed to establish TCP connection', 'http redirect to',
                       'unexpected status code',
                       'didnot find devType for',  'unexpected partial url', TERMINAL_PROMPT, COMMAND_PROMPT])

    description = m_child.before + ', ' + m_child.after
    if i == 0:
        vulnerability_id = 1
        scan_time = round((time.time() - starttime), 2)
        vulnerability_status = 'Non-vulnerable'
    elif i == 1 or i == 2 or i == 3:
        # set_status('Vulnerable')
        scan_time = round((time.time() - starttime), 2)
        vulnerability_status = 'Vulnerable'
    else:
        scan_time = round((time.time() - starttime), 2)
        vulnerability_status = 'Non-vulnerable'
        # set_status('Non-vulnerable')
    scan_id = DBModel.insert_miraiscanner_report(vulnerability_id, device_id, ip, description, scan_time,
                                                 description, vulnerability_status)
    scanner_id = DBModel.get_scan_id('MiraiScanner')

    val = DBModel.insert_scan_results(scanner_id, vulnerability_id, device_id, vulnerability_status, 'N/A', 0, 0, 'N/A', 'N/A')

    print('Completed Mirai scan: {0}, elapsed {1}s ( Host ID:{2}) \n'.format(time.strftime("%H:%M:%S"), scan_time,
                                                                             device_id))

def scanner_id():
    scanner_id = DBModel.get_scan_id('NmapScanner')
    print (scanner_id)

def runScan(ip, device_id):
    launch_mirai_can(ip, device_id)

if __name__ == '__main__':
    scanner_id()
