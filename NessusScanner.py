
# Copyright 2016 Ruth Ogunnaike
"""
#This code connects to the the Nessus penetration testing tool to run vulnerability scans based on the specified type.
Connection is done via a REST -API
"""

import requests
import json
import time
import sys

url = 'https://localhost:8834'
verify = False
username = 'seesec'
password = 'seesec.2017'

scanResult = {}
url = 'https://localhost:8834'
result_path= 'scanresults/'
verify = False
filename=''


class Scanner(object):

    def build_url(self, resource):
        return '{0}{1}'.format(url, resource)


def login(usr, pwd):
    """
    Login to scanserver (nessus for this case).
    """
    login = {'username': usr, 'password': pwd}
    data = connect('POST', '/session', '', data=login)
    return data['token']


def get_policies(token):
    """Get scan policies
    Get all of the scan policies but return only the title and the uuid of
    each policy.
    """
    data = connect('GET', '/editor/policy/templates', token, data=None)
    return dict((p['title'], p['uuid']) for p in data['templates'])


def add(name, desc, targets, pid, token):
    """
    Add a new scan
    Create a new scan using the policy_id, name, description and targets. The
    scan will be created in the default folder for the user. Return the id of
    the newly created scan.
    """
    scan = {'uuid': pid,
            'settings': {
                'name': name,
                'description': desc,
                'text_targets': targets}
            }

    data = connect('POST', '/scans',token, data=scan)

    return data['scan']


def update(scan_id, name, desc, targets, token, pid=None):
    """
    Update a scan
    Update the name, description, targets, or policy of the specified scan. If
    the name and description are not set, then the policy name and description
    will be set to None after the update. Targets value must be set
    """

    scan = {}
    scan['settings'] = {}
    scan['settings']['name'] = name
    scan['settings']['desc'] = desc
    scan['settings']['text_targets'] = targets

    if pid is not None:
        scan['uuid'] = pid

    data = connect('PUT', '/scans/{0}'.format(scan_id), token, data=scan)
    return data


def launch( sid, token):
    """
    Launch a scan
    Launch the scan specified by the sid.
    """
    data = connect('POST', '/scans/{0}/launch'.format(sid), token)
    return data['scan_uuid']


def get_history_ids(sid, token):
    """
    Get history ids
    Create a dictionary of scan uuids and history ids so we can lookup the
    history id by uuid.
    """
    data = connect('GET', '/scans/{0}'.format(sid), token)
    return dict((h['uuid'], h['history_id']) for h in data['history'])


def status(sid, hid, token):
    """
    Check the status of a scan run
    Get the historical information for the particular scan and hid. Return
    the status if available. If not return unknown.
    """
    d = get_scan_history(sid, hid, token)
    return d['status']


def export(sid, hid, token):
    """
    Make an export request
    Request an export of the scan results for the specified scan and
    historical run. The format can be any one of nessus, html, pdf, csv,
     or db. Once the request is made, we have to wait for the export to be ready.
    """

    data = {'history_id': hid,
            'format': 'csv'}
    data = connect('POST', '/scans/{0}/export'.format(sid), token, data=data)

    fid = data['file']

    while export_status(sid, fid, token) is False:
        time.sleep(5)

    return fid


def export_status(sid, fid, token):
    """
    Check export status
    Check to see if the export is ready for download.
    """
    data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid), token)
    return data['status'] == 'ready'


def get_scan_history(sid, hid, token):
    """
    Scan history details
    Get the details of a particular run of a scan.
    """
    params = {'history_id': hid}
    data = connect('GET', '/scans/{0}'.format(sid),token, params)

    return data['info']


def download(sid, fid, token):
    """
    Download the scan results
    Download the scan results stored in the export file specified by fid for
    the scan specified by sid.
    """
    data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid), token)
    filename = 'nessus_{0}_{1}.csv'.format(sid, fid)
    # filename = 'nessus_{0}_{1}.pdf'.format(sid, fid)

    print('Saving scan results to {0}/{1}.'.format(result_path, filename))
    path = "{0}/{1}".format(result_path, filename)

    with open(path, 'w') as f:
        f.write(data)
        f.close()
    return path

def readFile(filename):

    """Read through the result of th vulnerability scan.
    This only reads csv files"""
    import csv

    f = open(filename)
    csv_f = csv.reader(f)

    none = 0
    high = 0
    medium = 0
    critical = 0
    low = 0

    for rows in csv_f:
        if rows[3] == 'None':
            none = none + 1
        if rows[3] == 'Low':
            low = low + 1
        if rows[3] == 'Medium':
            medium = medium + 1
        if rows[3] == 'High':
            high = high + 1
        if rows[3] == 'Critical':
            critical = critical + 1
    #securitystatus = (none, low, medium, high, critical)
    lofinfo = ''
    status = {}
    if (high != 0 or critical!= 0):
        loginfo = 'The device has {0} high vulnerabilities and {1} critical vulnerability.' \
                  ' Device Blacklisted'.format(high, critical)
        status =('Vulnerable', loginfo)
    if (medium != 0 and low != 0):
        loginfo = 'The device has {0} low vulnerabilities and {1} medium vulnerability.' \
                  ' Device Blacklisted'.format(low, medium)
        status = (' Somewhat vulnerable', loginfo)
    if (none > 2):
        loginfo = 'The device has mininimal vulnerability, {0} info. Device Blacklisted'.format(none)
	status = ('Somewhat vulnerable', loginfo)
    else:
        loginfo = 'The device has minimal vulnerabity, {0} info.' \
                  ' Device Whitelisted'.format(none)
        status=('Non-vulnerable', loginfo)

    return status


def history_delete(sid, hid, token):
    """
    Delete a historical scan.
    This deletes a particular run of the scan and not the scan itself. the
    scan run is defined by the history id.
    """
    connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid), token)


def logout(token):
    """
    Logout of nessus.
    """
    connect('DELETE', '/session', token)


def delete( scan_id, token):
    """
    Delete a scan
    This deletes a scan and all of its associated history. The scan is not
    moved to the trash folder, it is deleted.
    """
    connect('DELETE', '/scans/{0}'.format(scan_id), token)


def connect(method, resource,token,  data=None):
    """
    Send a request to scanserver based on the specified data. If the session token
    is available add it to the request. Specify the content type as JSON and
    convert the data to JSON format.
    """
    headers = {'X-Cookie': 'token={0}'.format(token),
               'content-type': 'application/json'}

    data = json.dumps(data)

    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify, timeout =99*99)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

    # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        print (r.status_code)
        print (e['error'])
        sys.exit()

    # When downloading a scan we need the raw contents not the JSON data.
    if 'download' in resource:
        return r.content
    else:
        return r.json()


def build_url(resource):
    return '{0}{1}'.format(url, resource)


def runScan(ip_address, device_id):
    print("initiating scan")

    token = login(username, password)

    print('Adding new scan.')
    policies = get_policies(token)
    policy_id = policies['DROWN Detection']
    scan_data = add('Vulnerability Scan', 'Create a new scan with API', '76.103.2.54', policy_id, token)
    scan_id = scan_data['id']

    print('Updating scan with new targets.')
    update(scan_id, scan_data['name'], scan_data['description'], ip_address, token)
    print('Launching new scan.')
    scan_uuid = launch(scan_id, token)
    history_ids = get_history_ids(scan_id, token)
    history_id = history_ids[scan_uuid]
    while status(scan_id, history_id, token) != 'completed':
        time.sleep(5)

    print('Exporting the completed scan.')
    file_id = export(scan_id, history_id, token)
    filename = download(scan_id, file_id, token)
    result = readFile(filename)

    print(scan_id)

    print('Deleting the scan.')
    set_status(result[0])


def get_status():
    return nessus_status;


def set_status(value):
    global nessus_status
    nessus_status = value

