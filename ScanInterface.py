
# Copyright 2016 Ruth Ogunnaike
"""

provides the interface to initiate vulnerability scan. Multiple scans can be launched from this interface.
Add your custom scanner to use this interface.
runScan, this runs vulnerabilities scans using the integrated scanning tools (both penetration testing tools and
custom scanners based on your configuration).Your scanner must be configured to return Vulnerable or Non-vulnerable
getStatus(), this returns a scan status Vulnerable or Non-vulnerable after analyzing results from all the integrated
scanning tools. If >50% of the tools flags the device as Vulnerable, the final status will be Vulnerable. If <50%,
flagged as non-vulnerable. (The percentage can vary depending on our digression)
isResolved(ip), this tries to resolve the vulnerabilities detected. Currently, it only resolves for default or weak passwo
rd vulnerability

updateList(directory, mac_add) blacklists or whitelists the device based on the scan status. The directory is the black
list or white list directory. Mac_add is the MAC address of the device

updatePolicy(whitelist, blacklist, firewallpolicies), this method update the firewall policies (the access control list)
.Blacklisted hosts are blocked from communicating with other hosts in the network. Parameter whitelistis the whitelisted
hosts file director, blacklist is the blacklisted hosts file director and firewallpolicies is the access control list file directory.
 """
import UpdatePolicy
import SshScanner
import MiraiScanner
import Nmap
import time
# from scanserver \
import DBModel
import Resolutions
import sys


class ScanInterface(classmethod):
    def __init__(self, parent=None):
        print ('login')
        # token= self.login(username, password)


def runScan(ip):
    device_id = DBModel.insert_device_bios(ip, 'description', 'mac_address', 'ip_address', 'manufacturer', 'brand',
                                           'model', 'type', 'version', 'operating_system', 0, 0, 0, 0)

    launch_all_scans(ip, device_id)
    result = get_final_status(ip, device_id)
    time.sleep(1)
    return result


def launch_all_scans(ip, device_id):
    print('IP address: {0} leased. \n'.format(ip))
    print('Launching vulnerability scans on Host: {0} \n'.format(ip))

    Nmap.launch_nmap_scan(ip, device_id)
    MiraiScanner.runScan(ip, device_id)
    SshScanner.runScan(ip, device_id)
    print('***Vulnerability scans on your device is complete \n')


def get_final_status(ip, device_id):
    print('***Analyzing results, please wait.....................\n')
    result =''
    conclusion_status = getStatus(device_id)
    print ('CONCLUSION: {0}'.format(conclusion_status))
    if conclusion_status == 'Vulnerable':
        result = send_prompt(device_id, 1, ip)
    elif conclusion_status == 'Non-vulnerable':
        print('There was no vulnerability found in your device, your device can communicate with'
              ' other device with IP: {0} \n '.format(ip))
        result = send_prompt(device_id, 2, ip)
    else:
        print('Output not recognized')
    return result


def send_prompt(device_id, vuln_index, ip):
    result = ''
    if vuln_index == 1:
        vuln_scans = DBModel.get_vulns_scanid(device_id)
        for v in vuln_scans:
            if v == 1:
                result = resolve_vuln(device_id, ip)
                return result

    else:
        Resolutions.non_vuln_prompt(device_id)
        return 'Good'



def getStatus(device_id):
    vuln_report = DBModel.get_vulnerability_status(device_id)
    total_count = float(0)
    vuln_count = float(0)
    unaccountted = float(0)
    for item in vuln_report:
        total_count += 1
        if str(item.description) == 'Vulnerable':
            vuln_count += 1
        elif str(item.description) == 'Non Vulnerable':
            vuln_count += 0
        else:
            unaccountted += 1 
     
    percent =round(((vuln_count / total_count) * 100), 2)
    # percent =float(vuln_count /total_count)
    # print(vuln_count)
    # print (total_count)
    # print (percent)
    if percent > 5:
        return 'Vulnerable'
    else:
        return 'Non-vulnerable'


def resolve_vuln(device_id, ip):
    user_prompt = Resolutions.vuln_prompt('Default password vulnerability', 'Changing password', device_id)
    if user_prompt == 'yes':
        SshScanner.isPasswordChanged(ip)
        Resolutions.non_vuln_prompt(device_id)
        return 'Good'
    if user_prompt == 'no':
        print ('\n Communication in the network disabled for this device ')
        Resolutions.non_vuln_prompt(device_id)
        return 'Bad'

if __name__ == '__main__':
    # runScan("192.168.1.37")
    runScan(sys.argv[1])
    # getStatus(26)


    # defaultScannning('10.156.1.162')
    # create_new_console('Amazon Echo', '45:23:34:12:ac:j7')
    # num = validate_user_input('Bad lock detection', 'Changing the default password')
    time.sleep(1)

    # print('Searching available Fixes....')
    # resolve_ssh_scanner()


def isResolved(ip):
    print "Resolved"
    SshScanner.isPasswordChanged(ip)


def updateList(directory, mac_add):
    UpdatePolicy.addlist(directory, mac_add)


def analyze_scan_results():
    print ('Result analysis')


def get_suggestions():
    print('Get Suggestions')


def updatePolicy(whitelist, blacklist, firewallpolicies):
    UpdatePolicy.updatepolicy(whitelist, blacklist, firewallpolicies)


def exist(directory, mac_add):
    UpdatePolicy.exist(directory, mac_add)
