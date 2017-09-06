
import sys
import nmap # using python nmap library
import time
import socket
from subprocess import Popen, PIPE
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from libnmap.objects import  NmapHost, NmapReport, NmapService

# The -A option can be used to perform an aggressive scan which is equal to - "enable OS detection and Version detection, Script scanning and Traceroute". Here is a quick example

def run_scan2(ip_address):
    nm = NmapProcess(ip_address, options='-sV')
    rc = nm.run()

    # print (nm.stdout)
    nmap_report = NmapParser.parse(nm.stdout)

    # print(nmap_report.r)
    print(nmap_report.id)
    print(nmap_report.version)
    print(nmap_report.commandline)
    print(nmap_report.endtime)
    print(nmap_report.get_dict())
    print(nmap_report.get_raw_data())
    print(nmap_report.hosts[0])
    # my_host = NmapHost(hostnames=nmap_report.)
    # print (my_host.address)
    print(nmap_report.summary)

    # for hosts in nmap_report:
    #     print hosts.

    # if rc == 0:
    #     print nm.stdout
    # else:
    #     print nm.stderr

#
# def runScan(ipAddress):
#     print 'Running Nmap Scanner'
#     print 'Retrieving device BIOs'
#     print('Retrieving Device BIOs for Host {0)'.format(ipAddress))
#     host = ipAddress;
#     nmapScan = nmap.PortScanner()   ## create a type scanner form nmap library
#     nmapScan.scan(hosts=host,   arguments='-n -sP -PE -v -A -sA') #'-n -sP -PE -PA21,23,80,3389'
#
#     # nmapScan[ipAddress].command_line()
#     nmapScan[ipAddress].all_hosts()
#     nmapScan[ipAddress].hostname()
#     nmapScan[ipAddress].state()
#     nmapScan[ipAddress].all_protocols() #['tcp']
#     nmapScan[ipAddress].keys() #[80, 25, 443, 22, 111]
#     nmapScan[ipAddress].has_tcp(22) #True  #does it support ssh
#     nmapScan[ipAddress].has_tcp(23)  # {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'}
#     nmapScan[ipAddress]['tcp'][22]['state'] #'open'
#
#     # deviceDict = [(x, pentest[x] ['status'] ['state']) for x in pentest.all_hosts]
#
#     all_hosts = nmapScan.all_hosts()
#     for host, status in all_hosts:
#         # if 'up' in status:
#         print('------------------------------------------------')
#         print('Host {0): Status {1}'.format(host, status))
#         print('Host : %s (%s)' % (host, nmapScan[host].hostname()))
#         print ('State : %s' % nmapScan[host].state())
#         for protoc in nmapScan.all_protocols():
#             print ('-----------------------------')
#             print('Protocol : %' % protoc)
#
#         lport = nmapScan[host][protoc].keys()
#         lport.sort()
#         for port in lport:
#             print ('Port %s\tstate : %s ' % (port, nmapScan[host][protoc][port]['state']))
#         print (nmapScan.csv())
#
#             # >> > nm.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
#             # >> > hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
#             # >> > for host, status in hosts_list:
#             #     >> > print('{0}:{1}'.host)
#             # 192.168
#             # .1
#             # .0:down
#         print "Nmap scan complete -Ruth"





def test(device_id, mac_address):
    messages = ('Scan results for device: {0}, with MAC address: {1}'.format(device_id, mac_address))
    new_window_command = "xterm -e ".split()
    handle = Popen(new_window_command + [sys.executable, 'test.py'] + [device_id] + [mac_address]
                   , stdin=PIPE, stderr=PIPE,  close_fds=False)

    output = handle.communicate()
    print(output)
    handle.wait()
    print(handle.pid)


def validate_user_input(vulnerability_name, resolution_name):
    while True:
        consent = raw_input('Do you want SeeSec to resolve vulnerability: {0}, by {1} on your device? Enter Y(Yes) '
                            'or N(No)  \n'.format(vulnerability_name, resolution_name)).lower()
        if consent in ('y', 'yes', 'n', 'no'):
            if consent in ('y', 'yes'):
                print(resolution_name + '. Please wait.... \n')

                return 1
            elif consent in ('n', 'no'):
                while True:
                    confirm = raw_input('Are you sure you do not want to resolve vulnerability: {0}. Enter Y(Yes) to'
                                        ' cancel vulnerability fix, Enter N(No) to resolve vulnerability \n'.
                                        format(vulnerability_name)).lower()
                    if confirm in ('y', 'yes', 'n', 'no'):
                        if confirm in ('n', 'no'):
                            print(resolution_name + '. Please wait.... \n')
                            return 1
                        elif confirm in ('y', 'yes'):
                            print('You have opted out on resolving vulnerability: {0}. Please be aware your'
                                  ' device is vulnerable and you are at risk of a cyber attack. \n'
                                  .format(vulnerability_name))
                            return 0
                        else:
                            print('Onto the next...... \n')
                            return 0
                    else:
                        print('Enter a valid input \n')

            else:
                print('Discarding resolution on vulnerability: {0} \n'.format(vulnerability_name))
            break
        else:
            print('Enter a valid input')


def defaultScannning(ipAddress):
    print('Retrieving Device BIOs for Host {0}'.format(ipAddress))
    nma = nmap.PortScannerAsync()
    nma.scan(hosts=ipAddress, arguments='-n -sV -O', callback=callback_result)

    while nma.still_scanning():
        print("Waiting >>>")
        nma.wait(2)


def callback_result(host, scan_result):
    print '------------------'
    print host, scan_result


def run_scan(ip_address):
    nm = nmap.PortScanner()
    host = ip_address
    nm.scan(hosts=host, arguments='-n -sP -sC -sV -v -script vuln')
    # nm.sudo_run_background()
    print(nm.get_nmap_last_output())
    # new_command = 'nmap -O -oX mscan.xml '.split(' ')  # 10.156.7.36'
    # start_time = time.time()
    # process = Popen(new_command + [ip_address] + ['-e'], stdout=PIPE, stdin=PIPE, stderr=PIPE, shell=True)
    # process.wait()
    # response = process.communicate()
    # print('About to print response -----------------yeah-------')
    # print(response)


if __name__ == '__main__':
    run_scan2('10.156.1.162')
    # defaultScannning('10.156.1.162')
    # create_new_console('Amazon Echo', '45:23:34:12:ac:j7')
    # num = validate_user_input('Bad lock detection', 'Changing the default password')
    print('Finished running')
    # resolve_ssh_scanner()

    # for host, result in x._scan_result['scan'].items():
    #     print "[*]" + thost + "tcp/" + tport + " " + result['status']['state']

            # nmap -iL /tmp/test.txt - to scan a list of hosts from a file
    # nmap 192.168.1.0/24 --exclude 192.168.1.5 - to exclude hosts from a scan
    # or nmap -iL /tmp/scanlist.txt --excludefile /tmp/exclude.txt - to exclude list of hosts from a scan
    # 5: nmap -v -A 192.168.1.1 - Turn on OS and version detection scanning script (IPv4)
    # nmap -sA 192.168.1.254  - to Find out if a host/network is protected by a firewall
    # 7: nmap -PN 192.168.1.1 - Scan a host when protected by the firewall
    # 8:nmap -6 IPv6-Address-Here OR nmap -6 server1.cyberciti.biz OR nmap -v A -6 2607:f0d0:1002:51::4Scan an IPv6 host/address. The -6 option enable IPv6 scanning. The syntax is:
    #
    # - To get all the characteristics, use this url as a resource
    # https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/




# import nmap # using python nmap library
# import socket
#
#
# def runScan(ipAddress):
#     print 'Running Nmap Scanner'
#     print 'Retrieving device BIOs'
#     print('Retrieving Device BIOs for Host {0)'.format(ipAddress))
#     host = ipAddress;
#     nmapScan = nmap.PortScanner()   ## create a type scanner form nmap library
#     nmapScan.scan(hosts=host,   arguments='-n -sP -PE -v -A -sA') #'-n -sP -PE -PA21,23,80,3389'
#
#     # nmapScan[ipAddress].command_line()
#     nmapScan[ipAddress].all_hosts()
#     nmapScan[ipAddress].hostname()
#     nmapScan[ipAddress].state()
#     nmapScan[ipAddress].all_protocols() #['tcp']
#     nmapScan[ipAddress].keys() #[80, 25, 443, 22, 111]
#     nmapScan[ipAddress].has_tcp(22) #True  #does it support ssh
#     nmapScan[ipAddress].has_tcp(23)  # {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'}
#     nmapScan[ipAddress]['tcp'][22]['state'] #'open'
#
#     # deviceDict = [(x, pentest[x] ['status'] ['state']) for x in pentest.all_hosts]
#
#     all_hosts = nmapScan.all_hosts()
#     for host, status in all_hosts:
#         # if 'up' in status:
#         print('------------------------------------------------')
#         print('Host {0): Status {1}'.format(host, status))
#         print('Host : %s (%s)' % (host, nmapScan[host].hostname()))
#         print ('State : %s' % nmapScan[host].state())
#         for protoc in nmapScan.all_protocols():
#             print ('-----------------------------')
#             print('Protocol : %' % protoc)
#
#         lport = nmapScan[host][protoc].keys()
#         lport.sort()
#         for port in lport:
#             print ('Port %s\tstate : %s ' % (port, nmapScan[host][protoc][port]['state']))
#         print (nmapScan.csv())
#
#             # >> > nm.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
#             # >> > hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
#             # >> > for host, status in hosts_list:
#             #     >> > print('{0}:{1}'.host)
#             # 192.168
#             # .1
#             # .0:down
#         print "Nmap scan complete -Ruth"
#
# def callback_result(host, scan_result):
#     print '------------------'
#     print host, scan_result
#
#
# # def defaultScannning(ipAddress):
# ipAddress = '10.156.30.119'
# print('Retrieving Device BIOs for Host {0}'.format(ipAddress))
# nma = nmap.PortScannerAsync()
# nma.scan(hosts=ipAddress, arguments='-s -o -sP')
# # arguments='-n -sP -PE -v -A -O'
#
#
# while nma.still_scanning():
#     print("Waiting >>>")
#     nma.wait(2)
#
# #
# # def main():
# #     defaultScannning("10.156.10.79")
# #
# # if __name__ == '__main__':
# #     main()
#
#
#             # nmap -iL /tmp/test.txt - to scan a list of hosts from a file
#     # nmap 192.168.1.0/24 --exclude 192.168.1.5 - to exclude hosts from a scan
#     # or nmap -iL /tmp/scanlist.txt --excludefile /tmp/exclude.txt - to exclude list of hosts from a scan
#     # 5: nmap -v -A 192.168.1.1 - Turn on OS and version detection scanning script (IPv4)
#     # nmap -sA 192.168.1.254  - to Find out if a host/network is protected by a firewall
#     # 7: nmap -PN 192.168.1.1 - Scan a host when protected by the firewall
#     # 8:nmap -6 IPv6-Address-Here OR nmap -6 server1.cyberciti.biz OR nmap -v A -6 2607:f0d0:1002:51::4Scan an IPv6 host/address. The -6 option enable IPv6 scanning. The syntax is:
#     #
#     # - To get all the characteristics, use this url as a resource
#     # https://www.cyberciti.biz/networking/nmap-command-examples-tutorials/
#
