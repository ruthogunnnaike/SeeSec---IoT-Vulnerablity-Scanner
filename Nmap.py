
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
import os
import socket
import time
import sys
import DBModel
import xml.etree.ElementTree as ET
from subprocess import PIPE, Popen


def launch_nmap_scan(ip, device_id):
    scan_result_name = str(device_id) + '.xml'
    cmd = 'sudo nmap -O -sV -A --script vuln -oX {0} {1} --reason'.format(scan_result_name, ip)
    start_time = time.time()
    # Log Scan
    txt = "\n*****************************\nRunning Nmap Scan: %s (Scanning your device for web, operating systems" \
          " and application vulnerabilities) \n" % (ip)
    print(txt)

    process = Popen(['-c', cmd], shell=True, stdout=PIPE, stdin=PIPE)
    process.communicate()
    process.wait()
    scan_time = round((time.time() - start_time), 2)
    parse_xml_ouput(scan_result_name, device_id)


def parse_xml_ouput(filename, device_id):
    tree = ET.parse(filename)
    root = tree.getroot()
    starttime='-1'
    endtime='-1'
    state = '-1'
    reason='-1'
    reason_ttl='-1'
    hostname_name = '-1'
    hostname_type = '-1'
    seconds = '-1'
    lastboot = '-1'
    distance_value='-1'
    tcp_index = '-1'
    tcp_difficulty = '-1'
    tcp_values = '-1'
    ipid_class = '-1'
    ipid_values = '-1'
    tcpts_class = '-1'
    tcpts_values = '-1'
    times_srtt = '-1'
    times_rttvar = '-1'
    times_to = '-1'
    finished_time = '-1'
    finished_timestr = '-1'
    finished_elapsed = '-1'
    finished_summary = '-1'
    finished_exit = '-1'
    hosts_up = '-1'
    hosts_down = '-1'
    hosts_total='-1'

     # ----------------ScanInfo
    for root_child in root:
        if root_child.tag == 'scaninfo':
            scaninfo = root_child
            services = scaninfo.get('services')
            type = scaninfo.get('type')
            protocol = scaninfo.get('protocol')
            numservices = scaninfo.get('numservices')

        # -------------------------------------Host---------------------------------------------
        if root_child.tag == 'host':
            host = root_child
            for child in host:
                if child.tag == 'status':
                    state = child.get('state')
                    reason = child.get('reason')
                    reason_ttl = child.get('reason_ttl')
                elif child.tag == 'address':
                    addrtype = child.get('addrtype')
                    addr = child.get('addr')
                    add_vendor = child.get('vendor')
                    DBModel.insert_address(device_id, addrtype, addr, add_vendor)
                elif child.tag == 'uptime':
                    seconds = child.get('seconds')
                    lastboot = child.get('lastboot')
                elif child.tag == 'distance':
                    distance_value = child.get('value')
                elif child.tag == 'tcpsequence':
                    tcp_index = child.get('index')
                    tcp_difficulty = child.get('difficulty')
                    tcp_values = child.get('values')
                elif child.tag == 'ipidsequence':
                    ipid_class = child.get('class')
                    ipid_values = child.get('values')
                elif child.tag == 'tcptssequence':
                    tcpts_class = child.get('class')
                    tcpts_values = child.get('values')
                elif child.tag == 'times':
                    times_srtt = child.get('srtt')
                    times_rttvar = child.get('rttvar')
                    times_to = child.get('to')
                elif child.tag == 'hostnames':
                    for hostname in child.iter('hostname'):
                        hostname_name = hostname.get('name')
                        hostname_type = hostname.get('type')
                elif child.tag == 'trace':
                    for hop in child.iter('hop'):
                        hop_ttl = hop.get('ttl')
                        hop_ipaddr = hop.get('ipaddr')
                        hop_rtt = hop.get('rtt')
                        hop_host = hop.get('host')
                        DBModel.insert_device_hops(device_id, hop_ttl, hop_ipaddr, hop_rtt, hop_host)
                elif child.tag == 'ports':
                    for port in child.iter('port'):
                        port_protocol = port.get('protocol')
                        port_portid = port.get('portid')

                        for port_child in port:
                            if port_child.tag == 'state':
                                state_state = port_child.get('state')
                                state_reason = port_child.get('reason')
                                state_reason_ttl = port_child.get('reason_ttl')
                            elif port_child.tag == 'service':
                                service_name = port_child.get('name')
                                service_product = port_child.get('product')
                                service_version = port_child.get('version')
                                service_extrainfo = port_child.get('extrainfo')
                                service_ostype = port_child.get('ostype')
                                service_method = port_child.get('method')
                                service_conf = port_child.get('conf')

                                cpe_value = ''
                                for cpe in port_child.iter('cpe'):
                                    cpe_value += cpe.text + ','

                                DBModel.insert_device_ports(device_id, port_protocol, port_portid, state_state,
                                                            state_reason, state_reason_ttl, service_name,
                                                            service_product, service_version, service_ostype,
                                                            service_method, service_conf, cpe_value, service_extrainfo)
                            elif port_child.tag == 'script':
                                script_id = '' + port_child.get('id')
                                script_output = port_child.get('output')
                                script_state = ''
                                script_title = ''
                                script_key = ''
                                script_description = ''
                                script_disclosure = ''
                                script_exploit_results = ''
                                script_refs = ''

                                for script_child in port_child: #most like a table tag
                                    if script_child.tag == 'table':
                                        for global_table_child in script_child:
                                            if global_table_child.tag == 'elem':
                                                if global_table_child.get('key') == 'state':
                                                    script_state = global_table_child.text
                                                elif global_table_child.get('key') == 'title':
                                                    script_title = global_table_child.text
                                                elif global_table_child.get('key') == 'disclosure':
                                                    script_disclosure = global_table_child.text
                                                else:
                                                    print('Not accounting for this yet')
                                            elif global_table_child.tag == 'table':
                                                if global_table_child.get('key') == 'ids':
                                                    for ids_elem in global_table_child:
                                                        script_id += ids_elem.text + '\n'
                                                elif global_table_child.get('key') == 'description':
                                                    for des_elem in global_table_child:
                                                        script_description += des_elem.text + '\n'
                                                elif global_table_child.get('key') == 'exploit_results':
                                                    for exploit_elem in global_table_child:
                                                        script_exploit_results += exploit_elem.text + '\n'
                                                elif global_table_child.get('key') == 'refs':
                                                    for exploit_elem in global_table_child:
                                                        script_refs += exploit_elem.text + '\n'

                                DBModel.insert_port_vuln_script(device_id, script_id, script_output, script_state, script_title,
                                                                port_portid, script_description, script_disclosure,
                                                                script_exploit_results, script_refs)

                elif child.tag == 'os':
                    for os in host.iter('os'):
                        for portused in os.iter('portused'):
                            state = portused.get('state')
                            proto = portused.get('proto')
                            portid = portused.get('portid')
                            DBModel.insert_device_OSPortUsed(device_id, state, proto, portid)

                        for osmatch in os.iter('osmatch'):
                            osmatch_name = osmatch.get('name')
                            osmatch_accuracy = osmatch.get('accuracy')
                            osmatch_line = osmatch.get('line')

                            osclass_osgen = ''
                            osclass_type = ''
                            osclass_vendor = ''
                            osclass_osfamily = ''
                            for osclass in osmatch.iter('osclass'):
                                osclass_type += '| ' + str(osclass.get('type'))
                                osclass_vendor += ' | ' + str(osclass.get('vendor'))
                                osclass_osfamily += ' | ' + str(osclass.get('osfamily'))
                                osclass_osgen += ' | ' + str(osclass.get('osgen'))
                                osclass_accuracy = osclass.get('accuracy')

                                os_cpe_value = ''
                                for cpe in osclass.iter('cpe'):
                                    os_cpe_value += cpe.text + ','
                            DBModel.insert_device_osinfo(device_id, osmatch_name, osmatch_accuracy, osmatch_line, osclass_type,
                                                             osclass_vendor, osclass_osfamily, osclass_osgen, osclass_accuracy,
                                                             os_cpe_value)

                else:
                    print('Something else')

        # -----------------------------------------------------Runstats
        if root_child.tag == 'runstats':
            runstats = root_child
            for rchild in runstats:
                if rchild.tag == 'finished':
                    finished_time = rchild.get('time')
                    finished_timestr = rchild.get('timestr')
                    finished_elapsed = rchild.get('elapsed')
                    finished_summary = rchild.get('summary')
                    finished_exit = rchild.get('exit')
                elif rchild.tag == 'hosts':
                    hosts_up = rchild.get('up')
                    hosts_down = rchild.get('down')
                    hosts_total = rchild.get('total')
            DBModel.insert_nmap_report(device_id, services, type, protocol, numservices, starttime, endtime, state, reason,
                                       reason_ttl, hostname_name, hostname_type, seconds, lastboot, distance_value, tcp_index,
                                       tcp_difficulty, tcp_values, ipid_class, ipid_values, tcpts_class, tcpts_values,
                                       times_srtt, times_rttvar, times_to, finished_time, str(finished_timestr), str(finished_elapsed),
                                       finished_summary, finished_exit, hosts_up, hosts_down, hosts_total)

            scanner_id = DBModel.get_scan_id('NmapScanner')

            nmap_vuln_status = ''
            num = DBModel.get_nmap_vuln_stat(device_id)
            if num == 0:
                nmap_vuln_status = 'Non-vulnerable'
            else:
                nmap_vuln_status = 'Vulnerable'

            DBModel.insert_scan_results(scanner_id, 0, device_id, nmap_vuln_status, 'N/A', 0, 0, type, 'N/A')

            print(
                'Completed Nmap scan: {0}, Scan time: {1}s ( Host ID:{2}) \n'.format(time.strftime("%H:%M:%S"),
                                                                                     str(finished_elapsed), device_id))


def runScan(ip, device_id):
    launch_nmap_scan(ip, device_id)


# def parse_build(filename):
#     tree = ET.parse(filename)
#     root = tree.getroot()
#     print(root.tag)
#     for child in root:
#         if child.tag == 'host':
#             for sub_child in child:
#                 if sub_child.tag =='ports':
#                     for grand_child in sub_child:
#                         print('\n', 'This is a port tag -------', grand_child.tag)
#                         for great_child in grand_child:
#                             print(great_child.tag)
#                             print (great_child.attrib, '\n')
#                             if great_child.tag == 'script':
#                                 for x in great_child:
#                                     print(x.tag, '\n')
#                                     print(x.attrib, '\n')



if __name__ == '__main__':
    # runScan('scanme.nmap.org', 15)
    parse_xml_ouput('96.xml', 96)
    # parse_xml('96.xml')