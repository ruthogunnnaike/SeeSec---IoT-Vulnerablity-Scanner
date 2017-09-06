from peewee import *
from datetime import *



db_seesec = SqliteDatabase('SeeSec.sqlite') #, check_same_threads=False)
class BaseModel(Model):
    class Meta:
        database = db_seesec  # This model uses SeeSec database


class AvailableFix(BaseModel):
    id = IntegerField(unique=True)
    vulnerability_id = IntegerField()
    scannerid = IntegerField()
    description = TextField()
    dateadded = TextField()
    lastmodifieddate = TextField(default=str(datetime.now()))
    usestatus = IntegerField(default=1)


class Scanners(BaseModel):
    id = IntegerField(unique=True)
    name = TextField()
    description = TextField()
    author = TextField()
    function = TextField()
    company = TextField()
    type = TextField()
    version = TextField()
    source = TextField
    dateadded = TextField(default=str(datetime.now()))
    lastmodifieddate = TextField(default=str(datetime.now()))
    usestatus = IntegerField(default=1)


class Vulnerability(BaseModel):
    id = IntegerField(unique=True)
    name = TextField()
    description = TextField()
    cvereferences = TextField()
    phases = TextField()
    votes = TextField()
    comments = TextField()
    fixavailable = IntegerField()
    dateadded = TextField()
    lastmodifieddate = TextField(default=str(datetime.now()))
    usestatus = IntegerField(default=1)


class IoTOperatingSystems(BaseModel):
    id = IntegerField(unique=True)
    name = TextField()
    description = TextField()
    version = TextField()
    vulnerable = IntegerField()
    patch_available = IntegerField()
    dateadded = TextField()
    lastmodifieddate = TextField(default=str(datetime.now()))
    userstatus = IntegerField(default=1)


class Suggestions(BaseModel):
    id = IntegerField(unique=True)
    vulnerability_id = ForeignKeyField(Vulnerability)
    scanner_id = ForeignKeyField(Scanners)
    description = TextField()
    suggestion = TextField()
    dateadded = TextField(default=str(datetime.now()))
    lastmodifieddate = TextField(default=str(datetime.now()))
    usestatus = IntegerField(default=1)


class SshScannerReport(BaseModel):
    id = IntegerField(unique=True)
    VulnerabilityID = IntegerField()
    DeviceID = IntegerField()
    IPAddress = TextField()
    Description = TextField()
    ScanTime = TextField()
    UpTime = TextField()
    PortStatus = TextField()
    Response = TextField()
    DefaultPassword = TextField()
    Combinations = IntegerField()
    VulnerabilityStatus = TextField()
    ScanDate = TextField(default=str(datetime.now()))
    LastModifiedDate = TextField(default=str(datetime.now()))
    UseStatus = IntegerField(default=1)


class MiraiReport(BaseModel):
    id = IntegerField(unique=True)
    VulnerabilityID = IntegerField()
    DeviceID = IntegerField()
    IPAddress = TextField()
    Description = TextField()
    ScanTime = TextField()
    Response = TextField()
    VulnerabilityStatus = TextField()
    ScanDate = TextField(default=str(datetime.now()))
    LastModifiedDate = TextField(default=str(datetime.now()))
    UseStatus = IntegerField(default=1)


class ScanResults(BaseModel):
    id = IntegerField(unique=True, primary_key=True)
    vulnerabilityid = IntegerField()  # ForeignKeyField(Vulnerability, related_name='to_scan_results')
    scannerid = IntegerField()  # ForeignKeyField(Scanners, related_name='to_scanners')
    deviceid = IntegerField()  # ForeignKeyField(DeviceBios, related_name='to_devices')
    description = TextField()
    newpassword = TextField()
    resolved = IntegerField(default=0)
    fixavailable = IntegerField(default=0) # ForeignKeyField(Vulnerability, related_name='to_scan_results_fix')
    type = TextField()
    version = TextField()
    scandate = TextField(default=str(datetime.now()))
    lastmodifieddate = TextField(default=str(datetime.now()))
    usestatus = IntegerField(default=1)


class OperatingSystems(BaseModel):
    id = IntegerField(unique=True, primary_key=True)
    Name = TextField()
    Description = TextField()
    Vulnerable = IntegerField()
    RiskLevel = TextField()
    Version = TextField()
    SafeVersion = TextField()
    DateAdded = TextField(default=str(datetime.now()))
    LastModifiedDate = TextField(default=str(datetime.now()))
    UseStatus = IntegerField(default=1)


class EncryptionAlgorithms(BaseModel):
    id = IntegerField(unique=True, primary_key=True)
    Name = TextField()
    EncryptionType = TextField()
    Description = TextField()
    Vulnerable = IntegerField()
    RiskLevel = TextField()
    VulnerableTo = TextField()
    DateAdded = TextField(default=str(datetime.now()))
    LastModifiedDate = TextField(default=str(datetime.now()))
    UseStatus = IntegerField(default=1)


class DeviceAddress(BaseModel):
    id = PrimaryKeyField(db_column='ID', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    addresstype = TextField(db_column='AddressType', null=True)
    address = TextField(db_column='Address', null=True)
    vendor = TextField(db_column='Vendor', null=True)
    hophost = TextField(db_column='HopHost', null=True)
    dateadded = TextField(db_column='DateAdded', null=True, default=str(datetime.now()))
    lastmodifieddate = TextField(default=str(datetime.now()))
    usestatus = IntegerField(db_column='UseStatus', null=True, default=1)

    class Meta:
        db_table = 'DeviceAddress'


class DeviceBios(BaseModel):
    id = PrimaryKeyField(db_column='ID', null=True)
    accuracy = TextField(db_column='Accuracy', null=True)
    brand = TextField(db_column='Brand', null=True)
    version = TextField(db_column='Version', null=True)
    capacity = IntegerField(db_column='Capacity', null=True)
    description = TextField(db_column='Description', null=True)
    ipaddress = TextField(db_column='IPAddress', null=True)
    lastsoftwareupdated = TextField(db_column='LastSoftwareUpdated', null=True)
    macaddress = TextField(db_column='MacAddress', null=True)
    manufacturedate = TextField(db_column='ManufactureDate', null=True)
    manufacturer = TextField(db_column='Manufacturer', null=True)
    memory = IntegerField(db_column='Memory', null=True)
    model = TextField(db_column='Model', null=True)
    name = TextField(db_column='Name', null=True)
    numberofservices = TextField(db_column='NumberOfServices', null=True)
    operatingsystem = TextField(db_column='OperatingSystem', null=True)
    type = TextField(db_column='Type', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True, default=1)
    dateadded = TextField(db_column='DateAdded', null=True, default=str(datetime.now()))
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True, default=str(datetime.now()))


class DeviceHops(BaseModel):
    dateadded = TextField(db_column='DateAdded', null=True, default=str(datetime.now()))
    deviceid = IntegerField(db_column='DeviceID', null=True)
    hophost = TextField(db_column='HopHost', null=True)
    hopipaddress = TextField(db_column='HopIpAddress', null=True)
    hoprtt = TextField(db_column='HopRtt', null=True)
    hopttl = TextField(db_column='HopTtl', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True, default=str(datetime.now()))
    usestatus = IntegerField(db_column='UseStatus', null=True, default=1)

    class Meta:
        db_table = 'DeviceHops'


class DeviceOSInformation(BaseModel):
    id = PrimaryKeyField(db_column='ID', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    osmatchname = TextField(db_column='OsmatchName', null=True)
    osmatchaccuracy = TextField(db_column='OsmatchAccuracy', null=True)
    osmatchline = TextField(db_column='OsmatchLine', null=True)
    osclasstype = TextField(db_column='OsclassType', null=True)
    osclassvendor = TextField(db_column='OsclassVendor', null=True)
    osclassosfamily = TextField(db_column='OsclassOsfamily', null=True)
    osclassosgen = TextField(db_column='OsclassOsgen', null=True)
    osclassaccuracy = TextField(db_column='OsclassAccuracy', null=True)
    osclasscpe = TextField(db_column='OsclassCPE', null=True)
    dateadded = TextField(db_column='DateAdded', null=True, default=str(datetime.now()))
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True, default=str(datetime.now()))
    usestatus = IntegerField(db_column='UseStatus', null=True, default=1)

    class Meta:
        db_table = 'DeviceOSInformation'

class DeviceOSPortUsed(BaseModel):
    id = PrimaryKeyField(db_column='ID', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    state = TextField(db_column='State', null=True)
    proto = TextField(db_column='Proto', null=True)
    portid = TextField(db_column='PortID', null=True)
    dateadded = TextField(db_column='DateAdded', null=True, default=str(datetime.now()))
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True, default=str(datetime.now()))
    usestatus = IntegerField(db_column='UseStatus', null=True, default=1)

    class Meta:
        db_table = 'DeviceOSPortUsed'

class DevicePorts(BaseModel):
    id = PrimaryKeyField(db_column='ID', null=True)
    deviceid=IntegerField()
    protocol= TextField()
    portid= TextField()
    state= TextField()
    reason= TextField()
    reasonttl= TextField()
    servicename= TextField()
    products= TextField()
    version= TextField()
    extrainfo = TextField()
    ostype= TextField()
    method= TextField()
    conf= TextField()
    dateadded = TextField(default=str(datetime.now()))
    lastmodifieddate = TextField(default=str(datetime.now()))
    usestatus = TextField(default=1)

class NmapReport(BaseModel):
    deviceid = IntegerField(db_column='DeviceID', null=True)
    distancevalue = IntegerField(db_column='DistanceValue', null=True)
    endtime = TextField(db_column='EndTime', null=True)
    finishedelapsed = TextField(db_column='FinishedElapsed', null=True)
    finishedexit = TextField(db_column='FinishedExit', null=True)
    finishedsummary = TextField(db_column='FinishedSummary', null=True)
    finishedtime = TextField(db_column='FinishedTime', null=True)
    finishedtimestr = TextField(db_column='FinishedTimeStr', null=True)
    hostname = TextField(db_column='HostName', null=True)
    hosttype = TextField(db_column='HostType', null=True)
    hostsdown = TextField(db_column='HostsDown', null=True)
    hoststotal = TextField(db_column='HostsTotal', null=True)
    hostsup = TextField(db_column='HostsUp', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    ipidclass = TextField(db_column='IPIDClass', null=True)
    ipidvalues = TextField(db_column='IPIDValues', null=True)
    lastboot = TextField(db_column='LastBoot', null=True)
    dateadded = TextField(db_column='DateAdded', null=True, default=str(datetime.now()))
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True, default=str(datetime.now()))
    numberofservices = TextField(db_column='NumberofServices', null=True)
    protocol = TextField(db_column='Protocol', null=True)
    reason = TextField(db_column='Reason', null=True)
    reasonttl = TextField(db_column='ReasonTtl', null=True)
    seconds = TextField(db_column='Seconds', null=True)
    services = TextField(db_column='Services', null=True)
    start = TextField(db_column='Start', null=True)
    starttime = TextField(db_column='StartTime', null=True)
    state = TextField(db_column='State', null=True)
    tcpdifficulty = TextField(db_column='TCPDifficulty', null=True)
    tcpindex = TextField(db_column='TCPIndex', null=True)
    tcptsclass = TextField(db_column='TCPTSClass', null=True)
    tcptsvalues = TextField(db_column='TCPTSValues', null=True)
    tcpvalues = TextField(db_column='TCPValues', null=True)
    timesrttvar = TextField(db_column='TimesRttvar', null=True)
    timessrtt = TextField(db_column='TimesSrtt', null=True)
    timesto = TextField(db_column='TimesTo', null=True)
    type = TextField(db_column='Type', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True, default=1)
    version = TextField(db_column='Version', null=True)

    class Meta:
        db_table = 'NmapReport'


class DeviceNmapVulnScripts(BaseModel):
    id = PrimaryKeyField(db_column='ID', null=True)
    deviceid=IntegerField()
    scriptid= TextField()
    output= TextField()
    state= TextField()
    title= TextField()
    key= TextField()
    description= TextField()
    disclosure= TextField()
    exploitsresults= TextField()
    refs = TextField()
    dateadded = TextField(default=str(datetime.now()))
    lastmodifieddate = TextField(default=str(datetime.now()))
    usestatus = TextField(default=1)


db_seesec.connect()

#  ---------------------------------------INSERT METHODS (BEFORE SCAN)------------------------


def insert_port_vuln_script(device_id, script_id, script_output, script_state, script_title, script_key, script_description,
                            script_disclosure, script_exploit_results, script_refs):
    port_vuln_script = DeviceNmapVulnScripts(deviceid=device_id,
                                             scriptid=script_id,
                                             output=script_output,
                                        state=script_state,
                                        title=script_title,
                                        key=script_key,
                                        description=script_description,
                                             disclosure=script_disclosure,
                                             exploitsresults=script_exploit_results,
                                        refs=script_refs)

    port_vuln_script.save()


def insert_address(device_id, addrtype, addr, add_vendor):
    device_address = DeviceAddress(deviceid=device_id,
                                         addresstype=addrtype,
                                         address=addr,
                                         vendor=add_vendor)
    device_address.save()


def insert_device_osinfo(device_id, osmatch_name, osmatch_accuracy, osmatch_line, osclass_type, osclass_vendor,
                         osclass_osfamily, osclass_osgen, osclass_accuracy, os_cpe_value):

    db_seesec = SqliteDatabase('SeeSec.sqlite')  # , check_same_threads=False)
    db_seesec.connect()
    device_osinfo = DeviceOSInformation(deviceid=device_id,
                                        osmatchname=osmatch_name,
                                        osmatchaccuracy=osmatch_accuracy,
                                        osmatchline=osmatch_line,
                                        osclasstype=osclass_type,
                                        osclassvendor=osclass_vendor,
                                        osclassosfamily=osclass_osfamily,
                                        osclassosgen=osclass_osgen,
                                        osclassaccuracy=osclass_accuracy,
                                        osclasscpe=os_cpe_value)

    device_osinfo.save()


def insert_device_hops(device_id, hop_ttl, hop_ipaddr, hop_rtt, hop_host):
    device_hops = DeviceHops(deviceid=device_id,
                                     hopttl=hop_ttl,
                                     hopipaddress=hop_ipaddr,
                                     hoprtt=hop_rtt,
                                     hophost=hop_host)

    device_hops.save()


def insert_device_OSPortUsed(device_id, state, proto, portid):
    device_osport_used = DeviceOSPortUsed(deviceid=device_id,
                                        state=state,
                                        proto=proto,
                                        portid=portid)

    device_osport_used.save()


def insert_device_ports(device_id, port_protocol, port_portid, state_state, state_reason, state_reason_ttl,
                                service_name, service_product, service_version, service_ostype, service_method,
                                service_conf, cpe_value, service_extrainfo):
    device_ports = DevicePorts(
        deviceid=device_id,
    protocol=port_protocol,
    portid=port_portid ,
    state=state_state ,
    reason=state_reason,
    reasonttl=state_reason_ttl ,
    servicename=service_name ,
    products=service_product ,
    version=service_version,
    ostype=service_ostype,
    method=service_method,
    conf=service_conf,
    cpe = cpe_value,
        extrainfo= service_extrainfo
    )

    device_ports.save()


def insert_nmap_report(device_id, services, type,
                               protocol, numservices, starttime, endtime, state, reason, reason_ttl, hostname_name,
                               hostname_type, seconds, lastboot, distance_value, tcp_index, tcp_difficulty,
                               tcp_values, ipid_class, ipid_values, tcpts_class, tcpts_values, times_srtt,
                               times_rttvar, times_to, finished_time, finished_timestr, finished_elapsed,
                               finished_summary, finished_exit, hosts_up, hosts_down, hosts_total):
    nmap_report = NmapReport(
        deviceid=device_id,
        distancevalue=distance_value,
        endtime=endtime,
        finishedelapsed=finished_elapsed,
        finishedexit=finished_exit,
        finishedsummary=finished_summary,
        seconds=seconds,
        tcpdifficulty=tcp_difficulty,
    state=state,
    starttime=starttime,
    services=services,
    reasonttl=reason_ttl,
    protocol=protocol,
    numberofservices=numservices,
    reason=reason,
    lastboot=lastboot,
    ipidvalues=ipid_values,
    ipidclass=ipid_class,
    hostsup=hosts_up,
    hoststotal=hosts_total,
    hostsdown =hosts_down,
    hosttype=hostname_type,
    hostname=hostname_name,
    finishedtimestr=finished_timestr,
        tcpindex=tcp_index,
        tcptsclass=tcpts_class,
        tcptsvalues=tcpts_values,
        tcpvalues=tcp_values,
        timesrttvar=times_rttvar,
        timessrtt=times_srtt,
        timesto=times_to,
        type=type,
    finishedtime=finished_time)

    nmap_report.save()


def insert_sshscanner_report(vulnerability_id, device_id, ip_address, description, scan_time, up_time, port_status,
                             response, default_password, combinations, vulnerability_status):
    ssh_scanner = SshScannerReport(VulnerabilityID=vulnerability_id,
                                   DeviceID=device_id,
                                   IPAddress=ip_address,
                                   Description=description,
                                   ScanTime=scan_time,
                                   UpTime=up_time,
                                   PortStatus=port_status,
                                   Response=response,
                                   DefaultPassword=default_password,
                                   Combinations=combinations,
                                   VulnerabilityStatus=vulnerability_status,
                                   ScanDate=datetime.now(),
                                   LastModifiedDate=datetime.now())

    ssh_scanner.save()
    qry = SshScannerReport.select().order_by(SshScannerReport.id.desc()).get().id
    return qry


def insert_miraiscanner_report(vulnerability_id, device_id, ip_address, description, scan_time, response,
                               vulnerability_status):
    mirai_scanner = MiraiReport(VulnerabilityID=vulnerability_id,
                                   DeviceID=device_id,
                                   IPAddress=ip_address,
                                   Description=description,
                                   ScanTime=scan_time,
                                   Response=response,
                                   VulnerabilityStatus=vulnerability_status,
                                   ScanDate=datetime.now(),
                                   LastModifiedDate=datetime.now())

    mirai_scanner.save()
    mirai_qry = MiraiReport.select().order_by(MiraiReport.id.desc()).get().id
    return mirai_qry


def insert_device_bios(name, description, mac_address, ip_address, manufacturer, brand, model, type, version,
                       operating_system, memory, capacity, accuracy, numberservices):
        iot_device = DeviceBios(name=name,
                                   description=description,
                                   macaddress=mac_address,
                                   ipaddress=ip_address,
                                   manufacturer =manufacturer,
                                   brand=brand,
                                   model=model,
                                   type=type,
                                   version=version,
                                   operatingsystem=operating_system,
                                   memory=memory,
                                   capacity=capacity,
                                   accuracy=accuracy,
                                   numberofservices=numberservices,
                                   manufacturedate=datetime.now(),
                                   lastsoftwareupdated=datetime.now(),
                                   dateadded=datetime.now(),
                                   lastmodifieddate=datetime.now())
        iot_device.save()
        qry = DeviceBios.select().order_by(DeviceBios.id.desc()).get().id
        return qry


def insert_scan_results(scanner_id, vulnerability_id,  device_id, description, new_password, resolved, fix_available,
                        scan_type, version):
    scan_result = ScanResults(scannerid=scanner_id,
                              vulnerabilityid=vulnerability_id,
                              deviceid=device_id,
                              description=description,
                              newpassword=new_password,
                              resolved=resolved,
                              fixavailable=fix_available,
                              type=scan_type,
                              version=version,
                              scandate=datetime.now(),
                              lastmodifieddate=datetime.now()
                              )

    scan_result.save()
    scan_result_qry = ScanResults.select().order_by(ScanResults.id.desc()).get().id
    return scan_result_qry


#  ---------------------------------------AFTER SCAN METHODS------------------------





def get_scan_results(device_id):
    qry = ScanResults.select(ScanResults, Vulnerability.name).join(Vulnerability, on=Vulnerability.id).where(
         ScanResults.device_id == device_id)
    qry.execute
    for msg in qry:
        print('Suggestions for fixing vulnerability: {0}'.format(msg))
    print('Scan Results')


def is_fix_available(vulnerability_id):
    qry = AvailableFix.select(AvailableFix.description, Suggestions.suggestion).where(
        Suggestions.vulnerability_id == vulnerability_id)
    qry.execute()
    for msg in qry:
        print ('Fix is available for %s', vulnerability_id)


def get_suggestions(vulnerability_id):
    qry = Suggestions.select(Suggestions.description, Suggestions.suggestion).where(Suggestions.vulnerability_id
                                                                                    == vulnerability_id)
    qry.execute
    for msg in qry:
        print('Suggestions for fixing vulnerability: {0}'.format(msg.description))


def get_vulnerability():
    qry = Vulnerability.select().where(Vulnerability.name == 'CVE-2015-5611')
    qry.execute()
    for msg in qry:
        print(msg.description)


def get_scan_id(scanner_name):
    scanner_id = Scanners.select().where(Scanners.name == scanner_name).get().id
    return scanner_id


def insert_new_scanner():
    print('New scanner added successfully')


def get_nmap_vuln_stat(device_id):
    qry = DeviceNmapVulnScripts.select(DeviceNmapVulnScripts.id).where(
        (DeviceNmapVulnScripts.deviceid == device_id),
        ((DeviceNmapVulnScripts.state == 'LIKELY VULNERABLE') | (DeviceNmapVulnScripts.state == 'VULNERABLE'))
    ).execute()
    return qry.count


def get_vulnerability_status(device_id):
    qry = ScanResults.select(ScanResults.description).where(ScanResults.deviceid == device_id
                                                                               ).execute()

    # list = [[]]
    # for vuln_stat in qry:
    #     print(str(vuln_stat.description))
    #     list.append([vuln_stat.description])
    return qry


def get_scan_report(device_id):
    report = ''
    device_info = get_device_info(device_id)
    ports_used = get_device_portsused(device_id)
    ports = get_device_ports(device_id)
    vuln_checks = get_device_vuln_checks(device_id)

    report += '\n **************************SCAN REPORT************************* \n'
    report += '***Device Information \n'
    report += 'IP Address: {0} \n'.format(device_info[0])
    report += 'Mac Address: {0} \n'.format(device_info[1])
    report += 'Vendor Address: {0} \n'.format(device_info[2])

    report += '\n***Ports Used \n'
    report += 'Port\t Protocol\t State \n'
    for used in ports_used:
        report += '{0}\t     {1}\t     {2} \n'.format(str(used.portid), str(used.proto), str(used.state))

    report += '\n***Device Ports Information \n'
    # report.py += 'Port\t Protocol\t State  \t Service_Name\t\t Products\t    Version\t\\t Type_of_Operating_System \n'
    for item in ports:
        report += '{0}\tProtocol: {1}\t   State: {2}\t  Service_Name:  {3}\tProducts: {4}\tVersion: {5}\t' \
                  'Type of Operating System: {6} \n'.format(
            str(item.portid), str(item.protocol), str(item.state), str(item.servicename), str(item.products),
              str(item.version), str(item.ostype))

    report += '\n*****************VULNERABILITY CHECKS \n'
    count = 0
    for vulns in vuln_checks:
        if len(vulns) != 0:
            count += 1
            if vulns[0] in ('SSH Scanner: Remote shell login','Mirai Scanner: Password Scanner'):
                report += '{0}. {1}{8}  \n\t State: {2}\n\t Title: {3}\n\t Key: {4} \n\t Description: {5}\n\t ' \
                          'Exploit Results: {6} \n\t References: {7} \n'\
                          '\n'.format(count, vulns[0], vulns[1], vulns[2], vulns[3], vulns[4], vulns[5], vulns[6],
                                      vulns[7])
            else:
                report += '{0}. {1}{2} \n'.format(count, vulns[0], vulns[7])
                          # '\n'.format(count, vulns[0], vulns[1], vulns[2], vulns[3], vulns[4], vulns[5], vulns[6], vulns[7])

                # report += '{0}. {1}{8}  \n\t State: {2}\n\t Title: {3}\n\t Key: {4} \n\t Description: {5}\n\t Exploit Results: {6} \n\t' \
                #           ' References: {7} \n'\
                #           '\n'.format(count, vulns[0], vulns[1], vulns[2], vulns[3], vulns[4], vulns[5], vulns[6], vulns[7])

    print(report)
    # return report


def get_device_info(device_id):
    list = []
    # mac_address=''
    # ip_address=''

    try:
        ip_address = DeviceAddress.select(DeviceAddress.address).where(
            DeviceAddress.deviceid == device_id, DeviceAddress.addresstype == 'ipv4').get().address
    except DeviceAddress.DoesNotExist:
        list.append('N/A')
    else:
        if ip_address in ('None', ''):
            list.append('NIL')
        else:
            list.append(ip_address)

    try:
        mac_address = DeviceAddress.select(DeviceAddress.address).where(
            DeviceAddress.deviceid == device_id, DeviceAddress.addresstype == 'mac').get().address
    except DeviceAddress.DoesNotExist:
        list.append('N/A')
    else:
        if mac_address in ('None', ''):
            list.append('NIL')
        else:
            list.append(mac_address)

    try:
        vendor = DeviceAddress.select(DeviceAddress.vendor).where(
            DeviceAddress.deviceid == device_id, DeviceAddress.addresstype == 'mac').get().vendor
    except DeviceAddress.DoesNotExist:
        list.append('N/A')
    else:
        if vendor in ('None', ''):
            list.append('NIL')
        else:
            list.append(vendor)

    return list


def get_device_hops(device_id):
    qry = DeviceAddress.select(DeviceAddress.address).where(
        DeviceAddress.deviceid == device_id, DeviceAddress.addresstype == 'ipv4').get().address


def get_device_portsused(device_id):
    list = [[]]
    qry = DeviceOSPortUsed.select(DeviceOSPortUsed.portid, DeviceOSPortUsed.proto, DeviceOSPortUsed.state).where(
        DeviceOSPortUsed.deviceid == device_id).order_by(DeviceOSPortUsed.portid.asc()).execute()

    return qry


def get_device_ports(device_id):
    list = [[]]
    qry = DevicePorts.select(DevicePorts.portid, DevicePorts.protocol, DevicePorts.state, DevicePorts.servicename,
                             DevicePorts.products, DevicePorts.version, DevicePorts.ostype).where(
        DevicePorts.deviceid == device_id).order_by(DevicePorts.products.desc()).execute()

    return qry


def get_device_os_services(device_id):
    print('s')

def get_device_os_services(device_id):
    print('s')

def get_suggestions(device_id):
    print('s')


def get_device_vuln_checks(device_id):
    list = [[]]
    try:
        nmap = DeviceNmapVulnScripts.select(DeviceNmapVulnScripts.scriptid, DeviceNmapVulnScripts.state,
                                            DeviceNmapVulnScripts.title, DeviceNmapVulnScripts.key,
                                            DeviceNmapVulnScripts.description, DeviceNmapVulnScripts.exploitsresults,
                                            DeviceNmapVulnScripts.refs, DeviceNmapVulnScripts.output).where(
            DeviceNmapVulnScripts.deviceid == device_id).execute()
    except DeviceNmapVulnScripts.DoesNotExist:
        list.append(['Nmap: Vulnerability checks was not successful for device: {0)'.format(device_id), '', '', '', '',
                     '', '', ''])
    else:
        for item in nmap:
            list.append(['NMAP Scanner --Port[{0}]: '.format(str(item.key)) + str(item.scriptid), str(item.state),
                         str(item.title), str(item.key), str(item.description), str(item.exploitsresults),
                         str(item.refs), str(item.output)])

    ssh_scanner = SshScannerReport.select(SshScannerReport.VulnerabilityStatus, SshScannerReport.Description).where(
        SshScannerReport.DeviceID == device_id).execute()
    for ssh in ssh_scanner:
        list.append(['SSH Scanner: Remote shell login', str(ssh.VulnerabilityStatus), 'Default/Weak password scanner', '',
                     str(ssh.Description), '', '', ''])

    mirai_scanner = MiraiReport.select(MiraiReport.VulnerabilityStatus, MiraiReport.Description).where(
        MiraiReport.DeviceID == device_id).execute()
    for mirai in mirai_scanner:
        list.append(['Mirai Scanner: Password Scanner', str(mirai.VulnerabilityStatus), 'Device factory credentials', '',
                 str(mirai.Description), '', '', ''])

    return list


def get_vulns_scanid(device_id):
    list = []
    vulns_scans = ScanResults.select(ScanResults.scannerid).where(ScanResults.description == 'Vulnerable',
                                                                  ScanResults.deviceid == device_id,
                                                                  ScanResults.fixavailable == 1).execute()
    for scanid in vulns_scans:
        list.append(scanid.scannerid)
        # print(scanid.scannerid)
    return list

if __name__ == "__main__":
    # ID = insert_device_bios('new', 'description', '54:ty:867', '172.34.98.76', 'manufacturer', 'brand', 'model',
    #                          'type', 'version', 'operating_system', 4, 5)
    # insert_scan_results(1, 2, 3, 'description', 'xyz', 1, 1, 'Badlock', 'version')
    # get_vulnerability()
    get_scan_report(100)
    # print('Database creation completed successfully {0}'.format(ID))



