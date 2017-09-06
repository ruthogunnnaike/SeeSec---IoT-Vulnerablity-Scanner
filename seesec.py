from peewee import *

database = SqliteDatabase('SeeSec.sqlite', **{})

class UnknownField(object):
    def __init__(self, *_, **__): pass

class BaseModel(Model):
    class Meta:
        database = database

class Availablefixes(BaseModel):
    dateadded = TextField(db_column='DateAdded', null=True)
    description = TextField(db_column='Description', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    scannerid = IntegerField(db_column='ScannerID', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    vulnerabilityid = IntegerField(db_column='VulnerabilityID', null=True)

    class Meta:
        db_table = 'AvailableFixes'

class Deviceaddress(BaseModel):
    address = TextField(db_column='Address', null=True)
    addresstype = TextField(db_column='AddressType', null=True)
    dateadded = TextField(db_column='DateAdded', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    hophost = TextField(db_column='HopHost', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    vendor = TextField(db_column='Vendor', null=True)

    class Meta:
        db_table = 'DeviceAddress'

class Devicebios(BaseModel):
    accuracy = TextField(db_column='Accuracy', null=True)
    brand = TextField(db_column='Brand', null=True)
    capacity = IntegerField(db_column='Capacity', null=True)
    dateadded = TextField(db_column='DateAdded', null=True)
    description = TextField(db_column='Description', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    ipaddress = TextField(db_column='IPAddress', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
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
    usestatus = IntegerField(db_column='UseStatus', null=True)
    version = TextField(db_column='Version', null=True)

    class Meta:
        db_table = 'DeviceBios'

class Devicehops(BaseModel):
    dateadded = TextField(db_column='DateAdded', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    hophost = TextField(db_column='HopHost', null=True)
    hopipaddress = TextField(db_column='HopIpAddress', null=True)
    hoprtt = TextField(db_column='HopRtt', null=True)
    hopttl = TextField(db_column='HopTtl', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)

    class Meta:
        db_table = 'DeviceHops'

class Deviceosinformation(BaseModel):
    dateadded = TextField(db_column='DateAdded', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    osclassaccuracy = TextField(db_column='OsclassAccuracy', null=True)
    osclasscpe = TextField(db_column='OsclassCPE', null=True)
    osclassosfamily = TextField(db_column='OsclassOsfamily', null=True)
    osclassosgen = TextField(db_column='OsclassOsgen', null=True)
    osclasstype = TextField(db_column='OsclassType', null=True)
    osclassvendor = TextField(db_column='OsclassVendor', null=True)
    osmatchaccuracy = TextField(db_column='OsmatchAccuracy', null=True)
    osmatchline = TextField(db_column='OsmatchLine', null=True)
    osmatchname = TextField(db_column='OsmatchName', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)

    class Meta:
        db_table = 'DeviceOSInformation'

class Deviceosportused(BaseModel):
    dateadded = TextField(db_column='DateAdded', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    portid = TextField(db_column='PortID', null=True)
    proto = TextField(db_column='Proto', null=True)
    state = TextField(db_column='State', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)

    class Meta:
        db_table = 'DeviceOSPortUsed'

class Deviceports(BaseModel):
    id = PrimaryKeyField(db_column='ID', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    protocol = TextField()
    portid = TextField(db_column='PortID', null=True)
    proto = TextField(db_column='Proto', null=True)
    state = TextField(db_column='State', null=True)
    reason = TextField()
    dateadded = TextField(db_column='DateAdded', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)

    class Meta:
        db_table = 'DevicePorts'

class Encryptionalgorithms(BaseModel):
    dateadded = TextField(db_column='DateAdded', null=True)
    description = TextField(db_column='Description', null=True)
    encryptiontype = TextField(db_column='EncryptionType', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    name = IntegerField(db_column='Name', null=True)
    risklevel = TextField(db_column='RiskLevel', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    vulnerable = IntegerField(db_column='Vulnerable', null=True)
    vulnerableto = TextField(db_column='VulnerableTo', null=True)

    class Meta:
        db_table = 'EncryptionAlgorithms'

class Miraireport(BaseModel):
    description = TextField(db_column='Description', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    ipaddress = TextField(db_column='IPAddress', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    response = TextField(db_column='Response', null=True)
    scandate = TextField(db_column='ScanDate', null=True)
    scantime = TextField(db_column='ScanTime', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    vulnerabilityid = IntegerField(db_column='VulnerabilityID', null=True)
    vulnerabilitystatus = TextField(db_column='VulnerabilityStatus', null=True)

    class Meta:
        db_table = 'MiraiReport'

class Nmapreport(BaseModel):
    args = TextField(db_column='Args', null=True)
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
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    numberofservices = TextField(db_column='NumberofServices', null=True)
    protocol = TextField(db_column='Protocol', null=True)
    reason = TextField(db_column='Reason', null=True)
    reasonttl = TextField(db_column='ReasonTtl', null=True)
    scanner = TextField(db_column='Scanner', null=True)
    seconds = TextField(db_column='Seconds', null=True)
    services = TextField(db_column='Services', null=True)
    start = TextField(db_column='Start', null=True)
    startstr = IntegerField(db_column='StartStr', null=True)
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
    usestatus = IntegerField(db_column='UseStatus', null=True)
    version = TextField(db_column='Version', null=True)
    xmloutputversion = TextField(db_column='XmlOutputVersion', null=True)

    class Meta:
        db_table = 'NmapReport'

class Operatingsystems(BaseModel):
    dateadded = TextField(db_column='DateAdded', null=True)
    description = TextField(db_column='Description', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    name = IntegerField(db_column='Name', null=True)
    risklevel = TextField(db_column='RiskLevel', null=True)
    safeversion = TextField(db_column='SafeVersion', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    version = TextField(db_column='Version', null=True)
    vulnerable = IntegerField(db_column='Vulnerable', null=True)

    class Meta:
        db_table = 'OperatingSystems'

class Scanresults(BaseModel):
    description = TextField(db_column='Description', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    fixavailable = IntegerField(db_column='FixAvailable', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    newpassword = TextField(db_column='NewPassword', null=True)
    resolved = IntegerField(db_column='Resolved', null=True)
    scandate = TextField(db_column='ScanDate', null=True)
    scannerid = IntegerField(db_column='ScannerID', null=True)
    type = TextField(db_column='Type', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    version = TextField(db_column='Version', null=True)
    vulnerabilityid = IntegerField(db_column='VulnerabilityID', null=True)

    class Meta:
        db_table = 'ScanResults'

class Scanners(BaseModel):
    author = TextField(db_column='Author', null=True)
    company = TextField(db_column='Company', null=True)
    dateadded = TextField(db_column='DateAdded', null=True)
    description = TextField(db_column='Description', null=True)
    function = TextField(db_column='Function', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    name = TextField(db_column='Name', null=True)
    source = TextField(db_column='Source', null=True)
    type = TextField(db_column='Type', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    version = TextField(db_column='Version', null=True)

    class Meta:
        db_table = 'Scanners'

class Sshscannerreport(BaseModel):
    combinations = IntegerField(db_column='Combinations', null=True)
    defaultpassword = TextField(db_column='DefaultPassword', null=True)
    description = TextField(db_column='Description', null=True)
    deviceid = IntegerField(db_column='DeviceID', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    ipaddress = TextField(db_column='IPAddress', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    portstatus = TextField(db_column='PortStatus', null=True)
    response = TextField(db_column='Response', null=True)
    scandate = TextField(db_column='ScanDate', null=True)
    scantime = TextField(db_column='ScanTime', null=True)
    uptime = TextField(db_column='UpTime', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    vulnerabilityid = IntegerField(db_column='VulnerabilityID', null=True)
    vulnerabilitystatus = TextField(db_column='VulnerabilityStatus', null=True)

    class Meta:
        db_table = 'SshScannerReport'

class Suggestions(BaseModel):
    dateadded = TextField(db_column='DateAdded', null=True)
    description = TextField(db_column='Description', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    scannerid = IntegerField(db_column='ScannerID', null=True)
    suggestion = TextField(db_column='Suggestion', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    vulnerabilityid = IntegerField(db_column='VulnerabilityID', null=True)

    class Meta:
        db_table = 'Suggestions'

class Vulnerability(BaseModel):
    cvereferences = TextField(db_column='CVEReferences', null=True)
    comments = TextField(db_column='Comments', null=True)
    dateadded = TextField(db_column='DateAdded', null=True)
    description = TextField(db_column='Description', null=True)
    fixavailable = IntegerField(db_column='FixAvailable', null=True)
    id = PrimaryKeyField(db_column='ID', null=True)
    lastmodifieddate = TextField(db_column='LastModifiedDate', null=True)
    name = TextField(db_column='Name', null=True)
    phases = TextField(db_column='Phases', null=True)
    status = TextField(db_column='Status', null=True)
    usestatus = IntegerField(db_column='UseStatus', null=True)
    votes = TextField(db_column='Votes', null=True)

    class Meta:
        db_table = 'Vulnerability'

class SqliteSequence(BaseModel):
    name = UnknownField(null=True)  # 
    seq = UnknownField(null=True)  # 

    class Meta:
        db_table = 'sqlite_sequence'

