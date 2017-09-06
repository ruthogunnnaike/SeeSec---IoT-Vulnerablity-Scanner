import csv
import sqlite3
#from peewee import*
from datetime import*


def create_database():
    sqlite_db = 'SeeSec.sqlite.sqlite'
    print('Creating database: {0}. Version: {1}'.format(sqlite_db, sqlite3.version))
    print('Connecting to {0}'.format(sqlite_db))

    conn = sqlite3.connect('SeeSec.sqlite')
    print('Database connection successful')

    cursor = conn.cursor()
    cursor.execute(''' 
    CREATE TABLE IF NOT EXISTS Vulnerability(ID INTEGER PRIMARY KEY AUTOINCREMENT,    
                                           Name TEXT,
                                           Status TEXT,
                                           Description TEXT,
                                           CVEReferences TEXT,
                                           Phases TEXT,
                                           Votes TEXT,
                                           Comments TEXT,
                                           FixAvailable INTEGER,
                                           DateAdded TEXT,                                       
                                           LastModifiedDate TEXT,
                                           UseStatus INTEGER) 
    ''')

    reader = csv.reader(open('IoTVulnerabilities.csv', 'rb'))
    int_value = 1
    for row in reader:
        insert_value = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), unicode(row[2], 'utf8'),
                        unicode(row[3], 'utf8'), unicode(row[4], 'utf8'), unicode(row[5], 'utf8'),
                        unicode(row[6], 'utf8'), int_value, datetime.now(), datetime.now(), int_value]

        cursor.execute('INSERT INTO Vulnerability (Name, Status, Description, CVEReferences, Phases, Votes, Comments, '
                       'FixAvailable, DateAdded, LastModifiedDate, UseStatus) VALUES(?, ?, ?, ?, ? ,? ,? ,? ,?, ?, ?);',
                       insert_value)
        conn.commit()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS DeviceBios(ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                           Name TEXT,
                                           Description TEXT,
                                           MacAddress TEXT,
                                           IPAddress TEXT,
                                           Manufacturer TEXT,
                                           Brand TEXT,
                                           Model TEXT,
                                           Type TEXT,
                                           Version TEXT,
                                           OperatingSystem TEXT,
                                           Memory INTEGER,
                                           Capacity INTEGER ,
                                           Accuracy TEXT,
                                           NumberOfServices TEXT,
                                           ManufactureDate TEXT,
                                           LastSoftwareUpdated TEXT,
                                           DateAdded TEXT,
                                           LastModifiedDate TEXT,
                                           UseStatus INTEGER)                                       
    ''')
    conn.commit()

    cursor.execute('''
      CREATE TABLE IF NOT EXISTS DeviceOSInformation(ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                                    DeviceID INTEGER,
                                                    OsmatchName TEXT,
                                                    OsmatchAccuracy TEXT,
                                                    OsmatchLine TEXT,
                                                    OsclassType TEXT,
                                                    OsclassVendor TEXT,
                                                    OsclassOsfamily TEXT,
                                                    OsclassOsgen TEXT,
                                                    OsclassAccuracy TEXT,
                                                    OsclassCPE TEXT, 
                                                    DateAdded TEXT,
                                                    LastModifiedDate TEXT, 
                                                    UseStatus INTEGER)                                       
      ''')


    cursor.execute('''
          CREATE TABLE IF NOT EXISTS DeviceHops(ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                                        DeviceID INTEGER,
                                                        HopTtl TEXT,
                                                        HopIpAddress TEXT,
                                                        HopRtt TEXT,
                                                        HopHost TEXT, 
                                                        DateAdded TEXT,
                                                        LastModifiedDate TEXT, 
                                                        UseStatus INTEGER)                                       
          ''')

    cursor.execute('''
             CREATE TABLE IF NOT EXISTS DeviceAddress(ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                                           DeviceID INTEGER,
                                                           AddressType TEXT,
                                                           Address TEXT,
                                                           Vendor TEXT,
                                                           HopHost TEXT, 
                                                           DateAdded TEXT,
                                                           LastModifiedDate TEXT, 
                                                           UseStatus INTEGER)                                       
             ''')


    cursor.execute('''
                CREATE TABLE IF NOT EXISTS DeviceOSPortUsed(ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                                              DeviceID INTEGER,
                                                              State TEXT,
                                                              Proto TEXT,
                                                              PortID TEXT, 
                                                              DateAdded TEXT,
                                                              LastModifiedDate TEXT, 
                                                              UseStatus INTEGER)                                       
                ''')

    # cursor.execute('''
    #                 CREATE TABLE IF NOT EXISTS DevicePorts(ID INTEGER PRIMARY KEY AUTOINCREMENT,
    #                                                               DeviceID INTEGER,
    #                                                               State TEXT,
    #                                                               Proto TEXT,
    #                                                               PortID TEXT,
    #                                                               DateAdded TEXT,
    #                                                               LastModifiedDate TEXT,
    #                                                               UseStatus INTEGER)
    #                 ''')

    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS DevicePorts(ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                                    DeviceID INTEGER,
                                                    Protocol TEXT,
                                                    PortID TEXT, 
                                                    State TEXT, 
                                                    Reason TEXT,
                                                    ReasonTtl TEXT,
                                                    ServiceName TEXT,
                                                    Products TEXT,
                                                    Version TEXT,
                                                    ExtraInfo TEXT,
                                                    OsType TEXT, 
                                                    Method TEXT, 
                                                    Conf TEXT,
                                                    Cpe TEXT,
                                                    DateAdded TEXT, 
                                                    LastModifiedDate TEXT, 
                                                    UseStatus INTEGER)                                       
      ''')


    cursor.execute(''' 
    CREATE TABLE IF NOT EXISTS AvailableFixes(ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                           VulnerabilityID INTEGER,
                                           ScannerID INTEGER,
                                           Description TEXT, 
                                           DateAdded TEXT,
                                           LastModifiedDate TEXT,
                                           UseStatus INTEGER)             
    ''')

    # fixed_reader = csv.reader(open('AvailableFixes.csv', 'rb'))
    # for row in fixed_reader:
    #     insert_fixes = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), unicode(row[2], 'utf8'), datetime.now(),
    #                     datetime.now(), int_value]
    #
    #     cursor.execute('INSERT INTO AvailableFixes (VulnerabilityID, ScannerID, Description, DateAdded,'
    #                    ' LastModifiedDate, UseStatus) VALUES(?, ?, ?, ?, ? , ? ,? ,? ,?);',
    #                    insert_fixes)
    #     conn.commit()

    cursor.execute(''' 
    CREATE TABLE IF NOT EXISTS Suggestions(ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                           VulnerabilityID INTEGER,
                                           ScannerID INTEGER,
                                           Description TEXT, 
                                           Suggestion TEXT, 
                                           DateAdded TEXT,
                                           LastModifiedDate TEXT,
                                           UseStatus INTEGER)             
    ''')

    # suggestions_reader = csv.reader(open('Suggestions.csv', 'rb'))
    # for row in suggestions_reader:
    #     insert_suggestions = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), unicode(row[2], 'utf8'),
    #                           unicode(row[3], 'utf8'), datetime.now(), datetime.now(), int_value]
    #
    #     cursor.execute('INSERT INTO Suggestions (VulnerabilityID, ScannerID, Description, Suggestion, DateAdded,'
    #                    ' LastModifiedDate, UseStatus) VALUES(?, ?, ?, ?, ? , ? ,? ,? ,?);',
    #                    insert_suggestions)
    #     conn.commit()

    cursor.execute(''' 
  CREATE TABLE IF NOT EXISTS ScanResults(ID INTEGER  PRIMARY KEY AUTOINCREMENT,                          
                                           ScannerID INTEGER,
                                           VulnerabilityID INTEGER,
                                           DeviceID INTEGER,
                                           Description TEXT,
                                           NewPassword TEXT,
                                           Resolved INTEGER,
                                           FixAvailable INTEGER, 
                                           Type TEXT,
                                           Version TEXT,                                        
                                           ScanDate TEXT,
                                           LastModifiedDate TEXT,                                       
                                           UseStatus INTEGER
                                   )
    ''')
    conn.commit()

    cursor.execute(''' 
    CREATE TABLE IF NOT EXISTS Scanners(ID INTEGER PRIMARY KEY,
                                           Name TEXT,
                                           Description TEXT, 
                                           Author TEXT,
                                           Function TEXT,
                                           Company TEXT,
                                           Type TEXT,
                                           Version TEXT,
                                           Source TEXT,
                                           DateAdded TEXT,
                                           LastModifiedDate TEXT,
                                           UseStatus INTEGER
                                   )
    ''')

    scanners_reader = csv.reader(open('Scanners.csv', 'rb'))
    int_value2 = 1
    for row in scanners_reader:
        insert_value_scanners = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), unicode(row[2], 'utf8'),
                                 unicode(row[3], 'utf8'), unicode(row[4], 'utf8'), unicode(row[5], 'utf8'),
                                 unicode(row[6], 'utf8'), unicode(row[7], 'utf8'), datetime.now(), datetime.now(),
                                 int_value2]

        cursor.execute('INSERT INTO Scanners (Name, Description, Author, Function, Company, Type, '
                       'Version, Source, DateAdded, LastModifiedDate, UseStatus) VALUES(?, ?, ?, ?, ? ,'
                       '? ,? ,? ,?, ?, ?);',
                       insert_value_scanners)
        conn.commit()

    cursor.execute(''' 
      CREATE TABLE IF NOT EXISTS NmapReport(ID INTEGER  PRIMARY KEY AUTOINCREMENT,                          
                                             DeviceID INTEGER, 
                                             Services TEXT,                                        
                                             Type TEXT,
                                             Protocol TEXT,     
                                             NumberofServices TEXT,
                                             StartTime TEXT, 
                                             EndTime TEXT,
                                             State TEXT,                                        
                                             Reason TEXT,
                                             ReasonTtl TEXT,   
                                             HostName TEXT,
                                             HostType TEXT, 
                                             Seconds TEXT,
                                             LastBoot TEXT,                                        
                                             DistanceValue INTEGER,
                                             TCPIndex TEXT,
                                             TCPDifficulty TEXT, 
                                             TCPValues TEXT,
                                             IPIDClass TEXT,        
                                             IPIDValues TEXT,
                                             TCPTSClass TEXT, 
                                             TCPTSValues TEXT,
                                             TimesSrtt TEXT,        
                                             TimesRttvar TEXT, 
                                             TimesTo TEXT, 
                                             FinishedTime TEXT,
                                             FinishedTimeStr TEXT,        
                                             FinishedElapsed TEXT,
                                             FinishedSummary TEXT, 
                                             FinishedExit TEXT,
                                             HostsUp TEXT,        
                                             HostsDown TEXT,     
                                             HostsTotal TEXT,
                                             DateAdded TEXT,  
                                             LastModifiedDate TEXT,                                  
                                             UseStatus INTEGER
                                     )
      ''')


    cursor.execute(''' 
      CREATE TABLE IF NOT EXISTS  MiraiReport(ID INTEGER  PRIMARY KEY AUTOINCREMENT,  
                                             VulnerabilityID INTEGER,
                                             DeviceID INTEGER,
                                             IPAddress TEXT,
                                             Description TEXT,
                                             ScanTime TEXT,
                                             Response TEXT, 
                                             VulnerabilityStatus TEXT,                           
                                             ScanDate TEXT,
                                             LastModifiedDate TEXT,                                       
                                             UseStatus INTEGER
                                     )
      ''')
    conn.commit()

    cursor.execute(''' 
      CREATE TABLE IF NOT EXISTS  SshScannerReport(ID INTEGER  PRIMARY KEY AUTOINCREMENT,  
                                             VulnerabilityID INTEGER,
                                             DeviceID INTEGER,                                                              
                                             IPAddress TEXT,
                                             Description TEXT,                                                             
                                             ScanTime TEXT,
                                             UpTime Text,
                                             PortStatus Text,
                                             Response TEXT, 
                                             DefaultPassword TEXT,
                                             Combinations INTEGER,
                                             VulnerabilityStatus TEXT,                           
                                             ScanDate TEXT,
                                             LastModifiedDate TEXT,                                       
                                             UseStatus INTEGER
                                     )
      ''')
    conn.commit()

    cursor.execute(''' 
      CREATE TABLE IF NOT EXISTS  EncryptionAlgorithms(ID INTEGER  PRIMARY KEY AUTOINCREMENT,  
                                             Name INTEGER,
                                             EncryptionType TEXT,
                                             Description TEXT,   
                                             Vulnerable INTEGER,                                                              
                                             RiskLevel TEXT,   
                                             VulnerableTo Text,                            
                                             DateAdded TEXT,
                                             LastModifiedDate TEXT,                                       
                                             UseStatus INTEGER
                                     )
      ''')

    encryp_algo_reader = csv.reader(open('EncryptionAlgorithms.csv', 'rb'))
    for row in encryp_algo_reader:
        insert_encryp_algo = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), unicode(row[2], 'utf8'),
                              unicode(row[3], 'utf8'), unicode(row[4], 'utf8'), unicode(row[5], 'utf8'), datetime.now(),
                              datetime.now(),
                              int_value]

        cursor.execute('INSERT INTO EncryptionAlgorithms (Name, EncryptionType, Description, Vulnerable, RiskLevel,'
                       ' VulnerableTo, DateAdded, LastModifiedDate, UseStatus) VALUES(?, ?, ?, ?, ? , ? ,? ,? ,?);',
                       insert_encryp_algo)
        conn.commit()

    cursor.execute(''' 
      CREATE TABLE IF NOT EXISTS  OperatingSystems(ID INTEGER  PRIMARY KEY AUTOINCREMENT,  
                                             Name TEXT,
                                             Description TEXT,   
                                             Vulnerable INTEGER,                                                              
                                             RiskLevel TEXT,   
                                             Version Text,  
                                             SafeVersion Text,
                                             DateAdded TEXT,
                                             LastModifiedDate TEXT,                                       
                                             UseStatus INTEGER
                                     )
      ''')

    os_reader = csv.reader(open('OperatingSystems.csv', 'rb'))
    for row in os_reader:
        insert_os = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), unicode(row[2], 'utf8'), unicode(row[3], 'utf8'),
                     unicode(row[4], 'utf8'), unicode(row[5], 'utf8'), datetime.now(), datetime.now(), int_value]

        cursor.execute('INSERT INTO OperatingSystems (Name, Description, Vulnerable, RiskLevel, Version, SafeVersion,'
                       ' DateAdded, LastModifiedDate, UseStatus) VALUES(?, ?, ?, ?, ? , ? ,? ,? ,?);',
                       insert_os)
        conn.commit()

    cursor.execute(''' 
          CREATE TABLE IF NOT EXISTS  DeviceNmapVulnScripts(ID INTEGER  PRIMARY KEY AUTOINCREMENT,  
                                                 DeviceID INTEGER,
                                                 ScriptID TEXT,   
                                                 Output TEXT,                                                                
                                                 State TEXT,   
                                                 Title INTEGER,
                                                 Key TEXT,   
                                                 Description TEXT,                                                              
                                                 Disclosure TEXT,   
                                                 ExploitsResults Text,  
                                                 Refs Text,
                                                 DateAdded TEXT,
                                                 LastModifiedDate TEXT,                                       
                                                 UseStatus INTEGER
                                         )
          ''')
    conn.commit()
    conn.close()


def is_fix_available(vulnerability_id):
    print ('Fix is available for %s', vulnerability_id)


def get_suggestions(vulnerability_id):
    print('Suggestions for fixing vulnerability: %s', vulnerability_id)


def insert_scan_results(vulnerability_id, scanner_id, device_id, description, new_password, resolved, fix_available,
                        scan_type, version):
    conn = sqlite3.connect('SeeSec.sqlite')
    print('Database connection successful')

    cursor = conn.cursor()
    insert_value = [vulnerability_id, scanner_id, device_id, description, new_password, resolved, fix_available,
                    scan_type, version, datetime.now(), datetime.now()]

    cursor.execute('INSERT INTO ScanResults (VulnerabilityID, ScannerID, DeviceID, Description, NewPassword, Resolved,'
                   'FixAvailable, Type, Version, ScanDate, LastModifiedDate) '
                   'VALUES(?, ?, ?, ?, ? ,? ,? ,? ,?, ?, ?);',
                   insert_value)
    conn.commit()


def upload_new_scanners():
    conn = sqlite3.connect('SeeSec.sqlite')
    print('Database connection successful')

    cursor = conn.cursor()
    scanners_reader = csv.reader(open('Scanners.csv', 'rb'))
    int_value2 = 1
    for row in scanners_reader:
        insert_value_scanners = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), unicode(row[2], 'utf8'),
                                 unicode(row[3], 'utf8'), unicode(row[4], 'utf8'), unicode(row[5], 'utf8'),
                                 unicode(row[6], 'utf8'), unicode(row[7], 'utf8'), datetime.now(), datetime.now(),
                                 int_value2]

        cursor.execute('INSERT INTO Scanners (Name, Description, Author, Function, Company, Type, '
                       'Version, Source, DateAdded, LastModifiedDate, UseStatus) VALUES(?, ?, ?, ?, ? ,'
                       '? ,? ,? ,?, ?, ?);',
                       insert_value_scanners)
        conn.commit()
    print('New scanner added successfully')


def upload_new_operating_systems():
    conn = sqlite3.connect('SeeSec.sqlite')
    print('Database connection successful')
    cursor = conn.cursor()
    int_value = 1
    os_reader = csv.reader(open('OperatingSystems.csv', 'rb'))
    for row in os_reader:
        insert_os = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), "N/A", "N/A", "N/A","N/A",  datetime.now(),
                     datetime.now(), int_value]
        # insert_os = [unicode(row[0], 'utf8'), unicode(row[1], 'utf8'), unicode(row[2], 'utf8'), unicode(row[3], 'utf8'),
        #              unicode(row[4], 'utf8'), unicode(row[5], 'utf8'), datetime.now(), datetime.now(), int_value]

        cursor.execute('INSERT INTO OperatingSystems (Name, Description, Vulnerable, RiskLevel, Version, SafeVersion,'
                       ' DateAdded, LastModifiedDate, UseStatus) VALUES(?, ?, ?, ?, ? , ? ,? ,? ,?);',
                       insert_os)
        conn.commit()

if __name__ == "__main__":
    # insert_scan_results(1, 2, 3, 'description', 'xyz', 1, 1, 'Badlock', 'version')
    # create_database()


    # upload_new_operating_systems()
    print('Database creation completed successfully')

