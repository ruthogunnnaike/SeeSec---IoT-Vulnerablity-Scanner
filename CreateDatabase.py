import psycopg


# This method gets the data source name (DSN) - a data structure that contains the information about a specific database that an open database
# connectivity (ODBC) driver needs in order to connect to it.
#
#  pwd.getpwuid(uid): Return the passwords database entry for the given numeric user ID.
# pwd.getpwnam(name): Return the password database entry for the given user name.
# pwd.getpwall():Return a list of all available password database entries, in arbitrary order.
#
def getDsn(db=None, user=None, passwd=None, host=None ):
    if user==None:
        import  os,pwd
        user = pwd.getpwuid(os.getuid())[0]
    if db==None:
        db = user
    dsn = 'dbname =%s user=%s' %(db, user)

    if passwd != None:
        dsn += ' password=' + passwd
    if host != None:
        dsn += ' host=' + host
    return dsn


dsn = getDsn()
print "Connecting to %s" % dsn

#Database connection handle
dbh = psycopg.connect(dsn)
print "Connection successful."

#Database cursor
cur = dbh.cursor()

cur.execute("""CREATE TABLE DeviceBios(ID INTEGER IDENTITY(1,1) PRIMARY KEY NOT NULL,
                                       Name VARCHAR(100),
                                       Description VARCHAR(250),
                                       MacAddress VARCHAR(20),
                                       IPAddress VARCHAR(20),
                                       Manufacturer VARCHAR(50),
                                       Brand VARCHAR(50),
                                       Model VARCHAR(20),
                                       Type VARCHAR(20),
                                       Version VARCHAR(20),
                                       OperatingSystem VARCHAR(20),
                                       Memory INTEGER,
                                       Capacity INTEGER ,
                                       ManufactureDate DATETIME,
                                       LastSoftwareUpdated DATETIME,
                                       DateAdded DATETIME,
                                       LastModifiedData DATETIME,
                                       Status INTEGER
                                        """)

#Other tables include 1_ScanResult, 2_DefaultCredentials, 3_WeakPassword, 4_Suggestions, 5_KnownVulnerabilities,
#6_KnownVulnerableCryptographyAlgorithms, 7_KnownVulnerableSoftwareVersions

cur.execute("INSERT INTO myTable VALUES (5, 'Five')")

dbh.commit()
dbh.close()


# def createTable
# def insertData
# def deleteData
# def createDatabase
# def updateData


