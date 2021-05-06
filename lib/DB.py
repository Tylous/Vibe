#!/usr/bin/env python
import warnings
warnings.simplefilter( "ignore", UserWarning )
import pandas as dp
import sqlite3
from sqlite3 import Error
import csv
from pandas.io import sql


dp.set_option( 'display.max_columns', None )
dp.set_option( 'display.width', 999999909 )
global conn


def name(db_domain):
    global db_name
    db_name = '.db/' + db_domain + '.db'
    return db_name

def connect(name):
    global conn
    conn = sqlite3.connect(db_name, check_same_thread=False)
    return conn




def groupIDquery():
    global gidname
    connect_db()
    connection.execute('''select "Name" from GroupTB''')
    user = dp.read_sql( 'select "Primary Group Name" from UserTB', connection )
    user = user.drop_duplicates()
    user = user.to_string(index=False, header=False).split('\n')
    sql = load ()
    sql.begin ()
    for id in user:
        gidname = dp.read_sql('select Name from GroupTB where SID ="'+id+'"', connection ).drop_duplicates()
        gidname = gidname.to_string( index=False, header=False )
        connection.execute('''UPDATE UserTB Set "Primary Group Name" == " '''+gidname+"\n"+'''" where "Primary Group Name" == "'''+id+'''"''')
    sql.Close ()


def create_connection():
    try:
        conn.execute('''CREATE TABLE UserTB
            (Username, Description, "Home Directory", SID, "Profile Path", "Password Last Set", "Last Logged On", "Account Settings", "Primary Group Name", "Member Of")''')
        conn.execute('''CREATE TABLE GroupTB
            (Name, SID, Description, "Member Of", Members)''')
        conn.execute('''CREATE TABLE ComputerTB
            (Name, Description, "Operating System", "Operating System Version Number", "Member Of")''')
        conn.execute('''CREATE TABLE PasswordPolicyTB
        ("Minimum Password Length", "Lockout Threshold", "Lockout Duration", "Passwords Remembered", "Password Properties")''')
        conn.execute('''CREATE TABLE FGPasswordPolicyTB
        ("Minimum Password Length", "Lockout Threshold", "Lockout Duration", "Passwords Remembered", "Password Properties", 'members')''')
        conn.execute('''CREATE TABLE SPNTB
        ("SPN", "Username", "Description", "Password Last Set", "Member Of")''')
    except Error as e:
        conn.close()
    finally:
        conn.close()

def connect_db():
    global connection
    connection = sqlite3.connect (db_name, check_same_thread=False )
    connection.text_factory = str

def sharetable(user, share_db):
    connect_db ()
    if "." in user:
        user = user.replace(".","")
    cl = dp.DataFrame(share_db)
    cl = cl[['Computer', 'Share', 'Permission']]
    cl.reset_index ( inplace=True )
    del cl['index']
    cl.to_sql ( user, connection, index=False, if_exists="append" )
    cleanup = dp.read_sql("select * from '{}'".format(user), connection).drop_duplicates()
    cleanup.to_sql(user, connection, index=False, if_exists="replace")

def fileshare():
    connect_db ()
    try:
        FS_list = dp.read_sql ( 'select "Home Directory", "Profile Path" from UserTB', connection ).drop_duplicates()
        if not FS_list.values.any:
            pass
        else:
            FS_list = FS_list.drop_duplicates()
            FS_list = FS_list.to_string(header=False, index=False)
            FS_list = FS_list.upper()
            FS_list = FS_list.replace("\n", "").replace(" ", "")
            FS_list = FS_list.split("\\")
            uname_list = dp.read_sql ( 'select Name from ComputerTB', connection )
            uname_list = uname_list.to_string ( header=False, index=False )
            uname_list = uname_list.split ()
            l3 = [x for x in FS_list if x in uname_list]
            l3 = [_f for _f in l3 if _f]
            final = dp.DataFrame ( l3 )
            final = final.drop_duplicates ()
            final.to_sql("FileServer", connection, index=False, if_exists="replace")
    except ValueError:
        pass


class load():
    def begin(self):
        connection.execute("BEGIN TRANSACTION")

    def insert_Users(self, username, Desc, sidnumber, HD, PF, PLS, LLO, UACL, GroupID, memberof):
        connection.execute("insert into UserTB (Username, Description, SID, 'Home Directory', 'Profile Path', 'Password Last Set', 'Last Logged On', 'Account Settings', 'Primary Group Name', 'Member Of') values (?,?,?,?,?,?,?,?,?,?)", (username, Desc, sidnumber, HD, PF, PLS, LLO, UACL, GroupID, memberof))

    def Insert_Groups(self, username, sidnumber, Desc, memberof, member):
        connection.execute("insert into GroupTB (Name, SID, Description, 'Member Of', Members) values (?,?,?,?,?)", (username, sidnumber, Desc, memberof, member))

    def Insert_Computers(self, system, Desc, operatingsystem, operatingsystemversion, memberof):
        connection.execute("insert into ComputerTB (Name, Description, 'Operating System', 'Operating System Version Number', 'Member Of') values (?,?,?,?,?)", (system, Desc, operatingsystem, operatingsystemversion, memberof))

    def Insert_Passwd(self, minpwd, lcknum, lckdur, pwdhis, pwdpar):
        connection.execute ("insert into PasswordPolicyTB('Minimum Password Length', 'Lockout Threshold', 'Lockout Duration', 'Passwords Remembered', 'Password Properties') values (?,?,?,?,?)", (minpwd, lcknum, lckdur, pwdhis, pwdpar))

    def Insert_FGPasswd(self, FGminpwd, FGlcknum, FGpwdhis, FGlckdur, FGpwdp, FGmember):
        connection.execute ("insert into FGPasswordPolicyTB('Minimum Password Length', 'Lockout Threshold', 'Lockout Duration', 'Passwords Remembered', 'Password Properties', 'members') values (?,?,?,?,?,?)", (FGminpwd, FGlcknum, FGpwdhis, FGlckdur, FGpwdp, FGmember))

    def Insert_SPN(self, SPN, username, Desc, PLS, memberof):
        connection.execute("insert into SPNTB ('SPN', 'Username', 'Description', 'Password Last Set', 'Member Of') values (?,?,?,?,?)", (SPN, username, Desc, PLS, memberof))

    def Close(self):
        connection.commit()
        connection.close()


