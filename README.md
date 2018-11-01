# Vibe
Vibe is a tool designed to preform post-ex lateral movement techniques while remaining undetected by network detection tools including Threat Hunting appliances. 
Vibe works by pulling down all information about a domain, allowing users to perform the same domain net commands offline. Vibe also enumerates additional information that is not typically shown in these queries. 
Vibe also provides the ability to scan systems to see what shares are available and what privileges the account used, has access to. Vibe also provides the ability to enumerate user’s currently logged into systems, as well as, who has been logged in, while remaining undetected. 




## Installation


Vibe was developed with Python version 2.7

Tested and supported on Kali Linux and Ubuntu. 

Vibe uses the following external dependencies:

* python-ldap
* ldap3
* pandas
* tabulate
* impacket
* netaddr

To install run following commands:
```
sudo apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev
pip install  -r requirements.txt

```

## Usage



```
./vibe.py -h
usage: vibe.py [-h] -U username -P password -D domain -I IP [-o]

optional arguments:
  -h, --help            show this help message and exit
  -U username, --Username username
                        Username
  -P password, --Password password
                        Password
  -D domain, --Domain domain
                        Fully Qualified Domain Name
  -I IP, --IP IP        IP address of Domain Controller
  -o, --Offline         Offline Mode
  -r, --Remove          Remove Database

```





```
root@kali:~/# ./vibe.py -U admin -P Password! -D STARLABS.local -I 172.16.144.185



 ___      ___  ___      ________      _______ 
|\  \    /  /||\  \    |\   __  \    |\  ____\ 
\ \  \  /  / /\ \  \   \ \  \|\ /_   \ \ \_____    
 \ \  \/  / /  \ \  \   \ \   __  \   \ \  ____\        
  \ \    / /    \ \  \   \ \  \|\  \   \ \  \____ 
   \ \__/ /      \ \__\   \ \_______\   \ \______\ 
    \|__|/        \|__|    \|_______|    \|______|  
                                           (@Tyl0us)    


[+] Creating DB
[+] Credentials Valid, Generating Database
[+] Sucessful Database Created
0.434292078018
>>help
Commands
========
add_cred             Adds credentials to the credential table. Use -p for passwords and -h for password hashes
clear                Clears the screen
help                 Displays this help menu
list                 Lists either all Users, Computers, or Groups. Use the -f option to pipe the contents to a file
session              Scans target(s) to see who has/is currently logged in. Can take a list or range of hosts, using -t/--target and specify a user using -u/--user and --jitter/-j to add a delay. Requires: read/write privileges on either Admin$ or C$ share
net                  Perform a query to view all information pertaining to a specific user, group, or computer (Similar to the Windows net user, net group commands). example: 'net group Domain Admins'
query                Executes a query on the contents of tables
search               Searches for a key word(s) through every field of every table for any matches, displaying row
share_hunter         Scans target(s) enumerating the shares on the target(s) and the level of access the specified user, using  -u/--user. Can take a list or range of hosts, using -t/--target and --jitter/-j to add a delay
show                 Shows the contents of Computers, Credentials, Groups, Password policy, Store, Credentials, Files Servers and Access tables
store                Displays the contents of a specific table. Example: 'show [table name] (access, creds, computers, file servers, pwdpolicy, users)
exit                 Exit Vibe
>>

```

##Domain Information Quering 

The ```show``` command displays the contents of a table, specific information across all tables or the available modules, using the following syntax:

```

>>show users
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| Username       | Home Directory         |   SID | Password Last Set   | Last Logged On      | Account Settings   | Member Of                              |
+================+========================+=======+=====================+=====================+====================+========================================+
| Administrator  |                        |   500 | 2017-11-28 16:40:56 | 2017-11-28 16:35:48 | DONT_EXPIRE_PASSWD | Domain Users                           |
|                |                        |       |                     |                     | NORMAL_ACCOUNT     | WseInvisibleToDashboard                |
|                |                        |       |                     |                     | ACCOUNT_DISABLED   | Group Policy Creator Owners            |
|                |                        |       |                     |                     |                    | Domain Admins                          |
|                |                        |       |                     |                     |                    | Enterprise Admins                      |
|                |                        |       |                     |                     |                    | Schema Admins                          |
|                |                        |       |                     |                     |                    | Administrators                         |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| Guest          |                        |   501 | 1600-12-31 19:03:58 | 1600-12-31 19:03:58 | DONT_EXPIRE_PASSWD | Domain Guests                          |
|                |                        |       |                     |                     | PASSWD_NOTREQD     | Guests                                 |
|                |                        |       |                     |                     | NORMAL_ACCOUNT     |                                        |
|                |                        |       |                     |                     | ACCOUNT_DISABLED   |                                        |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| DefaultAccount |                        |   503 | 1600-12-31 19:03:58 | 1600-12-31 19:03:58 | DONT_EXPIRE_PASSWD | Domain Users                           |
|                |                        |       |                     |                     | PASSWD_NOTREQD     | System Managed Accounts Group          |
|                |                        |       |                     |                     | NORMAL_ACCOUNT     |                                        |
|                |                        |       |                     |                     | ACCOUNT_DISABLED   |                                        |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| Admin          |                        |  1000 | 2017-11-28 16:40:24 | 2018-08-24 13:01:20 | DONT_EXPIRE_PASSWD | Domain Users                           |
|                |                        |       |                     |                     | NORMAL_ACCOUNT     | Domain Admins                          |
|                |                        |       |                     |                     |                    | Administrators                         |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| krbtgt         |                        |   502 | 2017-11-28 16:44:43 | 1600-12-31 19:03:58 | NORMAL_ACCOUNT     | Domain Users                           |
|                |                        |       |                     |                     | ACCOUNT_DISABLED   | Denied RODC Password Replication Group |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| ballen         | \\\\SLServer01\\ballen |  1123 | 2017-11-28 17:40:08 | 2018-08-09 17:56:50 | DONT_EXPIRE_PASSWD | Domain Users                           |
|                |                        |       |                     |                     | NORMAL_ACCOUNT     | SL_R&D                                 |
|                |                        |       |                     |                     |                    | SL_Scientist                           |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| cramon         | \\\\SLFS02\\cramon     |  1125 | 2018-05-29 13:07:32 | 2018-08-23 21:47:26 | NORMAL_ACCOUNT     | Domain Users                           |
|                |                        |       |                     |                     |                    | SL_R&D                                 |
|                |                        |       |                     |                     |                    | SL_HelpDesk                            |
|                |                        |       |                     |                     |                    | Domain Admins                          |
|                |                        |       |                     |                     |                    | Enterprise Admins                      |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| hwells         |                        |  1126 | 2017-11-28 17:51:51 | 2018-08-23 21:46:21 | DONT_EXPIRE_PASSWD | Domain Users                           |
|                |                        |       |                     |                     | NORMAL_ACCOUNT     | SLServ01_Admin                         |
|                |                        |       |                     |                     |                    | SL_R&D                                 |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| ssmith         |                        |  2104 | 2018-08-09 20:54:14 | 2018-08-09 20:47:47 | NORMAL_ACCOUNT     | Domain Users                           |
|                |                        |       |                     |                     |                    | SL_HR                                  |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| csnow          | \\\\SLFS01\\csnow      |  2105 | 2018-08-09 19:35:05 | 2018-08-23 20:53:35 | NORMAL_ACCOUNT     | Domain Users                           |
|                |                        |       |                     |                     |                    | SL_R&D                                 |
|                |                        |       |                     |                     |                    | SL_Scientist                           |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| wwest          |                        |  2608 | 2018-08-09 20:58:39 | 1600-12-31 19:03:58 | NORMAL_ACCOUNT     | Domain Users                           |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
| iwallen        |                        |  2610 | 2018-05-16 22:49:37 | 1600-12-31 19:03:58 | NORMAL_ACCOUNT     | Domain Users                           |
+----------------+------------------------+-------+---------------------+---------------------+--------------------+----------------------------------------+
```

There are several different options that can be used with the ```show``` command includiong:

* access
* computers
* creds
* fgpolicy (only accessible if an account that has admin access to the domain contoller is used, on inital start up)
* file servers
* groups
* pwdpolicy
* store 
* users

Below are some examples of the information stored:

```
>>show access admin
+----------------+------------------------+--------------+
| Computer       | Share                  | Permission   |
+================+========================+==============+
| 172.16.144.185 | ADMIN$                 | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | C$                     | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | CertEnroll             | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | Company                | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | File History Backups   | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | Folder Redirection     | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | NETLOGON               | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | Shared Folders         | Read         |
+----------------+------------------------+--------------+
| 172.16.144.185 | SYSVOL                 | Read         |
+----------------+------------------------+--------------+
| 172.16.144.185 | test                   | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | UpdateServicesPackages | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | Users                  | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | WsusContent            | Read\Write   |
+----------------+------------------------+--------------+
| 172.16.144.185 | WSUSTemp               | Read\Write   |
+----------------+------------------------+--------------+
>>show file servers
File Servers Discovered
----------
SLSERVER01
SLFS02
SLFS01
----------
>>show pwdpolicy
Password Policy
---------------
Minimum Password Length: 7
Lockout Threshold: 5
Lockout Duration: 30.0 minutes
Passwords Remembered: 24
Password Properties: 1 DOMAIN_PASSWORD_COMPLEX
>>
```

The ```query``` command can be used to display a unique set of data based on the parememters specificed. The ```query``` command uses sql syntax.
The ```net``` command can also be used simillar to the windows command line arguements ```net user```, ```net group``` and ```net computer```.


```
>>net group Domain Admins
Group name: Domain Admins
Description: Designated administrators of the domain
Group Membership:
WseRemoteAccessUsers          WseAlertAdministrators        WseAllowHomePageLinks
WseAllowDashboardAccess       WseAllowAddInAccess           WseAllowMediaAccess
WseAllowComputerAccess        WseAllowShareAccess           WseRemoteWebAccessUsers
Denied RODC Password Replication GroupAdministrators                 
----------------------------------------------------------------------------------
Members:
cramon                        Admin                         Administrator
>>
```

## Search 

The ```search <key word(s)>``` command looks for a key word(s) through every field of every table for any matches, displaying all the information about that object it was discovered in.


```
>>search SLServer
Groups
---------
+----------------+-------+-------------------------------+-------------+------------+
| Name           |   SID | Description                   | Member Of   | Members    |
+================+=======+===============================+=============+============+
| SLServ01_Admin |  2609 | Admin Group for SLServer01... |             | SLSERVER01 |
|                |       |                               |             | hwells     |
+----------------+-------+-------------------------------+-------------+------------+
Users
---------
+------------+---------------+------------------------+-------+----------------------+---------------------+---------------------+--------------------+--------------+
| Username   | Description   | Home Directory         |   SID | Profile Path         | Password Last Set   | Last Logged On      | Account Settings   | Member Of    |
+============+===============+========================+=======+======================+=====================+=====================+====================+==============+
| ballen     | CEO...        | \\\\SLServer01\\ballen |  1123 | \\SLServer01\\ballen | 2017-11-28 17:40:08 | 2018-08-09 17:56:50 | DONT_EXPIRE_PASSWD | Domain Users |
|            |               |                        |       |                      |                     |                     | NORMAL_ACCOUNT     | SL_R&D       |
|            |               |                        |       |                      |                     |                     |                    | SL_Scientist |
+------------+---------------+------------------------+-------+----------------------+---------------------+---------------------+--------------------+--------------+
Computers
---------
+------------+---------------+--------------------------------+-----------------------------------+----------------+
| Name       | Description   | Operating System               | Operating System Version Number   | Member Of      |
+============+===============+================================+===================================+================+
| SLSERVER01 |               | Windows Server 2016 Essentials | 10.0 (14393)                      | SLServ01_Admin |
+------------+---------------+--------------------------------+-----------------------------------+----------------+
>>
```

## Share_Hunter 

The ```share_hunter``` command scans the remote host(s) or ranges (using the ```-t``` or ```--targets``` option) discovering all available shares, as well as the level of access the specificed user has (using the ```-u``` or ```--user``` option). The ```-j``` or ```--jitter``` option can be used to add delay in between requests. This information can get stored and can be viewed using the ```show access <username>```.


```
>>share_hunter -t 172.16.144.185-172.16.144.190 --user admin -j 2
172.16.144.186
-----------------
   [+]  ADMIN$: Read\Write
   [+]  C$: Read\Write
172.16.144.185
-----------------
   [+]  ADMIN$: Read\Write
   [+]  C$: Read\Write
   [+]  CertEnroll: Read\Write
   [+]  Company: Read\Write
   [+]  File History Backups: Read\Write
   [+]  Folder Redirection: Read\Write
   [+]  NETLOGON: Read\Write
   [*]  Shared Folders: Read
   [*]  SYSVOL: Read
   [+]  test: Read\Write
   [+]  UpdateServicesPackages: Read\Write
   [+]  Users: Read\Write
   [+]  WsusContent: Read\Write
   [+]  WSUSTemp: Read\Write
172.16.144.189
-----------------
   [+]  ADMIN$: Read\Write
   [+]  C$: Read\Write
172.16.144.187
-----------------
   [*] Host either not accessible or port 445 closed
172.16.144.188
-----------------
   [+]  ADMIN$: Read\Write
   [+]  C$: Read\Write
172.16.144.190
-----------------
   [+]  ADMIN$: Read\Write
   [+]  C$: Read\Write

```

## Session

The ```session``` command scans the remote host(s) or ranges (using the ```-t``` or ```--targets``` option) discovering all active user's, as well who has had a profile on the remote system. This command requires the specified user (using the ```-u``` or ```--user``` option) has read/write privileges on either Admin$ or C$ share. The ```-j``` or ```--jitter``` option can be used to add delay in between requests. This information can get stored and can be viewed using the ```show access <username>```.


```
>>session -u admin --targets SLServer01 --jitter 2
SLServer01
-----------------
  Currently Logged On
  -------------------
     [+] STARLABS\hwells
     [+] STARLABS\admin

  Users Who Have Logged On
  -------------------------
     [*] admin lastlogon: Tue Feb  6 21:11:46 2018
     [*] Administrator lastlogon: Tue Feb  6 20:40:54 2018
     [*] cramon lastlogon: Thu Mar  1 21:00:58 2018
     [*] hwells lastlogon: Wed Mar 28 23:44:30 2018
```
## Lit

The ```list``` commmand displays either all Users, Computers, or Groups. Use the `-f` option to pipe the output of the command to a file.

```
>>list users -f /tmp/users
--------------
Administrator
Guest
DefaultAccount
Admin
krbtgt
ballen
cramon
hwells
csnow
ssmith
wwest
iwestallen
--------------

```
