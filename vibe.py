#!/usr/bin/env python
import subprocess
import argparse
import cmd
import os
from pandas import *
import time
from tabulate import tabulate
from lib.AD import *
from lib.smb import Share_Hunting, Sessions
from lib.net import *


class colors:
	GRN = '\033[92m'
	RD = '\033[91m'
	NRM = '\033[0m'
	BLU = '\033[34m'


show = ['users', 'groups', 'computers', 'pwdpolicy', 'store', 'creds', 'fgpolicy', 'file servers', 'access']
net = ['user', 'group', 'computer']

parser = argparse.ArgumentParser(prog='main')
parser.add_argument('-U', '--username', metavar='username', dest='username', action='store', help='Username\n', required=True)
parser.add_argument('-P', '--password', metavar='password', dest='password', action='store', help='Password\n', required=True)
parser.add_argument('-D', '--domain', metavar='domain', dest='domain', action='store', help='Fully Qualified Domain Name\n', required=True)
parser.add_argument('-I', '--ip', metavar='IP', dest='IP', action='store', help='IP address of Domain Controller\n', required=True)
parser.add_argument('-o', '--offline', dest='offline', action='store_true', help='Offline Mode\n', required=False)
parser.add_argument('-r', '--remove', dest='remove', action='store_true', help='Remove Database\n', required=False)
parser.add_argument('-p', '--port', dest='port', action='store', help='Specify a specific port to connect on (default is 636)\n', required=False)
parser.add_argument('-u', '--unencrypted', dest='unencrypted', action='store_true', help='Specify a specific for unencrypted mode (if LDAPS is not available)\n', required=False)


args = parser.parse_args()


class menu(cmd.Cmd):
	global conn
	db_domain = args.domain
	conn = connect(name(db_domain))
	try:
		table = []
		prompt = ('>>')
		global result

		def result(tb):
			global results
			results = tb

		def do_show(self, option, intro=None):
			try:
				if option == 'users':
					dp.options.display.max_colwidth = 40000
					tb = dp.read_sql('select *from UserTB', conn)
					tb['Member Of'] = tb[['Primary Group Name', 'Member Of']].sum(axis=1)
					del tb['Primary Group Name']
					del tb['Profile Path']
					del tb['Description']
					print (tabulate(tb, showindex=False, headers=tb.columns, tablefmt="grid"))
					result(tb)
					return
				if option == 'groups':
					tb = dp.read_sql('select * from GroupTB', conn)
					tb['Description'] = tb['Description'].str[:35] + '...'
					print (tabulate(tb, showindex=False, headers=tb.columns, tablefmt="grid"))
					result(tb)
					return cmd.Cmd.cmdloop(self, intro)
				if option == 'computers':
					tb = dp.read_sql('select * from ComputerTB', conn)
					print (tabulate(tb, showindex=False, headers=tb.columns, tablefmt="grid"))
					result(tb)
					return cmd.Cmd.cmdloop(self, intro)
				if option == 'store':
					try:
						cmd.Cmd.onecmd(self, store)
						return cmd.Cmd.cmdloop(self, intro)
					except NameError:
						print "Nothing is stored"
						return cmd.Cmd.cmdloop(self, intro)
				if option == 'fgpolicy':
					tb = dp.read_sql('select * from FGPasswordPolicyTB', conn)
					print (tabulate(tb, showindex=False, headers=tb.columns, tablefmt="grid"))
					result(tb)
					return cmd.Cmd.cmdloop(self, intro)
				if option == 'pwdpolicy':
					tb = dp.read_sql('select * from PasswordPolicyTB', conn)
					print "Password Policy"
					print "---------------"
					print "Minimum Password Length: " + tb['Minimum Password Length'].to_string(index=False, header=False)
					print "Lockout Threshold: " + tb['Lockout Threshold'].to_string(index=False, header=False)
					print "Lockout Duration: " + tb['Lockout Duration'].to_string(index=False, header=False) + ' minutes'
					print "Passwords Remembered: " + tb['Passwords Remembered'].to_string(index=False, header=False)
					print "Password Properties: " + tb['Password Properties'].to_string(index=False, header=False)
					return cmd.Cmd.cmdloop(self, intro)
				if option.startswith('access'):
					try:
						username = option.split("access ")
						user = username[1]
						if "." in user:
							user.replace(".", "")
						tb = dp.read_sql('select * from ' + user + '', conn)
						print (tabulate(tb, showindex=False, headers=tb.columns, tablefmt="grid"))
						return cmd.Cmd.cmdloop(self, intro)
					except IndexError:
						print "Nothing recorded for this user"
					return cmd.Cmd.cmdloop(self, intro)
				if option == 'file servers':
					FS_list1 = dp.read_sql('select "Home Directory" from UserTB', conn)
					FS_list2 = dp.read_sql('select "Profile Path" from UserTB', conn)
					FS_list = FS_list2
					FS_list = FS_list.drop_duplicates()
					print FS_list
					FS_list = tabulate(FS_list, showindex=False)
					print "File Servers Discovered"
					print FS_list
					return cmd.Cmd.cmdloop(self, intro)
				else:
					print colors.BLU + "[-] " + colors.NRM + "Error: " + option + " does not exist or is empty, please try again."
			except pandas.io.sql.DatabaseError:
				print colors.RD + "[-] " + colors.NRM + "Error: Empty database. Object may not exist."
			except KeyboardInterrupt:
				return
			return cmd.Cmd.cmdloop(self, intro)

		def do_export(self, option, intro=None):
			try:
				dp.options.display.max_colwidth = 0
				args = iter(option.split())
				for arg in args:
					if arg == "-f" or arg == "--filetype":
						format = next(args)
					if arg == "-p" or arg == "--path":
						path = next(args)
				if path == '':
					print "Error: Unsupported file type specified. Please try again with either csv or html"
					return
				tablesnames = ['User','Group', 'Computer']
				if format =="csv":
					for tablename in tablesnames:
						tb = dp.read_sql('select *from '+tablename+'TB', conn)
						tb.replace('\n', ',')
						print '[+] File Saving to: ' + path + '/' + db_domain + '_' + tablename + 's.csv'
						export_csv = tb.to_csv(''+ path+'/'+db_domain+'_'+tablename+'s.csv', index=True, header=True)
					return cmd.Cmd.cmdloop(self, intro)
				if format == "html":
					for tablename in tablesnames:
						tb = dp.read_sql('select *from ' + tablename + 'TB', conn)
						tb = tb.replace({'\n':'<br>'}, regex=True)
						print '[+] File Saving to: ' + path + '/' + db_domain + '_' + tablename + 's.html'
						export_html = tb.to_html('' + path + '/' + db_domain + '_' + tablename + 's.html', escape=False)
					return cmd.Cmd.cmdloop(self, intro)
				else:
					print "Error: Unsupported file type specified. Please try again with either csv, html"
			except pandas.io.sql.DatabaseError:
				dp.options.display.max_colwidth = 40000
				print colors.RD + "[-] " + colors.NRM + "Error: Empty database. Object may not exist."
			except UnboundLocalError:
				print "Error: Missing opinion, please make sure you provide the format and export pathway, using the appropriate flags."
			dp.options.display.max_colwidth = 40000
			return cmd.Cmd.cmdloop(self, intro)


		def do_net(self, option, intro=None):
			try:
				option = option.split(' ')
				type = option[0]
				value = " ".join(option[1:])
				dp.options.display.max_colwidth = -1
				if type in ["user"]:
					tb = dp.read_sql('select * from UserTB where Username = \'' + value + '\' COLLATE NOCASE', conn)
					if tb.empty:
						print colors.BLU + "[*] " + colors.NRM + 'User: ' + value + ' does not exist, please try again'
						return
					print 'Username: ' + tb['Username'].to_string(index=False, header=False)
					print 'SID: ' + tb['SID'].to_string(index=False, header=False)
					print 'Description: ' + tb['Description'].to_string(index=False, header=False)
					print 'Home Directory : ' + tb['Home Directory'].to_string(index=False, header=False)
					print 'Profile Path : ' + tb['Profile Path'].to_string(index=False, header=False)
					print 'Password Last Set: ' + tb['Password Last Set'].to_string(index=False, header=False)
					print 'Last Logged On: ' + tb['Last Logged On'].to_string(index=False, header=False)
					print 'Account Settings: ' + tb['Account Settings'].to_string(index=False, header=False).replace('\'', '').replace('\\n', ',')
					print '----------------------------------------------------------------------------------'
					print 'Primary Group Name : ' + tb['Primary Group Name'].to_string(index=False, header=False).replace('\\n', '')
					print 'Group Membership: '
					display_Members_Of = tb['Member Of'].to_string(index=False, header=False).split('\\n')
					display_Members_Of.append(' ')
					display_Members_Of.append(' ')
					for c1, c2, c3 in zip(display_Members_Of[::3], display_Members_Of[1::3], display_Members_Of[2::3]):
						print '{:<30}{:<30}{:<}'.format(c1, c2, c3)
					result(tb)
					return cmd.Cmd.cmdloop(self, intro)
				elif type in ["group"]:
					tb = dp.read_sql('select * from GroupTB where Name = \'' + value + '\' COLLATE NOCASE', conn)
					if tb.empty:
						print colors.BLU + "[*] " + colors.NRM + 'Group: ' + value + ' does not exist, please try again'
						return
					print 'Group name: ' + tb['Name'].to_string(index=False, header=False)
					print 'Description: ' + tb['Description'].to_string(index=False, header=False)
					print 'Group Membership:'
					display_Membership = tb['Member Of'].to_string(index=False, header=False).split('\\n')
					display_Membership.append(' ')
					display_Membership.append(' ')
					for c1, c2, c3 in zip(display_Membership[::3], display_Membership[1::3], display_Membership[2::3]):
						print'{:<30}{:<30}{:<}'.format(c1, c2, c3)
					print '----------------------------------------------------------------------------------'
					print 'Members:'
					display_Members = tb['Members'].to_string(index=False, header=False).split('\\n')
					display_Members.append(' ')
					display_Members.append(' ')
					for c1, c2, c3 in zip(display_Members[::3], display_Members[1::3], display_Members[2::3]):
						print '{:<30}{:<30}{:<}'.format(c1, c2, c3)
					result(tb)
					return cmd.Cmd.cmdloop(self, intro)
				elif type in ["computer"]:
					tb = dp.read_sql('select * from ComputerTB where Name = \'' + value + '\' COLLATE NOCASE', conn)
					if tb.empty:
						print colors.BLU + "[*] " + colors.NRM + 'Computer: ' + value + ' does not exist, please try again'
						return
					print 'Computer Name: ' + tb['Name'].to_string(index=False, header=False)
					print 'Description: ' + tb['Description'].to_string(index=False, header=False)
					print 'Operating System: ' + tb['Operating System'].to_string(index=False, header=False)
					print 'Version Number: ' + tb['Operating System Version Number'].to_string(index=False, header=False)
					print '----------------------------------------------------------------------------------'
					print 'Group Membership: '
					display_Members_Of = tb['Member Of'].to_string(index=False, header=False).split('\\n')
					display_Members_Of.append(' ')
					display_Members_Of.append(' ')
					for c1, c2, c3 in zip(display_Members_Of[::3], display_Members_Of[1::3], display_Members_Of[2::3]):
						print '{:<30}{:<30}{:<}'.format(c1, c2, c3)
					result(tb)
					return cmd.Cmd.cmdloop(self, intro)
				else:
					print colors.RD + "[-] " + colors.NRM + "Error: Invalid net request, please try again."
			except pandas.io.sql.DatabaseError:
				print colors.RD + "[-] " + colors.NRM + "Error: Empty database."
			return cmd.Cmd.cmdloop(self, intro)

		def do_columns(self, option, intro=None):
			try:
				if option == "users":
					print "[-] Displaying the columns in the User Table"
					tb = dp.read_sql('select *from UserTB', conn)
					print tb.columns.values.tolist()
				elif option == "groups":
					print "[-] Displaying the columns in the Group Table"
					tb = dp.read_sql('select *from GroupTB', conn)
					print tb.columns.values.tolist()
				elif option == "computers":
					print "[-] Displaying the columns in the Computer Table"
					tb = dp.read_sql('select *from ComputerTB', conn)
					print tb.columns.values.tolist()
				else:
					print "Not one of the tables."
			except pandas.io.sql.DatabaseError:
				print colors.RD + "[-] " + colors.NRM + "Error: Empty database."
			return cmd.Cmd.cmdloop(self, intro)

		def do_list(self, option, intro=None):
			try:
				if "users" in option:
					tb = dp.read_sql('select Username from UserTB', conn)
					Users = tabulate(tb, showindex=False)
					print Users.strip()
					result(Users)
					if "-f" in option or "--file" in option:
						option = option.split(" ")
						filepath = option[2]
						tb.to_csv(filepath, sep='\t', index=False)
						print colors.GRN + "[+] " + colors.NRM + "Exported List of Users to: "+ filepath
					return cmd.Cmd.cmdloop(self, intro)
				if "groups" in option:
					tb = dp.read_sql('select Name from GroupTB', conn)
					Groups = tabulate(tb, showindex=False)
					print Groups.strip()
					result(Groups)
					if "-f" in option or "--file" in option:
						option = option.split(" ")
						filepath = option[2]
						tb.to_csv(filepath, sep='\t', index=False)
						print colors.GRN + "[+] " + colors.NRM + "Exported List of Groups to: " + filepath
					return cmd.Cmd.cmdloop(self, intro)
				if "computers" in option:
					tb = dp.read_sql('select Name from ComputerTB', conn)
					Computers = tabulate(tb, showindex=False)
					print Computers.strip()
					result(Computers)
					if "-f" in option or "--file" in option:
						option = option.split(" ")
						filepath = option[2]
						tb.to_csv(filepath, sep='\t', index=False)
						print colors.GRN + "[+] " + colors.NRM + "Exported List of Computers to: " + filepath
					return cmd.Cmd.cmdloop(self, intro)
			except pandas.io.sql.DatabaseError:
				print colors.RD + "[-] " + colors.NRM + "Error: Empty Database."

		def do_query(self, option, intro=None):
			try:
				if "export" in option:
					args = iter(option.split())
					for arg in args:
						if arg == "-f" or arg == "--filetype":
							format = next(args)
						if arg == "-p" or arg == "--path":
							path = next(args)
					if path == '':
						print "Error: Unsupported file type specified. Please try again with either csv or html"
						return
				if 'User' in option:
					option = option.replace("User", "UserTB")
				elif 'user' in option:
					option = option.replace("user", "UserTB")
				if 'Users' in option:
					option = option.replace("User", "UserTB")
				elif 'users' in option:
					option = option.replace("user", "UserTB")
				elif 'Group' in option:
					option = option.replace("Group", "GroupTB")
				elif 'group' in option:
					option = option.replace("group", "GroupTB")
				elif 'Groups' in option:
					option = option.replace("Group", "GroupTB")
				elif 'groups' in option:
					option = option.replace("group", "GroupTB")
				elif 'Computer' in option:
					option = option.replace("Computer", "ComputerTB")
				elif 'computer' in option:
					option = option.replace("computer", "ComputerTB")
				elif 'Computers' in option:
					option = option.replace("Computer", "ComputerTB")
				elif 'computers' in option:
					option = option.replace("computer", "ComputerTB")
				else:
					print "Error: Invalid query, please try again."
					return cmd.Cmd.cmdloop(self, intro)
				tb = dp.read_sql(option, conn)
				print (tabulate(tb, showindex=False, headers=tb.columns, tablefmt="psql"))
				result(tb)
				return cmd.Cmd.cmdloop(self, intro)
			except pandas.io.sql.DatabaseError:
				print colors.RD + "[-] " + colors.NRM + "Error: Empty Database."

		def do_search(self, option, intro=None):
			try:
				value = option
				dp.options.display.max_colwidth = 40000
				group_tb = dp.read_sql('select * from GroupTB where Name like "%' + value + '%" or SID like "%' + value + '%" or Description like "%' + value + '%" or "Member Of" like "%' + value + '%"  or Members like "%' + value + '%"  COLLATE NOCASE', conn)
				group_tb['Description'] = group_tb['Description'].str[:35] + '...'
				if group_tb.empty:
					pass
				else:
					print "Groups"
					print "---------"
					print (tabulate(group_tb, showindex=False, headers=group_tb.columns, tablefmt="grid"))
				user_tb = dp.read_sql('select * from UserTB where Username like "%' + value + '%" or Description like "%' + value + '%" or SID like "%' + value + '%" or "Profile Path" like "%' + value + '%" or "Home Directory" like "%' + value + '%" or "Password Last Set" like "%' + value + '%" or "Last Logged On" like "%' + value + '%" or "Account Settings" like "%' + value + '%" or "Primary Group Name" like "%' + value + '%" or "Member Of" like "%' + value + '%" COLLATE NOCASE', conn)
				user_tb['Description'] = user_tb['Description'].str[:35] + '...'
				user_tb['Member Of'] = user_tb[['Primary Group Name', 'Member Of']].sum(axis=1)
				del user_tb['Primary Group Name']
				if user_tb.empty:
					pass
				else:
					print "Users"
					print "---------"
					print (tabulate(user_tb, showindex=False, headers=user_tb.columns, tablefmt="grid"))
				computer_tb = dp.read_sql('select * from ComputerTB where Name like "%' + value + '%" or Description like "%' + value + '%" or "Operating System" like "%' + value + '%" or "Operating System Version Number" like "%' + value + '%"  or "Member Of" like "%' + value + '%" COLLATE NOCASE', conn)
				if computer_tb.empty:
					pass
				else:
					print "Computers"
					print "---------"
					print (tabulate(computer_tb, showindex=False, headers=computer_tb.columns, tablefmt="grid"))
			except KeyboardInterrupt:
				return
			return cmd.Cmd.cmdloop(self, intro)

		def cmd_sub_arg_parse(self, option):
			global user
			global password
			global domain
			global netaddr
			global jitter
			netaddr = ''
			jitter = 1
			user = ''
			password = ''
			domain = ''
			args = iter(option.split())
			for arg in args:
				if arg == "-d" or arg == "--domain":
					domain = next(args)
				if arg == "-p" or arg == "--password":
					password = next(args)
				if arg == "-u" or arg == "--user":
					user = next(args)
				if arg == "-t" or arg == "--targets":
					try:
						addr = next(args)
						if addr.startswith("file://"):
							addrrange = addr.split("file:/")
							f = file(addrrange[1])
							s = f.read()
							s = s.replace("\n",",")
							netaddr = s[:-1]
						else:
							netaddr = addr
					except Error as e:
						print "Bad file"
				if arg == "-j" or arg == "--jitter":
					jitter = next(args)
			return

		def do_session(self, option, intro=None):
			try:
				self.cmd_sub_arg_parse(option)
				if not netaddr:
					print colors.RD + "[-] " + colors.NRM + "No target provided. Please try again"
					return
				else:
					targets = IP(netaddr)
				if not user and not password and not domain:
					print colors.RD + "[-] " + colors.NRM + "Missing user information (i.e Domain, Username, Password). Please try again"
				else:
					pass

				r = Sessions(domain, user, password, jitter)
				r.sessions(targets)
			except IndexError:
				print colors.RD + "[-] " + colors.NRM + "Invalid Option"
				print colors.BLU + "[*] " + colors.NRM + "Scans target(s) enumerating who has or is currently logged into the target(s), using  -u/--user. Can take a list or range of hosts, using -t/--target. To throttle the speed use the -j/--jitter and the number of seconds (default 1). Example  session --user admin -t 192.168.1./24 -j 3."
			except KeyboardInterrupt:
				return
			return cmd.Cmd.cmdloop(self, intro)

		def do_share_hunter(self, option, intro=None):
			try:
				self.cmd_sub_arg_parse(option)
				if not netaddr:
					print colors.RD + "[-] " + colors.NRM + "No target provided. Please try again"
					return
				else:
					targets = IP(netaddr)
				if not user and not password and not domain:
					print colors.RD + "[-] " + colors.NRM + "Missing user information (i.e Domain, Username, Password). Please try again"
				else:
					pass

				sh = Share_Hunting(domain, user, password, jitter)
				print targets
				sh.share_hunter(targets)
			except IndexError:
				print colors.RD + "[-] " + colors.NRM + "Invalid Option"
				print colors.BLU + "[*] " + colors.NRM + "Scans target(s) enumerating the shares on the target(s) and the level of access the specified user, using  -u/--user. Can take a list or range of hosts, using -t/--target. Example  share_hunter --user admin -t 192.168.1./24 -j 3."
			except KeyboardInterrupt:
				return
			return cmd.Cmd.cmdloop(self, intro)


		def do_help(self, intro=None):
			print "Commands"
			print "========"
			print "clear                Clears the screen"
			print "help                 Displays this help menu"
			print "list                 Lists either all Users, Computers, or Groups. Use the -f option to pipe the contents to a file"
			print "session              Scans target(s) to see who has/is currently logged in. Can take a list or range of hosts, using -t/--target and specify a user using -d/--domain, -u/--user, -p/--password and --jitter/-j to add a delay. Requires: read/write privileges on either Admin$ or C$ share"
			print "net                  Perform a query to view all information pertaining to a specific user, group, or computer (Similar to the Windows net user, net group commands). example: \'net group Domain Admins\'"
			print "columns              Displays the column names in each of the three major tables (users, groups and computers"
			print "query                Executes a query on the contents of tables"
			print "search               Searches for a key word(s) through every field of every table for any matches, displaying row"
			print "share_hunter         Scans target(s) enumerating the shares on the target(s) and the level of access the specified user, using -d/--domain, -u/--user, -p/--password. Can take a list or range of hosts, using -t/--target and --jitter/-j to add a delay"
			print "show                 Shows the contents of Users, Computers, Credentials, Groups, Password policy, Store, Credentials, Files Servers and Access tables"
			print "store                Displays the contents of a specific table. Example: \'show [table name] (access, creds, computers, file servers, pwdpolicy, users)"
			print "export               Export the contents of the database to a path in one of the following formats: CSV, HTML. (using with -f or --filetype)"
			print "exit                 Exit Vibe"
			return cmd.Cmd.cmdloop(self, intro)

		def do_store(self, intro=None):
			global store
			store = precommand
			return cmd.Cmd.cmdloop(self, intro)

		def do_add_cred(self, text, intro=None):
			try:
				text = text.split(' ')
				domain = text[0]
				username = text[1]
				if text[2] == "-p":
					password = text[3]
					hash = ' '
				elif text[2] == "-h":
					hash = text[3]
					password = ' '
				cred_db(domain, username, password, hash)
			except IndexError:
				print "[-] Invalid Option"
			return cmd.Cmd.cmdloop(self, intro)

		def do_clear(self, intro=None):
			subprocess.call('clear', shell=True)

		def cmdloop(self, line, intro=None):
			try:
				return cmd.Cmd.cmdloop(self, intro)
			except KeyboardInterrupt:
				self.do_exit(line)

		def precmd(self, line):
			global precommand
			precommand = self.lastcmd
			return line

		def emptyline(self, intro=None):
			return cmd.Cmd.cmdloop(self, intro)

		def default(self, line):
			self.stdout.write(colors.RD + '[-] ' + colors.NRM + 'Invalid Command: %s\n' % line)

		def complete_show(self, text, line, start_index, end_index):
			if not text:
				completions = show[:]
			else:
				completions = [f for f in show if f.startswith(text)]
			return completions

		def complete_net(self, text, line, start_index, end_index):
			if not text:
				completions = net[:]
			else:
				completions = [f for f in net if f.startswith(text)]
			return completions

		def do_exit(self, line):
			print colors.BLU + "[*] " + colors.NRM + "Exiting..."
			return True

		def do_EOF(self, line):
			return True
	except IndexError:
		print colors.BLU + "[*] " + colors.NRM + "Missing argument"


print "\n"
print" ___      ___  ___      ________      _______ "
print"|\  \    /  /||\  \    |\   __  \    |\  ____\ "
print"\ \  \  /  / /\ \  \   \ \  \|\ /_   \ \ \_____    "
print" \ \  \/  / /  \ \  \   \ \   __  \   \ \  ____\        "
print"  \ \    / /    \ \  \   \ \  \|\  \   \ \  \____ "
print"   \ \__/ /      \ \__\   \ \_______\   \ \______\ "
print"    \|__|/        \|__|    \|_______|    \|______|  "
print"                                           (@Tyl0us)    "
print "\n"

if args.remove:
	print colors.GRN + "[+] " + colors.NRM + "Removed Domain Database: " +args.domain
	subprocess.call("rm -rf .db/" + args.domain + ".db", shell=True)
	sys.exit()


global db_domain
db_domain = args.domain
name(db_domain)
hash = ''

if bool(args.offline):
	pass
else:
	path = os.getcwd() + "/"
	fp = path + (name(db_domain))
	if os.path.getsize(fp) > 1:
		pass
	else:
		connect(name(db_domain))
		create_connection()
		t = time.time()
		try:
			l = ldapz()
			if not args.port:
				args.port = "636"
			if not args.port:
				args.unencrypted = "False"
			l.main(args.IP, args.username, args.domain, args.password, args.port, args.unencrypted)
			print colors.BLU + "[*] " + colors.NRM + str(time.time() - t)
		except Error as e:
			print e
			print colors.RD + "[-] " + colors.NRM + "Error Occurred While Generating The Domain"
			subprocess.call("rm -rf .db/" + args.domain + ".db", shell=True)

if __name__ == '__main__':
	menu().cmdloop('')
