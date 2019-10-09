#!/usr/bin/env python
import warnings
warnings.simplefilter("ignore", UserWarning)
import ldap
from ldap3.protocol.formatters.formatters import format_sid
import datetime
from lib.DB import *
import threading
import time
import sys
import os
from ldap.controls import SimplePagedResultsControl

class colors:
	GRN = '\033[92m'
	RD = '\033[91m'
	NRM = '\033[0m'


class ldapz():
	def ldap_query(self,l, base_dn, subtree, objectFilter, attrs):
		ldap_control = ldap.controls.SimplePagedResultsControl (True, size=1000, cookie='' )
		results = []
		while True:
			msgid = l.search_ext (base_dn, subtree, objectFilter, attrs, serverctrls=[ldap_control] )
			rtype, rawResults, id, server_controls = l.result3 ( msgid )
			results += rawResults
			page_controls = [c for c in server_controls if c.controlType == ldap.controls.SimplePagedResultsControl.controlType]
			if page_controls:
				cookie = page_controls[0].cookie
			if not cookie:
				break
			else:
				ldap_control.cookie = cookie
		return results

	def ADtime(self, time):
		global date
		seconds = int(time) / 10000000
		if seconds == 0:
			epoch = 0
		else:
			epoch = seconds - 11644473600
		dt = datetime.datetime(2000, 1, 1, 0, 0, 0)
		date = dt.fromtimestamp(epoch)

	def main(self, IP, lusername, domain, password, unencrypted, port):
		global gid
		global l
		gid = ""
		username = []
		Desc = []
		HD = []
		PLS = []
		LLO = []
		memberof = []
		members = []
		system = []
		GroupID = []
		UACL = []
		sidnumber = []
		operatingsystemversion = []
		operatingsystem = []
		FGminpass = []
		FGlocknum = []
		FGpasshis = []
		FGlockdur = []
		FGpassp = []
		FGmembers = []
		usernamelist = []
		profilepath = []
		samnamelist = []
		sql = load ()
		if port:
			IP = IP+":"+args.ports
		if unencrypted == True :
			con = ldap.initialize('ldap://' + IP)
		else:
			ldap.set_option( ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER )
			con = ldap.initialize('ldaps://'+IP )

		try:
			con.simple_bind_s(lusername + '@' + domain, password)
			print colors.GRN + "[+] "+ colors.NRM + "Credentials valid, generating database"
		except ldap.INVALID_CREDENTIALS:
			print colors.RD + "[-] "+ colors.NRM +  "Username or password is incorrect."
			os.remove ( ".db/" + domain + ".db")
			sys.exit()
		except ldap.SERVER_DOWN:
			print colors.RD + "[-] "+ colors.NRM + "Domain Controller either down or unreachable"
			os.remove(".db/" + domain + ".db")
			sys.exit()
		dictionary=['distinguishedName', 'sAMAccountName']
		user_attributes = ['distinguishedName', 'sAMAccountName', 'description', 'objectSid', 'homeDirectory', 'profilePath', 'pwdLastSet', 'lastLogon', 'memberOf',
						   'primaryGroupID', 'userAccountControl']
		group_attributes = ['distinguishedName', 'sAMAccountName', 'description', 'memberOf', 'member', 'objectSid']
		computer_attributes = ['description', 'memberOf', 'operatingSystem', 'operatingSystemVersion']
		FGPP_attributes = ['msDS-LockoutDuration', 'msDS-MaximumPasswordAge', 'msDS-LockoutThreshold', 'msDS-MinimumPasswordLength', 'msDS-PasswordComplexityEnabled', 'msDS-PasswordHistoryLength','msDS-PSOAppliesTo','pwdProperties']
		searchScope = ldap.SCOPE_SUBTREE
		object = ['user', 'group', 'computer', 'msDS-PasswordSettings', 'FGPP-PasswordSettings']
		if unencrypted == True:
			l = ldap.initialize('ldap://' + IP)
		else:
			l = ldap.initialize( 'ldaps://'+IP )
		l.set_option( ldap.OPT_REFERRALS, 0 )
		l.simple_bind_s(lusername + '@' + domain, password)
		domain = domain.replace('.', ',DC=')
		baseDN = "DC="+domain
		sql = load()
		connect_db()
		sql.begin()
		try:
			for obj in object:
				searchFilter = '(&(objectCategory=' + obj + '))'
				if obj == 'group':
					print colors.GRN + "[+] " + colors.NRM + "Table 1/4 : Generating Group Table"
					results = self.ldap_query(l, baseDN, searchScope, searchFilter, group_attributes)
					memberof = []
					Desc = []
					username = []
					dictionary = dict ( zip ( usernamelist, samnamelist ) )
				if obj == 'user':
					print colors.GRN + "[+] " + colors.NRM + "Table 2/4 : Generating User Table"
					results = self.ldap_query ( l, baseDN, searchScope, searchFilter, user_attributes )
					memberof = []
					Desc = []
					username = []
				if obj == 'computer':
					print colors.GRN + "[+] " + colors.NRM + "Table 3/4 : Generating Computer Table"
					results = self.ldap_query ( l, baseDN, searchScope, searchFilter, computer_attributes )
					memberof = []
					Desc = []
				if obj == 'msDS-PasswordSettings':
					print colors.GRN + "[+] " + colors.NRM + "Table 4/4 : Generating Password Policy Table"
					results = l.search_s( baseDN, ldap.SCOPE_BASE )
				if obj == 'FGPP-PasswordSettings':
					FGPPDN = 'CN=Password Settings Container,CN=System,' + (baseDN)
					searchFilter = '(&(objectCategory=msDS-PasswordSettings))'
					results = l.search_s(FGPPDN, searchScope, searchFilter, FGPP_attributes)
				for result in results:
					if result[0] is None:
						pass
					else:
						result_dn = result[0].replace( 'CN=', '' ).split( ',' )
						results_attrs = result[1]
						name = result_dn[0]
						if 'sAMAccountName' in results_attrs:
							sAMAccountName = str( results_attrs['sAMAccountName'] ).replace( '[', '' ).replace( ']', '' )[1:-1]
						else:
							sAMAccountName = ""
						if 'description' in results_attrs:
							description = str( results_attrs['description'] ).replace( '[', '' ).replace( ']', '' )[1:-1]
						else:
							description = ""
						if 'profilePath' in results_attrs:
							profilepath = str( results_attrs['profilePath'] ).replace( '[', '' ).replace( ']', '' )[
											1:-1]
						else:
							profilepath = ""
						if 'homeDirectory' in results_attrs:
							homeDirectory = str ( results_attrs['homeDirectory'] ).replace ( '[', '' ).replace ( ']', '' )[
											1:-1]
						else:
							homeDirectory = ""
						if 'pwdLastSet' in results_attrs:
							time = str( results_attrs['pwdLastSet'] ).replace( '[', '' ).replace( ']', '' )[1:-1]
							self.ADtime( time )
							pwdLastSet = date
						else:
							pwdLastSet = ""
						if 'lastLogon' in results_attrs:
							time = str( results_attrs['lastLogon'] ).replace( '[', '' ).replace( ']', '' )[1:-1]
							self.ADtime( time )
							lastLogon = date
						else:
							lastLogon = ""
						if 'primaryGroupID' in results_attrs:
								gidnum = str( results_attrs['primaryGroupID'] ).replace( '[', '' ).replace( ']', '' ).replace('\'', '' )
						else:
							pass
						if 'memberOf' in results_attrs:
							membersOf = []
							for memberOf in results_attrs["memberOf"]:
								r = memberOf.split( ',CN=' )[0].replace( 'CN=', '' ).replace(',Builtin,'+baseDN+'', '' ).replace(baseDN,'').replace('OU=',' ')
								r = r.split(',')
								membersOf.append(r[0])
							membersOf = ','.join( membersOf ).replace(',','\n')
						else:
							membersOf = ""
						if "member" in results_attrs:
							mem = []
							if obj == 'group':
								trimmed_results = results_attrs.copy ()
								del trimmed_results['distinguishedName'], trimmed_results['sAMAccountName'], trimmed_results['objectSid']
								if 'description' in trimmed_results:
									del trimmed_results['description']
								if 'memberOf' in trimmed_results:
									del trimmed_results['memberOf']
								for key, value in trimmed_results.iteritems ():
									for v in value:
										t = v.split ( ',CN=' )[0].replace ( 'CN=', '' ).replace ( baseDN,' ' ).replace ( 'OU=',' ' )
										t = t.split ( ',' )
										if str ( t[0] ) in usernamelist:
											mem.append ( dictionary['' + str ( t[0] ) + ''] )
										else:
											mem.append ( str ( t[0] ) )

							else:
								for member in results_attrs["member"]:
									t = member.split ( ',CN=' )[0].replace ( 'CN=', '' ).replace ( baseDN, ' ' ).replace ( 'OU=', ' ' )
									t = t.split ( ',' )
									mem.append ( str ( t[0] ) )
								if str ( t[0] ) in usernamelist:
									mem.append ( dictionary['' + str ( t[0] ) + ''] )
								else:
									mem.append ( str ( t[0] ) )
							mem = ','.join ( mem ).replace ( ',', '\n' )
						else:
							mem = " "
						if 'objectSid' in results_attrs:
							for SID in results_attrs["objectSid"]:
								sids = (format_sid( SID ).split( '-' )[-1])

						if 'userAccountControl' in results_attrs:
							userac = []
							uac = {'ACCOUNT_DISABLED': 0x00000002,
								   'ACCOUNT_LOCKED': 0x00000010,
								   'PASSWD_NOTREQD': 0x00000020,
								   'PASSWD_CANT_CHANGE': 0x00000040,
								   'NORMAL_ACCOUNT': 0x00000200,
								   'WORKSTATION_ACCOUNT': 0x00001000,
								   'SERVER_TRUST_ACCOUNT': 0x00002000,
								   'DONT_EXPIRE_PASSWD': 0x00010000,
								   'SMARTCARD_REQUIRED': 0x00040000,
								   'PASSWORD_EXPIRED': 0x00800000
								   }
							UAC = results_attrs["userAccountControl"]
							for trigger, val in uac.items():
								vUAC = ''.join(UAC)
								if int(vUAC) & val:
									userac.append(trigger)
							userac = str(userac).replace('[','').replace(']','').replace(',','\n').replace(' ', '').replace('\'','')

						if 'operatingSystem' in results_attrs:
							OS = str(results_attrs["operatingSystem"]).replace('\']', '').replace('[\'', '')
						else:
							OS = ""
						if 'operatingSystemVersion' in results_attrs:
							OSV = str( results_attrs["operatingSystemVersion"] ).replace( '\']', '' ).replace( '[\'', '' )
						else:
							OSV = ""
						if "msDS-MinimumPasswordLength" in results_attrs:
							FGminpwd = (str ( results_attrs["msDS-MinimumPasswordLength"] ).replace ( '[\'', '' ).replace ('\']', '' ))
						else:
							FGminpwd = ' '
						if "msDS-LockoutThreshold" in results_attrs:
							FGlcknum = (str ( results_attrs["msDS-LockoutThreshold"] ).replace ( '[\'', '' ).replace ( '\']', '' ))
						else:
							FGlcknum = ' '
						if "msDS-PasswordHistoryLength" in results_attrs:
							FGpwdhis = (str ( results_attrs["msDS-PasswordHistoryLength"] ).replace ( '[\'', '' ).replace ('\']', '' ))
						else:
							FGpwdhis = ' '
						if "msDS-LockoutDuration" in results_attrs:
							FGlckduration = results_attrs["msDS-LockoutDuration"]
							FGlckdur = (str ((int ( str ( FGlckduration ).replace ( '[\'-', '' ).replace ( '\']', '' ) ) * 0.0000001) / 60 ))
						else:
							FGlckdur = ' '
						if "msDS-PasswordComplexityEnabled" in results_attrs:
							FGpwdp = (str ( results_attrs["msDS-PasswordComplexityEnabled"] ).replace ( '[\'', '' ).replace ( '\']', '' ))
						else:
							FGpwdp = ' '
						if "msDS-PSOAppliesTo" in results_attrs:
							FGmember = (str ( results_attrs["msDS-PSOAppliesTo"] ).replace ( '[\'', '' ).replace ( '\']', '' ).replace (',CN=Users,DC=STARLABS,DC=local', '\n' ).replace('CN=',''))
						else:
							FGmember = ' '
						if obj == 'msDS-PasswordSettings':
							pwdpar = []
							minpwd = str( results_attrs["minPwdLength"] ).replace( '[\'', '' ).replace( '\']', '' )
							lcknum = str( results_attrs["lockoutThreshold"] ).replace( '[\'', '' ).replace( '\']', '' )
							pwdhis = str( results_attrs["pwdHistoryLength"] ).replace( '[\'', '' ).replace( '\']', '' )
							lckdur = results_attrs["lockoutDuration"]
							lckdur = str(
								(int( str( lckdur ).replace( '[\'-', '' ).replace( '\']', '' ) ) * 0.0000001) / 60 )
							pwdp = str( results_attrs["pwdProperties"] ).replace( '[\'', '' ).replace( '\']', '' )
							pwdpa = {
								'DOMAIN_PASSWORD_COMPLEX': 1,
								'DOMAIN_PASSWORD_NO_ANON_CHANGE': 2,
								'DOMAIN_PASSWORD_NO_CLEAR_CHANGE': 4,
								'DOMAIN_LOCKOUT_ADMINS': 8,
								'DOMAIN_PASSWORD_STORE_CLEARTEXT': 16,
								'DOMAIN_REFUSE_PASSWORD_CHANGE': 32}
							for trigger, val in pwdpa.items():
								vpwdp = ''.join( pwdp )
								if int( vpwdp ) & val:
									pwdpar.append( trigger )
							pwdpar = str( pwdpar ).replace( '[\'', '' ).replace( '\']', '' )
							sql.Insert_Passwd(minpwd, lcknum, lckdur, pwdhis, (pwdp + " " + pwdpar))
						if obj == 'FGPP-PasswordSettings':
							sql.Insert_FGPasswd(FGminpwd, FGlcknum, FGpwdhis, FGlckdur, FGpwdp, FGmember)
						if obj == 'group':
							sql.Insert_Groups(name, sids, description, str( membersOf), str(mem))
						if obj == 'user':

							usernamelist.append(name)
							samnamelist.append(sAMAccountName)
							sql.insert_Users(sAMAccountName, description, sids, homeDirectory, profilepath, pwdLastSet, lastLogon, userac, str(gidnum), (str(membersOf)))
						if obj == 'computer':
							sql.Insert_Computers(name, description, OS, OSV, (str(membersOf)))
		except ldap.REFERRAL:
			print colors.RD + "[-] "+ colors.NRM + "Incorrect fully qualified domain name. Please check your settings and try again."
			sys.exit()
		sql.Close()
	#	try:
	#		fileshare ()
	#	except TypeError as e:
	#		print colors.RD + "[-] " + colors.NRM + "Error occured generating list of file shares"
	#		print "[*] Skipping Fileshare enumeration. As result show fileshare will not work (however manual queries will work"
	#		pass
		print colors.GRN + "[+] "+ colors.NRM + "Database successfully created"
		groupIDquery ()
