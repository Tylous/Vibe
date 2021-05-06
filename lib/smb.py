#!/usr/bin/env python
from impacket.dcerpc.v5 import wkst, drsuapi, epm, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.rpcrt import DCERPCException
import time
from impacket.smbconnection import *
import string
import random
from time import sleep
from lib.DB import *

global targets
global jitter

class colors:
	GRN = '\033[92m'
	RD = '\033[91m'
	NRM = '\033[0m'
	BLU = '\033[34m'


class Share_Hunting():
	def __init__(self, domain, username, password, jitter):
		self._domain = domain
		self._user = username
		self._password = password
		self._lmhash = ''
		self._nthash = ''
		self._jitter = jitter
		print("Scanning Using: " + self._domain + "\\" + self._user + ": " + self._password)

	def id_generator(self, size=6, chars=string.ascii_uppercase + string.digits):
		return ''.join(random.choice(chars) for _ in range(size))

	def share_hunter(self, targets):
		targetlist = []
		sharelist = []
		permissionlist = []
		for target in targets:
			time.sleep(int(self._jitter))
			try:
				print(target)
				print("-----------------")
				smb = SMBConnection('*SMBSERVER', target, sess_port=445, timeout=10)
				smb.login(self._user, self._password, self._domain)
				list = smb.listShares()
				for shares in range(len(list)):
					perm = ""
					share = list[shares]['shi1_netname'][:-1]
					path = '\\*'
					if not share == "IPC$":
						try:
							read = smb.listPath(share, path)
							if read:
								try:
									path = '\\' + self.id_generator() + '\\'
									write = smb.createDirectory(share, path)
									if write:
										smb.deleteDirectory(share, path)
										print("   " + colors.GRN + "[+]" + colors.NRM + "  " + share + ": Read\Write")
										perm = 'Read\Write'
								except Exception:
									print("   " + colors.BLU + "[*]" + colors.NRM + "  " + share + ": Read")
									perm = 'Read'
						except Exception:
							print("   " + colors.RD + "[-]" + colors.NRM + "  " + share + ": No Access")
							del perm
							continue
						if perm:
							targetlist.append(target)
							sharelist.append(share)
							permissionlist.append(perm)
			except Exception:
				print(colors.BLU + "   [*] " + colors.NRM + "Host either not accessible or port 445 closed")
				continue
			except KeyboardInterrupt:
				return
			except SessionError:
				continue
		share_db = {'Computer': '', 'Share': '', 'Permission': ''}
		share_db.update(Computer=targetlist)
		share_db.update(Share=sharelist)
		share_db.update(Permission=permissionlist)
		sharetable(self._user, share_db)


class Sessions():
	def __init__(self, domain, username, password, jitter):
		self._domain = domain
		self._user = username
		self._password = password
		self._lmhash = ''
		self._nthash = ''
		self._jitter = jitter
		print("Authenticating Using: "+ self._domain + "\\" + self._user + ": " + self._password)


	def _create_rpc_connection(self, target_computer):
		rpctransport = transport.SMBTransport(target_computer, 445, r'\wkssvc', username=self._user, password=self._password, domain=self._domain, lmhash=self._lmhash, nthash=self._nthash)
		rpctransport.set_connect_timeout(10)
		dce = rpctransport.get_dce_rpc()
		try:
			dce.connect()
		except socket.error:
			return
		else:
			dce.bind(wkst.MSRPC_UUID_WKST)
			self._rpc_connection = dce

	def sessions(self, targets):
		for target in targets:
			users = []
			try:
				target_computer = target
				self._create_rpc_connection(target_computer)
				print(target_computer)
				print("-----------------")
				smb = SMBConnection('*SMBSERVER', target_computer, sess_port=445, timeout=5)
				smb.login(self._user, self._password, self._domain)
				try:
					sess = wkst.hNetrWkstaUserEnum(self._rpc_connection, 1)
				except DCERPCException as e:
					users = []
					print(colors.RD + "     [-]" + colors.NRM + " User does not have access")
					continue
				for wksta_user in sess['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
					userName = wksta_user['wkui1_username'][:-1]
					logonDomain = wksta_user['wkui1_logon_domain'][:-1]
					if "$" in userName:
						pass
					else:
						user = '%s\%s' % (logonDomain, userName)
						if user in users:
							pass
						else:
							users.append(user)
				print("  Currently Logged On")
				print("  -------------------")
				for user in users:
					print("     " + colors.GRN + "[+] " + colors.NRM + user)
				del users
				share = 'C$'
				path = '\\Users\\*'
				read = smb.listPath(share, path)
				print("\n  Users Who Have Logged On")
				print("  -------------------------")
				for r in read:
					if r.get_longname() == "Public" or r.get_longname() == "All Users" or r.get_longname() == "Default" or r.get_longname() == "Default User" or r.get_longname() == "." or r.get_longname() == "..":
						pass
					else:
						if r.is_directory():
							print(colors.GRN + "     [+] " + colors.NRM + r.get_longname() + " lastlogon: " + time.ctime(float(r.get_mtime_epoch())))
			except UnboundLocalError as e:
				print(target)
				users = []
				print(e)
				print(colors.RD + "     [-] " + colors.NRM + "User does not have access")
				continue
			except socket.error:
				users = []
				print(colors.BLU + "     [*] " + colors.NRM + "Host either not accessible or port 445 closed")
				continue

			except KeyboardInterrupt:
				return
			except SessionError:
				try:
					share = 'C$'
					path = '\\Documents and Settings\\*'
					read = smb.listPath(share, path)
					print("\nUsers who have logged on")
					print("--------------------------")
					for r in read:
						if r.get_longname() == "Public" or r.get_longname() == "All Users" or r.get_longname() == "Default" or r.get_longname() == "Default User" or r.get_longname() == "." or r.get_longname() == "..":
							pass
						else:
							if r.is_directory():
								print("     [*] " + r.get_longname() + " lastlogon: " + time.ctime(float(r.get_mtime_epoch())))
				except SessionError:
					continue
