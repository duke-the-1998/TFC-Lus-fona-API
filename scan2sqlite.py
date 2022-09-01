#!/usr/bin/env python3
import logging
import logging.config
import os
import sqlite3
import tempfile
import argparse
import re

import xmltodict
import sys
import datetime

from bs4 import BeautifulSoup


logconfig = { 
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': { 
        'standard': { 
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': { 
        'default': { 
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
        },
    },
    'loggers': { 
        '': {
            'handlers': ['default'],
            'level': 'DEBUG',
            'propagate': True
        },
    } 
}

class ModelHost:
	def __init__(self, address, addrtype="ipv4", name=None):
		self.address = address
		self.addrtype = addrtype
		self.name = name
		self.ports = []

	def addport(self, port):
		if isinstance(port, ModelPort):
			self.ports.append(port)
		else:
			raise ValueError("port is not a ModelPort")

	def __str__(self):
		ports = ', '.join([str(i) for i in self.ports])
		if self.name:
			return "{0}: {1} -> [{2}]".format(self.name, self.address, ports)
		else:
			return "{0} -> [{1}]".format(self.address, ports)

class ModelPort:
	def __init__(self, nr, proto="tcp", desc=None, state="open", ssl=False):
		self.nr = int(nr)
		self.proto = proto
		self.description = desc
		self.state = state
		self.ssl = ssl

	def __str__(self):
		return '{0}'.format(self.nr)


class ModelBlacklist:
	def __init__(self, bl):
		self.bl = bl

	def __str__(self):
		return '{0}'.format(self.bl)

#reverIP Model TODO

class Importer:
	def __init__(self, source, database=tempfile.mktemp('-hosts.db')):
		self.logger = logging.getLogger(self.__class__.__name__)
		self.source = source
		self.database = database
		self.hosts = []
		self.__process__()

	def __process__(self):
		self.logger.error("Not implemented here...")
		raise NotImplementedError("import")

	def __store__(self):
		self.logger.info('Opening database: {0}'.format(self.database))
		conn = sqlite3.connect(self.database)
		c = conn.cursor()
		c.execute("PRAGMA foreign_keys = on")
		c.execute('''
			CREATE TABLE IF NOT EXISTS `Host` (
				`HostID` INTEGER PRIMARY KEY AUTOINCREMENT,
				`Address`	TEXT,
				`Name`	TEXT
				
		);
		''')

		c.execute('''
			CREATE TABLE IF NOT EXISTS `Port` (
				ID   INTEGER,
				`Port`	INTEGER,
				`Protocol`	TEXT,
				`Description`	TEXT,
				`State`	TEXT,
				`SSL`	INTEGER,
				`Time` TIMESTAMP,
				PRIMARY KEY( `ID`,`Port`, `Protocol`),
				FOREIGN KEY (ID) REFERENCES `Host`(`HostID`)

		);
		''')
		
		for host in self.hosts:
			sql = 'INSERT OR REPLACE INTO `Host`(`Address`,`Name`) VALUES (?,?)'
			values = (host.address, host.name)
			self.logger.debug(sql)
			self.logger.debug(values)
			conn.execute(sql, values)
			sql='SELECT HostID FROM `Host` WHERE `Address`=?'
			values = (host.address,)
			
			host_id = conn.execute(sql, values).fetchall()[0][0]
			
			
			for port in host.ports:
				sql = 'INSERT OR REPLACE INTO `Port` VALUES (?,?,?,?,?,?,?)'
				values = (host_id, port.nr, port.proto, port.description, port.state, port.ssl, datetime.datetime.now())
				self.logger.debug(sql)
				self.logger.debug(values)
				conn.execute(sql, values)
				'''
				source = "blacklist_"+ip+".xml"
				with open (source, "r") as f:
					for line in map(str.strip, f):
						
						soup = BeautifulSoup(line, 'xml')
						bls = soup.find_all("blacklistinfo")
						#print(bls)
					
						for bl in bls:
							#print(bl)
							b = ModelBlacklist(bl['warning'])
							#b = ModelBlacklist(bl['blacklisted'])
							print(b)
							values = (host_id, str(b))
							sql = 'INSERT OR REPLACE INTO `Blacklist` VALUES (?,?)'
							
							conn.execute(sql, values)
							conn.commit()
						'''
		conn.commit()
		

class NmapXMLInmporter(Importer):
	def __process__(self, source=None):
		if not source:
			source = self.source
		self.logger.debug("Processing {0}".format(source))
		soup = BeautifulSoup(open(source).read(), "xml")
		hosts = soup.find_all("host")
		for host in hosts:
			if host.status['state'] == 'up':
				hostnames = host.find_all("hostname", attrs={'type':'user'})
				if len(hostnames) > 0:
					h = ModelHost(host.address['addr'], name=hostnames[0]['name'])
				else:
					h = ModelHost(host.address['addr'])
				ports = host.find_all("port")
				for port in ports:
					if "open" in port.state['state'] and "open|filtered" not in port.state['state']:
						if port.service:
							if 'tunnel' in port.service.attrs and port.service['tunnel'] == 'ssl':
								ssl = True
							else:
								ssl = False
							p = ModelPort(nr=port['portid'], proto=port['protocol'], desc=port.service['name'], ssl=ssl, state=port.state['state'])
						else:
							p = ModelPort(nr=port['portid'], proto=port['protocol'], state=port.state['state'])
						h.addport(p)

				self.logger.debug(h)
				self.hosts.append(h)
		self.__store__()


def blacklistTosql(ip):
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	cursor = conn.cursor()
	#c = conn.cursor()
	conn.execute('''
			CREATE TABLE IF NOT EXISTS `Blacklist` (
				HostID INTEGER,
				`Blacklist`	TEXT,

				PRIMARY KEY (HostID, `Blacklist`),
				FOREIGN KEY (HostID) REFERENCES `Host`(HostID)
		);
		''')
	
	source = "blacklist_"+ip+".xml"
	sql='SELECT HostID FROM `Host` WHERE `Address`=?'
	values = (ip,)
			
	host_id = conn.execute(sql, values).fetchall()[0][0]
	with open (source, "r") as f:
		for line in map(str.strip, f):
			
			soup = BeautifulSoup(line, 'xml')
			bls = soup.find_all("blacklistinfo")
			#print(bls)
		
			for bl in bls:
				#print(bl)
				b = ModelBlacklist(bl['warning'])
				#b = ModelBlacklist(bl['blacklisted'])
				print(b)
				values = (host_id, str(b))
				sql = 'INSERT INTO `Blacklist` VALUES (?,?)'
				
				conn.execute(sql, values)
			
		conn.commit()

def reverseTosql(ip):
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)

	conn.execute('''
			CREATE TABLE IF NOT EXISTS `ReverseIP` (
				ID INTEGER PRIMARY KEY,
				`ReverseIP`	BLOB,

				FOREIGN KEY (ID) REFERENCES Host(HostID)
		);
		''')
	
	source = "reverseIP_"+ip+".xml"
	soup = BeautifulSoup(open(source).read(), "xml")
	rvs = soup.find_all("reverseip")
	for rv in rvs:
			r = ModelBlacklist(rv['reverseIp'])
			print(r)

			values = (None, str(r))
			sql = 'INSERT OR REPLACE INTO `ReverseIP` VALUES (?,?)'
			
			conn.execute(sql, values)
			conn.commit()

def cleanDB():
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	conn.execute(''' DROP TABLE IF EXISTS `Blacklist`;''')
	conn.execute(''' DROP TABLE IF EXISTS `Port`;''')
	conn.execute(''' DROP TABLE IF EXISTS `ReverseIP`;''')
	conn.execute(''' DROP TABLE IF EXISTS `Host`;''')
	
	conn.commit()

def main(ip):
	#parser = argparse.ArgumentParser(description='Import Nessus and Nmap results into a sqlite database')
	#parser.add_argument('-f', nargs='+', dest="nmap", default=[], help='Nmap filename(s) to import')
	#parser.add_argument('-n', nargs='+', dest="nessus", default=[], help='Nessus filename(s) to import')
	#parser.add_argument('-m', nargs='+', dest="masscan", default=[], help='Masscan filename(s) to import')
	#parser.add_argument('database', help='Sqlite database path to create/update')

	#args = parser.parse_args()
	
	logging.config.dictConfig(logconfig)
	logger = logging.getLogger()
			#db = args.database
			#for i in args.nmap:
	logger.info("Nmap parsing '{0}'".format(ip))
	db = "monitorizadorIPs.db"
	NmapXMLInmporter(ip, database=db)



if __name__== "__main__":
	
	cleanDB()
	file = open(sys.argv[1], "r").readlines() 
    
	for line in file:
    
			ip = line.strip()
			f = ip+".xml"
			main(f)
			blacklistTosql(ip)
			reverseTosql(ip)





#sqlite3 database.db 'select "http://" || address || ":" || nr from port where ssl=0 and description like "%http%"'