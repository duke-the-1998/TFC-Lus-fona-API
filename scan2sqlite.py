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
		if not isinstance(port, ModelPort):
			raise ValueError("port is not a ModelPort")

		self.ports.append(port)
		
	def __str__(self):
		ports = ', '.join([str(i) for i in self.ports])
		if self.name:
			return "{0}: {1} -> [{2}]".format(self.name, self.address, ports)

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


class ModelInfo:
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
		conn.execute("PRAGMA foreign_keys = on")
		conn.execute('''
			CREATE TABLE IF NOT EXISTS `Host` (
				`HostID` INTEGER PRIMARY KEY AUTOINCREMENT,
				`Address`	TEXT,
				`Name`	TEXT
			
		);
		''')

		conn.execute('''
			CREATE TABLE IF NOT EXISTS `Port` (
				ID INTEGER PRIMARY KEY AUTOINCREMENT,
				HostID   INTEGER,
				`Time` TIMESTAMP,
				`Port`	INTEGER,
				`Protocol`	TEXT,
				`Description`	TEXT,
				`State`	TEXT,
				`SSL`	INTEGER,
				FOREIGN KEY (HostID, `Time`) REFERENCES `Time`(HostID, `Time`)
		);
		''')

		conn.execute('''
			CREATE TABLE IF NOT EXISTS `Time` (
				HostID   INTEGER,
				`Time` TIMESTAMP,
				PRIMARY KEY (HostID, `Time`),
				FOREIGN KEY (HostID) REFERENCES `Host`(`HostID`)
		);
		''')


		for host in self.hosts:
			sql = 'INSERT INTO `Host`(`Address`,`Name`) VALUES (?,?)'
			values = (host.address, host.name)
			self.logger.debug(sql)
			self.logger.debug(values)
			conn.execute(sql, values)
			sql='SELECT HostID FROM `Host` WHERE `Address`=?'
			values = (host.address,)
			
			host_id = conn.execute(sql, values).fetchall()[0][0]
		
			#tabela time
			sql = 'INSERT INTO `Time`(HostID, `Time`) VALUES (?,?)'
			date = datetime.datetime.now()
			values = (host_id, date)
			self.logger.debug(sql)
			self.logger.debug(values)
			conn.execute(sql, values)
					
			for port in host.ports:
				sql = 'INSERT INTO `Port` VALUES (?,?,?,?,?,?,?,?)'
				values = (None, host_id,date, port.nr, port.proto, port.description, port.state, port.ssl)
				self.logger.debug(sql)
				self.logger.debug(values)
				conn.execute(sql, values)
				
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
				if hostnames:
					h = ModelHost(host.address['addr'], name=hostnames[0]['name'])
				else:
					h = ModelHost(host.address['addr'])
				ports = host.find_all("port")

				for port in ports:
					#So permite open ports e nao filtered
					if "open" in port.state['state'] and "open|filtered" not in port.state['state']:
						if port.service:
							ssl = 'tunnel' in port.service.attrs and port.service['tunnel'] == 'ssl'		
							p = ModelPort(nr=port['portid'], proto=port['protocol'], desc=port.service['name'], ssl=ssl, state=port.state['state'])
						else:
							p = ModelPort(nr=port['portid'], proto=port['protocol'], state=port.state['state'])
						h.addport(p)
			else:
				h = ModelHost(host.address['addr'])

			self.logger.debug(h)
			self.hosts.append(h)
		self.__store__()


def blacklistTosql(ip):
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	cursor = conn.cursor()
	conn.execute('''
			CREATE TABLE IF NOT EXISTS `Blacklist` (
				ID INTEGER PRIMARY KEY AUTOINCREMENT,
				HostID INTEGER,
				`Blacklist`	TEXT,
				`Time` TIMESTAMP,
				FOREIGN KEY (HostID, `Time`) REFERENCES `Time`(HostID, `Time`)
		);
		''')
	
	source = "blacklist_"+ip+".xml"
	sql='SELECT HostID FROM `Host` WHERE `Address`=?'
	values = (ip,)
	host_id = conn.execute(sql, values).fetchall()

	sql='SELECT `Time` FROM `Time` WHERE HostID=?'
	

	host_id=host_id[0][0]
	values=(host_id,)
	time = conn.execute(sql, values).fetchall()
	time = time[0][0]

	with open (source, "r") as f:
		for line in map(str.strip, f):
			soup = BeautifulSoup(line, 'xml')
			bls = soup.find_all("blacklistinfo")

			for bl in bls:
				b = ModelInfo(bl['blacklisted'])
				values = (None, host_id, str(b), time)
				sql = 'INSERT INTO `Blacklist` VALUES (?,?,?,?)'
				
				conn.execute(sql, values)
				conn.commit()

def reverseTosql(ip):
	''' funcao que guarda os valores lidos de um ficheiro xml na base de dados

		Param:
		ip: string ip do alvo

		Funcionamento:
		Cria a tabela ReverseIP senão existir;
		Le o ficheiro xml e retira os dados necessarios;
		Coloca os dados na base de dados.
	'''
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)

	conn.execute('''
			CREATE TABLE IF NOT EXISTS `ReverseIP` (
				ID INTEGER PRIMARY KEY AUTOINCREMENT,
				HostID INTEGER,
				`ReverseIP`	TEXT,
				`Time` TIMESTAMP,
				FOREIGN KEY (HostID, `Time`) REFERENCES `Time`(HostID, `Time`)
		);
		''')
	
	source = "reverseIP_"+ip+".xml"

	sql='SELECT HostID FROM `Host` WHERE `Address`=?'
	values = (ip,)

	host_id = conn.execute(sql, values).fetchall()

	sql='SELECT `Time` FROM `Time` WHERE HostID=?'
	

	host_id=host_id[0][0]
	values=(host_id,)
	time = conn.execute(sql, values).fetchall()
	time = time[0][0]

	soup = BeautifulSoup(open(source).read(), "xml")
	rvs = soup.find_all("reverseip")

	
	for rv in rvs:
		r = ModelInfo(rv['reverseIp'])
		values = (None, host_id, str(r),time)
		sql = 'INSERT INTO `ReverseIP` VALUES (?,?,?,?)'
		
		conn.execute(sql, values)
		conn.commit()

def cleanDB():
	db = "monitorizadorIPs.db"
	conn = sqlite3.connect(db)
	conn.execute(''' DROP TABLE IF EXISTS `Blacklist`;''')
	conn.execute(''' DROP TABLE IF EXISTS `Port`;''')
	conn.execute(''' DROP TABLE IF EXISTS `ReverseIP`;''')
	conn.execute(''' DROP TABLE IF EXISTS `Time`;''')
	conn.execute(''' DROP TABLE IF EXISTS `Host`;''')
	
	conn.commit()

def starter(ip):
	
	logging.config.dictConfig(logconfig)
	logger = logging.getLogger()
	logger.info("Nmap parsing '{0}'".format(ip))

	#nome da base de dados pode ser alterado
	db = "monitorizadorIPs.db"
	NmapXMLInmporter(ip, database=db)


if __name__== "__main__":
	
	cleanDB()

	fl = open(sys.argv[1], "r").readlines() 
    
	for line in fl:
		
		ip = line.strip()
		f = ip+".xml"

		starter(f)
		blacklistTosql(ip)
		reverseTosql(ip)

	#os.remove(ip+".xml")
	#os.remove("blacklist_"+ip+".xml")
	#os.remove("reverseIP_"+ip+".xml")
	#os.remove("mscan.json")
	#os.remove("scans.txt")
	#os.remove("cleanIPs.txt")