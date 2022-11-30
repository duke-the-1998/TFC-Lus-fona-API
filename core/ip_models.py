#!/usr/bin/env python3

import datetime
import http.client
import ipaddress
import json
import logging
import logging.config
#import math
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import dns.resolver
import requests
#from ail_typo_squatting import runAll, subdomain
from bs4 import BeautifulSoup
from urllib.parse import urlparse


#---------------------------------------------------------



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
