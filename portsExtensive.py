#!/bin/env python3

import re

class PortScanner:

	ports = []

	def scanner_sshd(self, line):

		portsCandidate = re.compile("\\bport (\d+)\\b")

		for found in portsCandidate.findall(line):
			self.isThisAPort(found)

	def scanner_mwsa(self, line):
		
		portsCandidate = re.compile("\\bPort: (\d+)\\b")

		for found in portsCandidate.findall(line):
			self.isThisAPort(found)

	def scanner_firewall(self, line):

		portsCandidate = re.compile("\\b(?:service|s_port):\"(\d+)\"")

		for pair in line.split(";"):
			result = portsCandidate.findall(pair)
			if result:
				self.isThisAPort(result[0])

	def isThisAPort(self, digit):
		if len(digit) == 0 or digit[0] == "0" or int(digit) < 1 or int(digit) > 65535:
			return False
		else:
			self.ports.append(digit)
			return True

	def doSomething(self):
		for port in self.ports:
			print(port)

	def key_match(self, line):

		match_sshd = re.compile("(?i:okc\S+\\b) sshd\[\d{1,5}\]: .+$")	 
		match_mwsa = re.compile("(?i:okc\S+\\b) Microsoft.Windows.Security.Auditing\[\d{1,5}\]: .+$")
		match_firewall = re.compile("(?i:okc\S+\\b) FireWall \d{1,5} .+$")	 

		if re.search(match_sshd, line):
			self.scanner_sshd(line)
		if re.search(match_mwsa, line):
			self.scanner_mwsa(line)
		if re.search(match_firewall, line):
			self.scanner_firewall(line)
		

if __name__ == "__main__":

	portScanner = PortScanner()
	
	with open("file", "r") as file:
		lines = file.readlines()
		for line in lines:
			portScanner.key_match(line)

	portScanner.doSomething()
