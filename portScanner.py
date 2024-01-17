#!/bin/env python3

import re
import os
from datetime import datetime as dt

import json
#import mysql.connector

class PortScanner:
	portObjects = {}

	#Match message type. Doing so allows stricter regex on a per message type basis.
	def messageTypeMatch(self, line):
		if len(line.strip()) == 0:
			return

		matchSSHD = re.compile(r"(?i:okc\S+\b) sshd\[\d{1,5}\]: .+$")
		matchMWSA = re.compile(r"(?i:okc\S+\b) Microsoft.Windows.Security.Auditing\[\d{1,5}\]: .+$")
		matchFirewall = re.compile(r"(?i:okc\S+\b) FireWall \d{1,5} .+$")

		if re.search(matchSSHD, line):
			self.scannerSSHD(line)
		elif re.search(matchMWSA, line):
			self.scannerMWSA(line)
		elif re.search(matchFirewall, line):
			self.scannerFirewall(line)
		else:
			print(f"Log message type unidentified: {line}")

	#Per message type regex port extract.

	#SSHD message type id: 1
	def scannerSSHD(self, line):
		id = 1
		candidatePorts = re.compile(r"\bport (\d+)\b")#Per message port match
		candidateTime = re.compile(r"^<.+?>([A-Z][a-z]{2} (3[0-1]|[1-2]\d|[1-9]) \d{1,2}:\d{1,2}:\d{1,2}) ")#time match
		timeStamp = self.getTimeStamp(candidateTime.search(line).group(1), "%b %d %H:%M:%S")

		for found in candidatePorts.findall(line):
			if self.isThisAPort(found):
				self.printOut(id, timeStamp, found)
				self.addPortObject(id, timeStamp, found, line)

	#Microsoft Windows Security Auditing message type id: 2
	def scannerMWSA(self, line):
		id = 2
		candidatePorts = re.compile(r"\bClient Port: (\d+)\b")#Per message port match
		candidateTime = re.compile(r"^<.+?>([A-Z][a-z]{2} (3[0-1]|[1-2]\d|[1-9]) \d{1,2}:\d{1,2}:\d{1,2}) ")#time match
		timeStamp = self.getTimeStamp(candidateTime.search(line).group(1), "%b %d %H:%M:%S")

		for found in candidatePorts.findall(line):
			if self.isThisAPort(found):
				self.printOut(id, timeStamp, found)
				self.addPortObject(id, timeStamp, found, line)

	#Firewall message type id: 3
	def scannerFirewall(self, line):
		id = 3
		candidatePorts = re.compile(r"\b(?:service|s_port):\"(\d+)\"")#Per message port match
		candidateTime = re.compile(r"^<.+?>\d{1,5} (20\d{2}-\d{2}-\d{2})[A-Za-z](\d{1,2}:\d{1,2}:\d{1,2})[A-Za-z]")#time match
		timeStamp = self.getTimeStamp(candidateTime.search(line).group(1) + " "\
			+ candidateTime.search(line).group(2), "%Y-%m-%d %H:%M:%S")

		for found in candidatePorts.findall(line):
			if self.isThisAPort(found):
				self.printOut(id, timeStamp, found)
				self.addPortObject(id, timeStamp, found, line)

	#Extract time stamp
	def getTimeStamp(self, timeStamp, format):
		dtObject = dt.strptime(timeStamp, format)
		return "2020-" + dtObject.strftime("%m-%d %H:%M:%S")

	#Sanity check, avoid odd regex extractions.
	def isThisAPort(self, digit):
		if len(digit) == 0 or digit[0] == "0" or int(digit) < 1 or int(digit) > 65535:
			return False
		else:
			return True

	#Print out the information that has been found.
	def printOut(self, id, date, port):
		print(f"Port: {port}, Message type id: {id}, Time stamp: {date}" )

	#Python dictionary builder.
	def addPortObject(self, id, timeStamp, port, message):
		portObject = {
			"TimeStamp": timeStamp,
			"Port": port,
			"Message": message,
		}
		if id in self.portObjects:
			self.portObjects[id].append(portObject)
		else:
			self.portObjects[id] = []
			self.portObjects[id].append(portObject)

	#Load into a database
	#This is a hypothetical database load. Code is not active, library is not imported and no real database exist.
	def loadDB(self):
		connectorObject = mysql.connector.connect(#This code should not execute, error exist because library import is disabled.
			host="localhost",
			user="admin",
			password="password",
			database="Ports",
			port=3306
		)
		cursor = connectorObject.cursor()
		sql = "INSERT INTO ports (ID, timeStamp, port, message) VALUES (%s, %s, %s, %s);"
		for key in self.portObjects.keys():
			for obj in self.portObjects[key]:
				data = (key, obj['TimeStamp'], obj['Port'], obj['Message'])
				cursor.execute(sql, data)
		connectorObject.commit()
		connectorObject.close()

	#Load into JSON file
	def loadJSON(self):
		with open("ports.json", "w") as jsonFile:
			json.dump(self.portObjects, jsonFile, indent=3)

	#Closing method, db is disabled because no valid db exist, just serving as a hypothetical.
	def load(self):
		#self.loadDB()
		self.loadJSON()
		print("\nA json data dump has been created as ports.json. There is also logic built out for loading into DB, but this is disabled as no valid db exist.")

#Entry:
if __name__ == "__main__":
	portScanner = PortScanner()

	print("Please provide file location(default is 'file' in current working directory):")
	while True:
		path = input()
		if len(path) == 0:
			path = "file"
			break
		if os.path.exists(path.strip()):
			break
		else:
			print("Invalid path, try again(default is 'file' in current working directory):")

	with open(path, "r") as file:
		lines = file.readlines()
		for line in lines:
			portScanner.messageTypeMatch(line)
		portScanner.load()
