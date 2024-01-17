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
		matchSSHD = re.compile(r"(?i:okc\S+\b) sshd\[\d{1,5}\]: .+$")
		matchMWSA = re.compile(r"(?i:okc\S+\b) Microsoft.Windows.Security.Auditing\[\d{1,5}\]: .+$")
		matchFirewall = re.compile(r"(?i:okc\S+\b) FireWall \d{1,5} .+$")

		if re.search(matchSSHD, line):
			self.scannerSSHD(line)
		if re.search(matchMWSA, line):
			self.scannerMWSA(line)
		if re.search(matchFirewall, line):
			self.scannerFirewall(line)

	#Per message type regex port extract.

	#SSHD message type id: 1
	def scannerSSHD(self, line):
		candidatePorts = re.compile(r"\bport (\d+)\b")
		candidateDate = re.compile(r"^<.+?>([A-Z][a-z]{2} (3[0-1]|[1-2]\d|[1-9]) \d{1,2}:\d{1,2}:\d{1,2}) ")
		timeStamp = self.getTimeStamp(candidateDate.search(line).group(1), "%b %d %H:%M:%S")

		for found in candidatePorts.findall(line):
			if self.isThisAPort(found):
				self.printOut(1, timeStamp, found)
				self.addPortObject(1, timeStamp, found, line)

	#Microsoft Windows Security Auditing message type id: 2
	def scannerMWSA(self, line):
		candidatePorts = re.compile(r"\bPort: (\d+)\b")
		candidateDate = re.compile(r"^<.+?>([A-Z][a-z]{2} (3[0-1]|[1-2]\d|[1-9]) \d{1,2}:\d{1,2}:\d{1,2}) ")
		timeStamp = self.getTimeStamp(candidateDate.search(line).group(1), "%b %d %H:%M:%S")

		for found in candidatePorts.findall(line):
			if self.isThisAPort(found):
				self.printOut(2, timeStamp, found)
				self.addPortObject(2, timeStamp, found, line)

	#Firewall message type id: 3
	def scannerFirewall(self, line):
		candidatePorts = re.compile(r"\b(?:service|s_port):\"(\d+)\"")
		candidateDate = re.compile(r"^<.+?>\d{1,5} (20\d{2}-\d{2}-\d{2})[A-Za-z](\d{1,2}:\d{1,2}:\d{1,2})[A-Za-z]")
		timeStamp = self.getTimeStamp(candidateDate.search(line).group(1) + " "\
			+ candidateDate.search(line).group(2), "%Y-%m-%d %H:%M:%S")

		for found in candidatePorts.findall(line):
			if self.isThisAPort(found):
				self.printOut(3, timeStamp, found)
				self.addPortObject(3, timeStamp, found, line)

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
	def loadDB(self):
		connectorObject = mysql.connector.connect(
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

	while True:
		print("Please provide file location(default is 'file' in current working directory):")
		path = input()
		if len(path) == 0:
			path = r"file"
		if os.path.exists(path):
			break
		else:
			print("Invalid path, try again(default is 'file' in current working directory):")
			path = input()

	with open(path, "r") as file:
		lines = file.readlines()
		for line in lines:
			portScanner.messageTypeMatch(line)
		portScanner.load()
