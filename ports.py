#!/bin/env python3

import re

regexMatch = "[pP]orts?[ :\"]{1,3}([1-5]\d{4}|6[0-5]\d{3}|[1-9]{1,3})"
matcher = re.compile(regexMatch)

with open("file", "r") as file:
	lines = file.readlines()
	for line in lines:
		try:
			print(matcher.findall(line)[0])
		except IndexError:
			continue
