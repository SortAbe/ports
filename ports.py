#!/bin/env python3

import re

regexMatch = "(?:[pP]orts?|[sS]ervices?)[ :\"]{1,3}([1-5]\d{4}|6[0-5]\d{3}|[1-9]\d{1,3})\\b"
matcher = re.compile(regexMatch)

with open("file", "r") as file:
	lines = file.readlines()
	for line in lines:
		result = matcher.findall(line)
		if result:
			for i in result:
				print(i)
