Created: July 17, 2017
Modified (V4): June 11, 2018

Purpose: To parse Nessus and Lightning files and save multiple output CSV files to a specified location in the local directory.

Changes within Version 4: 
	1.User may select multiple files or directories. The parser will traverse through all directories to gather all files with a .nessus or .xml 	extension to parse accordingly. 
	2. Updated User Guide. 

Output files include:
	1. importSpreadsheet.csv, which includes the majority of information that is being parsed out of the file.
		a. The Lightning output of this file only includes a host name, vendor, qualified name, mac address, and ip_address. 
	2. host-ports.csv, which includes a list of all hosts, ports, protocols, and services.
		a.The Lightning ouput of this file only includes host and ports. 
	3. connector-ends.csv, list all the sources and target connecting points.
		a. The Lightning output of this file is created by the conversations within the lightning scan.
	4. host-vulnerabilities.csv, lists all the known vulnerabilities (base score and temporal score) on specific hosts.
		a. Not an output of the Lightning Scans.

This is a deployment-ready folder, including:
	Scan Parser: *.jar executable
	Resources folder (parser_resources), which includes:
		vendors.csv: List of Vendors and Qualified Names
		oui.csv: Organization Unique Identifier file (linking MAC Addresses with Vendor names)
		Scan_Parser_User_Guide.pdf: User guide
Import this folder (inclusive of the above files) into any location within the local directory and run the Parser executable. 

Modification History:
Date			Author			Description
18-Jan-2018 		sara.bergman		published version 2.1 
23-Feb-2018		sara.bergman		published version 3.0
16-Mar-2018		sara.bergman		published version 3.1
11-Jun-2018		sara.bergman		published version 4
