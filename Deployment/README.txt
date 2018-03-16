Primary Developer: Sara Bergman
Contributers: Corren McCoy, Jennifer Gregorio
Created: July 17, 2017
Modified (V3.1): Feb 23, 2018

Purpose: To parse nessus and lightning files and save multiple output CSV files to a specified location in the local directory.

Changes within Version 3: 
	1.Has the option to parse Raytheon Lightning Scans that creates 3 output files. 
	2.Created an additional output csv file for parsing nessus files that displays the host, base score, and temporal score of each of its vulnerabilities.
	3.Ability for the user to input the specific site for MBSE import.
	4.Additional installed_software cpe element columns in the importSpreadsheet output. 
Version 3.1 correctly parses the connector_ends output of the nessus file. 

Output files include:
	1. importSpreadsheet.csv, which includes the majority of information that is being parsed out of the file.
		1. The Lightning output of this file only includes a host name, vendor, qualified name, mac address, and ip_address. 
	2. host-ports.csv, which includes a list of all hosts, ports, protocols, and services.
		2a.The Lightning ouput of this file only includes host and ports. 
	3. connector-ends.csv, list all the sources and target connecting points.
		3a. The Lightning output of this file is created by the conversations within the lightning scan.
	4. host-vulnerabilities.csv, lists all the known vulnerabilities (base score and temporal score) on specific hosts.
		4a. Not an output of the Lightning Scans.

This is a deployment-ready folder, including:
	Scan Parser: *.jar executable
	Resources folder (parser_resources), which includes:
		vendors.csv: List of Vendors and Qualified Names
		oui.csv: Organization Unique Identifier file (linking MAC Addresses with Vendor names)
		ACAS_Nessus_Parser_User_Guide.pdf: User guide
Import this folder (inclusive of the above files) into any location within the local directory and run the Parser executable. 

Modification History:
Date			Author			Description
18-Jan-2018 		sara.bergman		published version 2.1 
23-Feb-2018		sara.bergman		published version 3.0
16-Mar-2018		sara.bergman		published version 3.1
