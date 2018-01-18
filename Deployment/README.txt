Primary Developer: Sara Bergman
Contributers: Corren McCoy, Jennifer Gregorio
Created: July 17, 2017
Modified (V2.1): Jan 18, 2018

Purpose: To parse nessus files and save 3 output CSV files to a specified location in the local directory
Changes within Version 2: Enhanced the csv output files. Enabled updates to the Cassandra Database 

This is a deployment-ready folder, including:
	NessusParser: *.jar executable
	Resources folder (parser_resources), which includes:
		List of Vendors and Qualified Names: vendors.csv
		Organization Unique Identifier file (linking MAC Addresses with Vendor names): oui.csv
		User guide: ACAS_Nessus_Parser_User_Guide.pdf

Import this folder (inclusive of the above files) into any location within the local directory and run the Parser executable. 

Modification History:
Date			Author			Description
18-Jan-2018 		sara.bergman		published version 2.1 