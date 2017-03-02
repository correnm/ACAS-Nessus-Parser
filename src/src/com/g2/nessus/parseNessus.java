package src.com.g2.nessus;

/**
 * 
 * @author Corren McCoy, G2 East, Virginia Beach, VA
 * Advantage of SAX parser in Java:
 * It is faster than DOM parser because it will not load the XML document into memory.
 * It's an event based handler.
 *
 * Dependencies:
 * http://opencsv.sourceforge.net/				-- simple csv parser library for Java
 * https://sourceforge.net/projects/opencsv/	-- opencsv-3.8.jar
 * 
 * Interface:
 * https://macvendors.com/			-- no registration or API key is required for up to 10,000 requests per day.
 * https://macvendors.co/api		-- API is free and without limits
 * https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
 * 
 * Coding References:
 * http://javarevisited.blogspot.com/2011/12/parse-read-xml-file-java-sax-parser.html
 * https://www.tutorialspoint.com/java_xml/java_sax_parse_document.htm
 * http://www.journaldev.com/1198/java-sax-parser-example
 * https://rosettacode.org/wiki/MAC_Vendor_Lookup
 * https://sourceforge.net/projects/opencsv/?source=typ_redirect
 * 
 * Modification History:
 * 1
 * 
 */


import java.util.ArrayList;
import java.util.Arrays;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.HashMap;
import java.net.HttpURLConnection;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.net.URL;
import java.util.Scanner;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.opencsv.*;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
import org.w3c.dom.NodeList;

public class parseNessus  extends DefaultHandler {
	// class variables
	public static File importDirectory = new File(".\\import\\nessus-scans\\SUBCOMM");
	public static File exportDirectory = new File(".\\export");
	public static File parserDirectory = new File(".\\import\\parser-data");
	public static String magicDrawImportSpreadsheet = ".\\export\\importSpreadsheet.csv";
	public static String site = "SUBCOMM";
	public static final String NESSUS_VERSION = "NessusClientData_v2";  // this version must be in the header tag
	public static final String VENDOR_FILE    = "vendors.csv";          // table export from MagicDraw

    public static HashMap<String, String> map = new HashMap<String, String>();
	public static String defaultVendorFile = ".\\import\\parser-data\\vendors.csv";
	public static Scanner scanner = null;
	public static boolean loadStatus = false;

	/** Base URL for API. The API from www.macvendors.com was chosen. */
	private static final String baseURL = "http://api.macvendors.com/";	
	
	// holds the data retrieved from the XML file for each host
	private static ArrayList<ReportHost> hostList  = new ArrayList<ReportHost>();
	private String temp;
	private String tagName;
	private static ReportHost host;

	// indicator for attributes in <tag name=____ >
	Boolean bHost_end 			= false;
	Boolean bMacAddress 		= false;
	Boolean bHostIp 			= false;
	Boolean bOs 				= false;
	Boolean bOperatingSystem	= false;
	Boolean bSystemType			= false;
	Boolean bHostFqdn			= false;
	Boolean bInstalledSoftware	= false;
	Boolean bTraceRouteHops		= false;
	Boolean bCvssBaseScore		= false;
	Boolean bCvssTemporalScore	= false;
	
	public String getSite(){
		return site;
	}
	
	public String getVersion(){
		return NESSUS_VERSION;
	}

	public static boolean vendorMap() throws Exception {

    	// Open the file for reading. Throw an exception if not found.
    	scanner = new Scanner(new FileReader(defaultVendorFile));		    	
	    	
    	while (scanner.hasNextLine()) {
    		// comma separator is expected delimiter
    		//2	3Com	Communications Profile::Vendor Hardware & Software::Vendor Folder::3Com
    		String[] columns = scanner.nextLine().split(",");
    		// column 1 = Vendor name, column 2 = MagicDraw Qualified Name
    		map.put(columns[1], columns[2]);
    	} // end while
    	
    	// DEBUGGING: display the loaded data
	    Iterator<Map.Entry<String, String>> i = map.entrySet().iterator();
    	while (i.hasNext()) {
    		String key = i.next().getKey();
    		//System.out.println(key);
    	} // end DEBUGGING
    	
    	// close all open resources to avoid compiler warning
	    if (scanner != null)
	    	scanner.close();
	    
	    // Got here without an exception. All good.
	    loadStatus = true;
	    return loadStatus;
	} // end vendorMap
	
	public static void startParser(File importDirectory) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		Scanner keyboard = new Scanner(System.in);
		
		try {
			// read all the files in the import directory into an array
			File[] listOfFiles = importDirectory.listFiles();
		
			for (int f = 0; f < listOfFiles.length; f++) {
				// Debugging: any files in this directory
				if (listOfFiles[f].isFile()) {
					System.out.println("File " + listOfFiles[f].getName());				
				} else if (listOfFiles[f].isDirectory()) {
					System.out.println("Directory " + listOfFiles[f].getName());
				}
				//The File.getAbsolutePath() will give you the full complete path name (filepath + filename) of a file
				File scanFile = new File(listOfFiles[f].getAbsolutePath());
	
				// Read: http://javarevisited.blogspot.com/2011/12/parse-read-xml-file-java-sax-parser.html
	            //Create a "parser factory" for creating SAX parsers
	            SAXParserFactory spfac = SAXParserFactory.newInstance();
	
	            //Now use the parser factory to create a SAXParser object
	            SAXParser sp = spfac.newSAXParser();
	
	            //Create an instance of this class; it defines all the handler methods
	            parseNessus handler = new parseNessus();
	
	            //Finally, tell the parser to parse the input and notify the handler
	            sp.parse(scanFile, handler);
	            
	            //@DEBUG: display output on the console
	            handler.readList();
	            writeMagicDrawCsvFile(magicDrawImportSpreadsheet);
			} // end for (list all files in directory)
		
		} catch (Exception e) {
			e.printStackTrace();
		} 
    	// close all open resources to avoid compiler warning
	    if (keyboard != null)
	    	keyboard.close();
	} // end startParser

    /*
     * When the parser encounters plain text (not XML elements),
     * it calls this method which accumulates them in a string buffer
     */
    public void characters(char[] buffer, int start, int length) {
    	// remove leading and trailing whitespace
    	temp = new String(buffer, start, length).trim();
    	
        if(temp.length() == 0) return; // ignore white space
    }

    /*
     * Every time the parser encounters the beginning of a new element,
     * it calls this method, which resets the string buffer
     */ 
    public void startElement(String uri, String localName,
                  String qName, Attributes attributes) throws SAXException {
    	
           temp = "";
           if (qName.equalsIgnoreCase("ReportHost")) {
        	   host = new ReportHost();
               host.setHost(attributes.getValue("name"));
           } else if (qName.equalsIgnoreCase("tag")) {
        	   // save the name of the attribute name=____ so we determine which value to update
        	   tagName = attributes.getValue("name").toLowerCase();        	   
        	   
        	   switch (tagName)
        	   {
        	   case "host_end": 			bHost_end = true; 			break;
        	   case "mac-address": 			bMacAddress = true; 		break;
        	   case "host-ip":				bHostIp = true; 			break;
        	   case "os":					bOs = true; 				break;
        	   case "operating-system":		bOperatingSystem = true; 	break;
        	   case "system-type":			bSystemType = true;			break;
        	   case "host-fqdn":			bHostFqdn = true;			break;
        	   }
        	   
        	   if (tagName.contains("cpe-")) {
        		   bInstalledSoftware = true;
        	   } else if (tagName.contains("traceroute-hop")) {
        		   bTraceRouteHops = true;
        	   }
        	   //System.out.println(tagName);
           } else if (qName.equalsIgnoreCase("cvss_base_score")) {
        	   bCvssBaseScore = true;
           } else if (qName.equalsIgnoreCase("cvss_temporal_score")) {
        	   bCvssTemporalScore = true;
           }
    } // end StartElement

    /*
     * When the parser encounters the end of an element, it calls this method
     */
    public void endElement(String uri, String localName, String qName)
                  throws SAXException {

           if (qName.equalsIgnoreCase("ReportHost")) {
        	   // add new host to the list
               hostList.add(host);
           } else if (bHost_end) { 
               host.setScanDate(temp);
               bHost_end = false;
           } else if (bMacAddress) {
        	   host.setMacAddress(temp);
        	   // MacAddress can be 1:M in the Nessus file separated by newline.
        	   // All will be for the same vendor so just use the first one in the list
        	   String[] macList = temp.split("\n");
        	   host.setVendor(lookupVendor(macList[0]));
        	   bMacAddress = false;
           } else if (bHostIp) {
        	   host.setIpAddress(temp);
        	   bHostIp = false;
           } else if (bOs) {
        	   host.setOs(temp);
        	   bOs = false;
           } else if (bOperatingSystem) {
        	   host.setOperatingSystem(temp);
        	   bOperatingSystem = false;
           } else if (bSystemType) {
        	   host.setSystemType(temp);
        	   bSystemType = false;
           } else if (bHostFqdn) {
        	   host.setFqdn(temp);
        	   bHostFqdn = false;
           } else if (bInstalledSoftware) {
        	   host.setInstalledSoftware(temp);
        	   bInstalledSoftware = false;
           } else if (bTraceRouteHops) {
        	   host.setTraceRouteHops(temp);
        	   bTraceRouteHops = false;
           } else if (bCvssBaseScore) {
        	   host.setCVSSBaseScore(temp);
        	   bCvssBaseScore = false;
           } else if (bCvssTemporalScore) {
        	   host.setCVSSTemporalScore(temp);
        	   bCvssTemporalScore = false;
           }
    }
    
    /*
     *  Displays parsed output on the console
     */
    public void readList() {
        System.out.println("Number of hosts '" + hostList.size()  + "'.");
        Iterator<ReportHost> it = hostList.iterator();
        while (it.hasNext()) {
        	System.out.println(it.next().toString());
            // just the host name
            //System.out.println(it.next().getHost());
        }
    }

   
   	public static void writeMagicDrawCsvFile(String fileName) {
        	//Delimiter used in CSV file
        	final String COMMA_DELIMITER = ",";
        	final String NEW_LINE_SEPARATOR = "\n";
        	
        	//CSV file header
        	final String[] FILE_HEADER = "host,vendor,macAddress,IP-Address,O/S,operatingSystem,systemType,FQDN,scanDate,installedSoftware,traceRouteHops, CVSSBaseScore, CVSSTemporalScore".split(",");
    		
    		FileWriter fileWriter = null;
    		CSVWriter writer = null;		
    		try {
    			fileWriter = new FileWriter(fileName);
    			writer = new CSVWriter(fileWriter, ',', '"');
    			//Write the CSV file header
    			//fileWriter.append(FILE_HEADER.toString());
    			//fileWriter.append(NEW_LINE_SEPARATOR);
    			
    			writer.writeNext(FILE_HEADER);
    			
    			//Write a new report object list to the CSV file
    	        Iterator<ReportHost> it = hostList.iterator();
    	        ReportHost curHost = new ReportHost();
    	        while (it.hasNext()) {
    	        	curHost = it.next();
    	        	String[] entries = curHost.toString().split("#");
    	        	writer.writeNext(entries);
    	        	/*
    	        	fileWriter.append(String.valueOf(curHost.getHost()));
    				fileWriter.append(COMMA_DELIMITER);
    				fileWriter.append(String.valueOf(curHost.getVendor()));
    				fileWriter.append(COMMA_DELIMITER);
    				fileWriter.append(String.valueOf(curHost.getMacAddress()));
    				fileWriter.append(COMMA_DELIMITER);
    				fileWriter.append(String.valueOf(curHost.getIpAddress()));
    				fileWriter.append(COMMA_DELIMITER);
    				fileWriter.append(String.valueOf(curHost.getOs()));
    				fileWriter.append(COMMA_DELIMITER);
    				fileWriter.append(String.valueOf(curHost.getOperatingSystem()));
    				fileWriter.append(COMMA_DELIMITER);
    				fileWriter.append(String.valueOf(curHost.getSystemType()));
    				fileWriter.append(COMMA_DELIMITER);
    				fileWriter.append(String.valueOf(curHost.getFqdn()));
    				fileWriter.append(COMMA_DELIMITER);
    				fileWriter.append(String.valueOf(curHost.getScanDate()));  
    				
    				// end of line
    				fileWriter.append(NEW_LINE_SEPARATOR);
    				*/
    			}
    			System.out.println("CSV file was created successfully.");
  			
    		} catch (Exception e) {
    			System.out.println("Error in writeMagicDrawCSVFile.");
    			e.printStackTrace();
    		} finally {
    			
    			try {
    				writer.flush();
    				writer.close();
    			} catch (IOException e) {
    				System.out.println("Error while flushing/closing fileWriter");
                    e.printStackTrace();
    			}
    			
    		} // end of try-catch
    	} // end method writeMagicDrawCSVFile
 
	/** Performs lookup on supplied MAC address.
	 * @param macAddress MAC address to lookup.
	 * @return Manufacturer of MAC address. */
	private static String lookupVendor(String macAddress) {
		try {
			StringBuilder result = new StringBuilder();
			URL url = new URL(baseURL + macAddress);
			System.out.println(url);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;
			while ((line = rd.readLine()) != null) {
				result.append(line);
			}
			rd.close();
			System.out.println(result);
			return result.toString();
		} catch (FileNotFoundException e) {
			// MAC not found
			return "N/A";
		} catch (IOException e) {
			// Error during lookup, either network or API.
			return null;
		}
	}
	
    //**************************************************************************************
	public static void main(String[] args) throws IOException, SAXException,
    ParserConfigurationException, Exception {
		boolean loadStatus;
		
		String statusMessage = null;
		
		try {
			loadStatus = vendorMap();
			if (loadStatus)
				statusMessage = "Vendor file loaded successfully.";
				startParser(importDirectory);
				statusMessage = "Parser completed successfully.";
	    } 
	    catch (FileNotFoundException e) {
	    	statusMessage = e.getMessage();
	    } 
	    catch (java.io.IOException e) {
	    	statusMessage = e.getMessage();
	    }
		finally {
			System.out.println("********* Parser Status **********");
			System.out.println(statusMessage);
		}
	} // end main
	
} // end parseNessus
