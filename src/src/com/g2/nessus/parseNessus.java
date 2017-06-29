 //parseNessus_has no tracehops showing
 package src.com.g2.nessus;

import java.awt.Component;
import java.io.BufferedReader;
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
 * -- no registration or API key is required for up to 10,000 requests per day.
 * https://macvendors.com/
 * -- API is free and without limits
 * https://macvendors.co/api		
 * -- File download directly from IEEE. Will need to be refreshed periodically to get latest entries on the oui.csv
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
 * 01/06/217		cmccoy	Created this package
 * 02/01/2017		cmccoy	No internet connection in the lab.
 * 							Changed mac address api calls to use an OUI file lookup to find the vendor. 
 * 
 */
 import java.io.File;
 import java.io.FileNotFoundException;
 import java.io.FileReader;
 import java.io.FileWriter;
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.InputStreamReader;
 import java.io.StringWriter;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JOptionPane;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.codec.language.Soundex;
import org.apache.commons.io.*;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.opencsv.CSVWriter;




public class parseNessus  extends DefaultHandler {
	// class variables
	public static String site = "SUBCOMM";
	public static final String NESSUS_VERSION = "NessusClientData_v2";  // this version must be in the header tag
	public static final String VENDOR_FILE    = "vendors.csv";          // table export from MagicDraw


	//loaded with vendors and Qualified Names from the vendors.csv
	public static HashMap<String, String> magicDrawVendors = new HashMap<String, String>();
	//resource file used for vendor references
	public static String defaultVendorFile = "vendors.csv";
	public static Scanner scanner = null;
	public static boolean loadStatus = false;

	/** Base URL for API. The API from www.macvendors.com was chosen. */
	private static final String baseURL = "http://api.macvendors.com/";	
	//will replace the above lookup vendor location
	public static String defaultMacFile = "oui.csv"; 
	//loaded with Mac Address and Organization names from oui.csv
	private static HashMap<String, String> ouiMacLookUp = new HashMap<String,String>();//sara
	
	// holds the data retrieved from the XML file for each host
	private static ArrayList<ReportHost> hostList  = new ArrayList<ReportHost>();
	//holds entries to be written on the connector-ends.csv
	private static ArrayList<String> connectorEndsList = new ArrayList<String>();
	//maps the host with its trace-route hops
	static Map <String, List<String>> hostTraceRmap = new HashMap<String, List<String>>();
	
	//Associates each host name (name or IP) with a unique host name that is not an IP. 
	private static HashMap<String, String> uniqueHostName = new HashMap<String,String>();//sara
	//sets a pattern for detecting word names appart from IP's
	private static final String IPADDRESS_PATTERN = 
	"^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." + 
	"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." + 
	"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." + 
	"([01]?\\d\\d?|2[0-4]\\d|25[0-5])$"; 
	//declaring "i" which keeps track of the unique names
	static int i;
		
	private String temp;
	private String tagName;
	private static ReportHost host;
	
	//indicator for writing .csv files 
	private static Boolean importSpreadSheet = false;
	private static Boolean connectorEnds = false;
	private static Boolean hostPorts = false;

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
	Boolean bPort				= false;
	Boolean bProtocol			= false;
	Boolean bSrvName			= false;
	
	
	public String getSite(){
		return site;
	}
	
	public String getVersion(){
		return NESSUS_VERSION;
	}
	
	public static boolean vendorMap() throws Exception {
		//trying to help match the web vendor to the vendor in the .csv
		Soundex soundex = new Soundex();//sara
    	// Open the file for reading. Throw an exception if not found.
		String vendorFile;

		try{
			
//			File file;
//			file = new File(getClass().getResource("/vendor.csv").toURI());
//			BufferedReader reader = new BufferedReader(new FileReader(file));
//			vendorFile = file.getAbsolutePath();
			
			
			File vendors = new File(parseNessus.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
			String path = vendors.getAbsolutePath();
			String file = vendors.getName();
			System.out.println("File: " + file);
			 vendorFile = path.replace(file, "") + defaultVendorFile ;
			System.out.println("vendorFile: " + vendorFile);
				
			scanner = new Scanner(new FileReader(vendorFile));
		
		
		
			while (scanner.hasNextLine()) {
				// comma separator is expected delimiter
				//2	3Com	Communications Profile::Vendor Hardware & Software::Vendor Folder::3Com
				String[] columns = scanner.nextLine().split(",");
    		
				System.out.println("soundex from VENDOR MAP: " + soundex.soundex(columns[1]));
				// column 1 = Vendor name, column 2 = MagicDraw Qualified Name
				magicDrawVendors.put(soundex.soundex(columns[1]), columns[2]);//sara mod
				//Debug to see if we are getting the right vendors with the right qualified name
				//magicDrawVendors.forEach((vendor, qualifiedName)-> System.out.println(vendor + "NAME: " + qualifiedName));
    		
			} // end while
    	
			// close all open resources to avoid compiler warning
			if (scanner != null)
				scanner.close();
	    
			// Got here without an exception. All good.
			loadStatus = true;
	    
		}catch (FileNotFoundException e){
			//Warns user that the vendors.csv could not be found
			JOptionPane fileNotFound = new JOptionPane();
			JOptionPane.showMessageDialog(fileNotFound,
				    "Parser could not find vendors.csv. \n Please upload vendors.csv to the same file location as this NessusParser executable.",
				    "CANNOT FIND VENDORS.CSV",
				    JOptionPane.WARNING_MESSAGE);
		}
	    
	    return loadStatus;
	} // end vendorMap
	
	
	public static void startParser(File[] inputFiles) throws IOException, ParserConfigurationException,
	org.xml.sax.SAXException {
		Scanner keyboard = new Scanner(System.in);
		 String statusMessage = null;
		 i=0; //initializing i to 0 for assigning unique names to the hosts in uniqueHostNames
		
		try {
			// read all the files in the import directory into an array
			//File[] listOfFiles = importDirectory.listFiles();
				loadStatus = vendorMap();
				if (loadStatus)
					statusMessage = "Vendor file loaded successfully.";
					//displayVendors();
					//displayHostNames(); sara - the list is empty at this point
					statusMessage = "Parser completed successfully.";
	
					File[] listOfFiles = inputFiles;
		
			for (int f = 0; f < listOfFiles.length; f++) {
				// Debugging: any files in this directory
				if (listOfFiles[f].isFile()) {
					System.out.println("File " + listOfFiles[f].getName());				
				} else if (listOfFiles[f].isDirectory()) {
					System.out.println("Directory " + listOfFiles[f].getName());
				}
				//The File.getAbsolutePath() will give you the full complete path name (filepath + saveTo) of a file
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
	            //handler.readList();
	            handler.addtoHostTraceRmap();
	            //writeMagicDrawCsvFile(magicDrawImportSpreadsheet);
			} // end for (list all files in directory)
		
		} catch (Exception e) {
			e.printStackTrace();
		} 
		finally {
			System.out.println("********* Parser Status **********");
			System.out.println(statusMessage);
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
    	//System.out.println("qName: " + qName); -- wanted to see what the options for qName were
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
           }else if (qName.equalsIgnoreCase("ReportItem")){ //sara
        	   host.setSrvProPort(attributes.getValue("port"),attributes.getValue("protocol"),attributes.getValue("svc_name" ));
        	   bPort = true;
        	   bProtocol = true;}

    } // end StartElement

   
    /*
     * When the parser encounters the end of an element, it calls this method
     */
    public void endElement(String uri, String localName, String qName)
                  throws SAXException {

           if (qName.equalsIgnoreCase("ReportHost")) {
        	   // add new host to the list
               hostList.add(host);
               setUniqueHostNamewHost(host);//sara
           } else if (bHost_end) { 
               host.setScanDate(temp);
               bHost_end = false;
           } else if (bMacAddress) {
        	   host.setMacAddress(temp);
        	   // MacAddress can be 1:M in the Nessus file separated by newline.
        	   // All will be for the same vendor so just use the first one in the list
        	   String[] macList = temp.split("\n");
        	   // use the IEEE lookup
        	   String vendor;
			try {
				vendor = lookupVendor(macList[0]).replaceAll("^\"|\"$", "");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				vendor = "N/A";
			}catch(NullPointerException e){
				vendor = "N/A";
			}
        	   host.setVendor(vendor);
        	   //System.out.println("Vendor: " + vendor);
        	   host.setQualifiedName(lookupMagicDrawVendor(vendor));
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
    
    public static String getUniqueHostName(String iP){
    	   String ip= iP.trim();
    	    	Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
    		Matcher matcher = pattern.matcher(ip);
    		String name;
    		if (uniqueHostName.keySet().contains(ip)){
    			name = uniqueHostName.get(ip);
    			//System.out.println("already has a name: " + ip );
    	    }else{
    	    	if (matcher.matches()){ //sHost is an ip address
    				uniqueHostName.put(ip, "EndPoint_"+i );
    				i++;
    				//System.out.println("New ip: " + ip );
    			}else{
    				uniqueHostName.put(ip, ip);
    				//System.out.println("Not an ip: " + ip );
    			}
    	    }
    		name = uniqueHostName.get(ip);
    		//System.out.println("ip: " + ip + " " + name);
    		return name;
    	    }
    	    
    	    
    	    
    	    public void setUniqueHostNamewHost(ReportHost host){
    	    	String sHost = host.getHost();
    	    	
    	    	Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
    	    	Matcher matcher = pattern.matcher(sHost);
    	    	
    	    	if (matcher.matches()){ //sHost is an ip address
    	    		uniqueHostName.put(sHost.trim(), "EndPoint_"+i );
    	    		i++;
    	    	}else{
    	    	  uniqueHostName.put(sHost.trim(), sHost.trim());
    	    	}  
    	    }

    	    
    	    public static void addtoHostTraceRmap(){
    	    	
    	    	 Iterator<ReportHost> it = hostList.iterator();
    	         ReportHost curHost = new ReportHost();
    	         while (it.hasNext()) {
    	         	curHost = it.next();
    	         	String routeHops = curHost.getTraceRouteHops();
    	         	//String ports = curHost.getPort();
    	         	String host = curHost.getHost();
    	         	String[] routeArray = routeHops.split("->");
    	         	List<String> routeList = Arrays.asList(routeArray);
    	         	List<String> withNames = new ArrayList<String>();
    	         	//hostPorts.put(host, ports);
    	         	hostTraceRmap.put(host, routeList);
    	     	int i = 0;
    	     	}
    	 
    			
    	       //readList();
    	       addtoConnectorEndsList(); 
    	    }
    	    
 
    //creates a list to populate the connector-ends spreadsheet
    public static void addtoConnectorEndsList(){
    	List<String> values;
    	String source = new String();
    	String target;
    	String targetN;
    	String sourceN;
    	String blockName;
    	String sourceName;
    	String targetName;
    	String owner = "Site";
    	String diagram = "Site::Diagram";
    	String delimiter = "#";
    	
    	boolean first = true;
    	System.out.println("Size of hostTraceRmap " + hostTraceRmap.keySet().size());
    	
    	for (String key : hostTraceRmap.keySet()){
    		first = true;
   		 	values = hostTraceRmap.get(key);
   		 
   		 	//System.out.println("==New Host==");
   		 	Iterator<String> it = values.iterator();
   		 	while (it.hasNext()){
   		 		if (first) {
   		 			source = it.next().trim();
   		 			first = false;
   		 		}else{
   		 			target = it.next().trim();
   		 			
   		 		StringBuffer connectorInfo = new StringBuffer();	
   		 		
   		 		blockName = getUniqueHostName(source);
   	        	sourceName = "Site::"+blockName;
   	        	
   	        	targetName = "Site::"+ getUniqueHostName(target);
   		 			
   	        	connectorInfo.append(source);
        		connectorInfo.append(delimiter);
    			connectorInfo.append(sourceName);
    			connectorInfo.append(delimiter);
    			connectorInfo.append(blockName);
    			connectorInfo.append(delimiter);
    			connectorInfo.append(target);
    			connectorInfo.append(delimiter);
    			connectorInfo.append(targetName);
    			connectorInfo.append(delimiter);
    			connectorInfo.append(owner);
    			connectorInfo.append(delimiter);
    			connectorInfo.append(diagram);
    			
    			connectorEndsList.add(connectorInfo.toString());

   		 			source = target;
   		 		}
   		 	}
    	}
    
    }
    
    /*
     *  Displays parsed output on the console
     */
    public static void readList() {

        	 System.out.println("========== HostTraceRoute List ==========");
             List<String> values = new ArrayList<String>();
            // String key;
         	Iterator<String> it =hostTraceRmap.keySet().iterator();
             for (String key: hostTraceRmap.keySet()){
             	//System.out.println("Key: " +key);
             	values = hostTraceRmap.get(key);
             System.out.println("Key: " +key);
             	for (String value: values){
             		
             	System.out.println("                 "  + " Value: " + value);
             	}
        	
        }

    }
    
    public static void writeConnectorEndsCsvFile(String saveTo) throws FileNotFoundException {
    	//Delimiter used in CSV file
    	final String COMMA_DELIMITER = ",";
    	final String NEW_LINE_SEPARATOR = "\n";
    	
    	//CSV file header
    	final String[] FILE_HEADER = "Source,SourceName,BlockName,Target,TargetName,Owner,Diagram".split(",");
		
		FileWriter fileWriter = null;
		CSVWriter writer = null;		
		try {
			fileWriter = new FileWriter(saveTo);
			writer = new CSVWriter(fileWriter, ',', '"');
			
			writer.writeNext(FILE_HEADER);
			
			//Write a new report object list to the CSV file
	        Iterator<String> it = connectorEndsList.iterator();
	        String curConnection = new String();
	        while (it.hasNext()) {
	        	curConnection = it.next();
	        	String[] entries = curConnection.split("#");
	        	writer.writeNext(entries);
	        	
			}
			connectorEnds = true;
	        System.out.println("connectorEndsCSV file was created successfully.");
		}catch (FileNotFoundException e){
			showWarning(saveTo);
		} catch (Exception e) {
			System.out.println("Error in connectorEndsCSVFile.");
			e.printStackTrace();
		} finally {
			
			try {
				writer.flush();
				writer.close();
			} catch (IOException e) {
				System.out.println("Error while flushing/closing fileWriter");
                e.printStackTrace();
			}catch (NullPointerException e){
				 e.printStackTrace();
			}
			 System.out.println("Save as file: " + saveTo);
			
		} // end of try-catch
	} // end method writeMagicDrawCSVFile
    
    public static void writeMagicDrawHostPorts(String saveTo) throws FileNotFoundException {
    	//Delimiter used in CSV file
    	final String COMMA_DELIMITER = ",";
    	final String NEW_LINE_SEPARATOR = "\n";
    	String portsEntry = new String();
    	
    	//CSV file header
    	final String[] FILE_HEADER = "host,ports,serviceName,protocol".split(",");
		
		FileWriter fileWriter = null;
		CSVWriter writer = null;		
		try {
			fileWriter = new FileWriter(saveTo);
			writer = new CSVWriter(fileWriter, ',', '"');
			writer.writeNext(FILE_HEADER);
			
			//Write a new report object list to the CSV file
			Iterator<ReportHost> it = hostList.iterator();
	         ReportHost curHost = new ReportHost();
	         while (it.hasNext()) {
	        	 curHost = it.next();
	        	List<String> hostPorts = curHost.getSrvProPort();
	        	Iterator<String> its = hostPorts.iterator();
	        	while(its.hasNext()){
	        		String row = its.next();
	        		System.out.println("ROW: " + row);
	        		String[] rowEntry = row.split("#");
	        		writer.writeNext(rowEntry);
	        	}
	        			
	        
			}
			hostPorts = true;
	         System.out.println("ports CSV file was created successfully.");
		}catch (FileNotFoundException e){
			showWarning(saveTo);
		} catch (Exception e) {
			System.out.println("Error in writeportsCSVFile.");
			e.printStackTrace();
		} finally {
			
			try {
				writer.flush();
				writer.close();
			} catch (IOException e) {
				System.out.println("Error while flushing/closing fileWriter");
                e.printStackTrace();
			}catch (NullPointerException e){
				e.printStackTrace();
			}
			 System.out.println("Save as file: " + saveTo);
			
		} // end of try-catch
	} // end method writeMagicDrawCSVFile
    
    public static void writeMagicDrawCsvFile(String saveTo) throws FileNotFoundException {
        	//Delimiter used in CSV file
        	final String COMMA_DELIMITER = ",";
        	final String NEW_LINE_SEPARATOR = "\n";
        	
        	//CSV file header
        	final String[] FILE_HEADER = "host,vendor,macAddress,qualifiedName,IP-Address,O/S,operatingSystem,systemType,FQDN,scanDate,installedSoftware,traceRouteHops,CVSSBaseScore,CVSSTemporalScore".split(",");
    		
    		FileWriter fileWriter = null;
    		CSVWriter writer = null;		
    		try {
    			fileWriter = new FileWriter(saveTo);
    		
    			writer = new CSVWriter(fileWriter, ',', '"');
    			writer.writeNext(FILE_HEADER);
    			
    			//Write a new report object list to the CSV file
    	        Iterator<ReportHost> it = hostList.iterator();
    	        ReportHost curHost = new ReportHost();
    	        while (it.hasNext()) {
    	        	curHost = it.next();
    	        	String[] entries = curHost.toString().split("#");
    	        	writer.writeNext(entries);
    	        
    			}
    	        importSpreadSheet = true;
    	        System.out.println("CSV file was created successfully.");
    		}catch (FileNotFoundException e){
    			showWarning(saveTo);
    		} catch (Exception e) {
    			System.out.println("Error in writeMagicDrawCSVFile.");
    			e.printStackTrace();
    		}finally {
    			
    			try {
    				writer.flush();
    				writer.close();
    			} catch (IOException e) {
    				System.out.println("Error while flushing/closing fileWriter");
                    e.printStackTrace();
    			}catch (NullPointerException e){
    				e.printStackTrace();
    			}
    			 System.out.println("Save as file: " + saveTo);
    			
    		} // end of try-catch
    	} // end method writeMagicDrawCSVFile
 
	/** Performs lookup on supplied MAC address.
	 * @param macAddress MAC address to lookup.
	 * @return Manufacturer of MAC address. */
	private static String lookupVendor(String macAddress) throws IOException {
		StringBuilder result = new StringBuilder();
		Soundex soundex = new Soundex();
		String firstSix = macAddress.replace(":", "").toUpperCase().substring(0,6);
		
		//Debug//
//			System.out.println("MacAddress: "+ newAddress);
		try{
		scanner = new Scanner(new FileReader(defaultMacFile));
		while (scanner.hasNextLine()){
			String[] columns = scanner.nextLine().split(",");
			ouiMacLookUp.put(columns[1], columns[2]);
		}
		
		 if (scanner != null)
		    	scanner.close();
		}catch (FileNotFoundException a){
		JOptionPane fileNotFound = new JOptionPane();

			JOptionPane.showMessageDialog(fileNotFound,
				    "Parser could not find oui.csv. \nPlease upload oui.csv to the same file location as this NessusParser executable. \nA new oui.csv can be uploaded at: \nhttp://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries.",
				    "CANNOT FIND OUI.CSV",
				    JOptionPane.WARNING_MESSAGE);

			System.exit(0);
		}
		 
		 String vendor = ouiMacLookUp.get(firstSix);
		 
		 return vendor;
	}

	private static String lookupMagicDrawVendor(String vendorName) {
		try {
			Soundex soundex = new Soundex();
			String result = new String();
			// Is this a vendor we already have in the master list?
			String vendor = soundex.encode(vendorName);
			result = magicDrawVendors.get(soundex.soundex(vendorName));
			//System.out.println("soundex from LOOKUP vendor: " + soundex.soundex(vendorName));

			return result == null ? "N/A" : result;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "N/A";
		}
	}
	 public ArrayList<ReportHost> getHostList() {
	        return hostList;
	    }
	 public HashMap<String, String> getUniqueHostList() {
	        return uniqueHostName;
	    }
	public static void showWarning(String filePath){
		JOptionPane fileNotFound = new JOptionPane();
		JOptionPane.showMessageDialog(fileNotFound,
			     "An output file cannot be accessed because it is currently being used by another process. \nAttempted file access: " + filePath,
			    "CANNOT ACCESS FILE",
			    JOptionPane.WARNING_MESSAGE);
	}
	 public static void showSaveConfirmation(String directory, Component window){
		 JOptionPane confirm = new JOptionPane();
		 if (importSpreadSheet && connectorEnds && hostPorts){
			 confirm.showMessageDialog(window, "Saved importSpreadsheet.csv, connector-ends.csv, and host-ports.csv to " + directory);
		 }
	 }
	 
} // end parseNessus
