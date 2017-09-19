 //parseNessus_has no tracehops showing
 package src.com.g2.nessus;

import java.awt.Component;
//import java.awt.Cursor;
//import java.io.BufferedReader;
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
 * 01/06/2017		cmccoy		Created this package
 * 02/01/2017		cmccoy		No internet connection in the lab.
 * 05/30/2017		sprokop		Changed mac address api calls to use an OUI file lookup to find the vendor. 
 * 06/29/2017		sprokop		Created outputs for connecctor-ends and hop-ports with service Name and protocol per host
 * 09/18/2017		sprokop		Updated the vendor and mac address matching and the Qualified Name output, creating version 2. 
 * 
 */
 import java.io.File;
 import java.io.FileNotFoundException;
 import java.io.FileReader;
 import java.io.FileWriter;
 import java.io.IOException;
// import java.io.InputStream;
// import java.io.InputStreamReader;
// import java.io.StringWriter;
//import java.net.URI;
//import java.net.URISyntaxException;
//import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
//import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//import javax.servlet.ServletContext;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.codec.language.Soundex;
//import org.apache.commons.io.*;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

//import com.datastax.driver.core.AuthProvider;
//import com.datastax.driver.core.BoundStatement;
//import com.datastax.driver.core.Cluster;
//import com.datastax.driver.core.PlainTextAuthProvider;
//import com.datastax.driver.core.PreparedStatement;
//import com.datastax.driver.core.ResultSet;
//import com.datastax.driver.core.Row;
//import com.datastax.driver.core.Session;
import com.opencsv.CSVWriter;

//import javafx.util.Pair;


public class parseNessus  extends DefaultHandler {
/**class variables**/
	//below 3 are currently unused, but might want to enhance the site and version features in the future. 
	public static String site = "SUBCOMM";
	public static final String NESSUS_VERSION = "NessusClientData_v2";  // this version must be in the header tag
	public static final String VENDOR_FILE    = "vendors.csv";          // table export from MagicDraw


	//loaded with vendors and Qualified Names from the vendors.csv
	public static HashMap<String, String> magicDrawVendors = new HashMap<String, String>();
	//resource file used for vendor references
	public static String defaultVendorFile = "vendors.csv";
	public static Scanner scanner = null;
	public static boolean loadStatus = false;

	//below URL is not used because the matching mac->vendor->qualifiedname process must occur apart from the web
	/** Base URL for API. The API from www.macvendors.com was chosen. */
	private static final String baseURL = "http://api.macvendors.com/";	
	//will replace the above lookup vendor location
	public static String defaultMacFile = "oui.csv"; 
	//loaded with Mac Address and Organization names from oui.csv
	private static HashMap<String, String> ouiMacLookUp = new HashMap<String,String>();
	
	// holds the data retrieved from the XML file for each host
	private static ArrayList<ReportHost> hostList  = new ArrayList<ReportHost>();
	//holds entries to be written on the connector-ends.csv
	private static ArrayList<String> connectorEndsList = new ArrayList<String>();

	
	//maps the host with its trace-route hops
	static Map <String, List<String>> hostTraceRmap = new HashMap<String, List<String>>();
	// stores a list of every source with each of its destinations. 
	static Map<String, List<String>> connectedElementsMap = new HashMap<String, List<String>>();
	
	//Associates each host name (name or IP) with a unique host name that is not an IP. 
	private static HashMap<String, String> uniqueNames = new HashMap<String,String>();
	
	//creates a list of host names associated with their ip addresses. 
	private static HashMap<String, String> hostNametoIPMap = new HashMap<String, String>();
	
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
	private static ReportItem item;
	
	//indicator for writing .csv files 
	private static Boolean importSpreadSheet = false;
	private static Boolean connectorEnds = false;
	private static Boolean hostPorts = false;

	private static File file;
	
	// indicator for attributes in <tag name=____ >
	Boolean bHost_end 			= false;
	Boolean bMacAddress 		= false;
	Boolean bHostIp 			= false;
	Boolean bHostStart			= false;
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
	Boolean bReportHost			= false;
	Boolean bCve				= false;
	Boolean bBaseScore			= false;
	Boolean bTemporalScore		= false;
	Boolean bDescription		= false;
	Boolean bVulnPub			= false;
	Boolean bPatchPub			= false;
	Boolean bSolution			= false;
	
	private static List<Connection> connectionsList = new ArrayList<Connection>();
	
	
	public String getSite(){
		return site;
	}
	
	public String getVersion(){
		return NESSUS_VERSION;
	}
	
	/*Loads a hash map, connecting vendors with qualified names */
	public boolean vendorMap() throws Exception {
		//trying to help match the web vendor to the vendor in the .csv
		Soundex soundex = new Soundex();
		String vendor;
    	// Open the file for reading. Throw an exception if not found.
		String vendorFile;

		try{
			
			//looks for vendor file located in the same path location of the parser. 
			File vendors = new File(parseNessus.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
			String path = vendors.getAbsolutePath();
			String file = vendors.getName();
			System.out.println("File: " + file);
			 vendorFile = path.replace(file, "") + defaultVendorFile ;
		
			scanner = new Scanner(new FileReader(vendorFile));
		
			while (scanner.hasNextLine()) {
				// comma separator is expected delimiter
				//2	3Com	Communications Profile::Vendor Hardware & Software::Vendor Folder::3Com
				String[] columns = scanner.nextLine().split(",");
    		
				//saves the soundex code for the vendor to match with the information from the oui.csv
				// column 1 = Vendor name, column 2 = MagicDraw Qualified Name
				// discards the "Inc." from the vendor name found in the vendor.csv to allow for more accurate matching. 
				// "Inc." exists in the vendor.csv but not in the oui.csv. 
				vendor = columns[1].replaceAll("Inc.", "");
				vendor = vendor.replaceAll("Co.", "");
				vendor = vendor.replaceAll("Ltd.", "");
				vendor = vendor.replaceAll("Corp.","");
				magicDrawVendors.put(soundex.soundex(vendor), columns[2]);
			} // end while
    	
			// close all open resources to avoid compiler warning
			if (scanner != null)
				scanner.close();
	    
			// Got here without an exception. All good.
			loadStatus = true;
	    
		}catch (FileNotFoundException e){
			showFileNotFound("vendors.csv", "\nResult: 'qualifiedName' will not be accurate.");
		}
	    
	    return loadStatus;
	} // end vendorMap
	

	public void startParser(File[] inputFiles) throws IOException, ParserConfigurationException,
	SAXException {
		Scanner keyboard = new Scanner(System.in);
		 String statusMessage = null;
		 i=0; //initializing i to 0 for assigning unique names to the hosts in uniqueNamess
		 
		 //clears the list in the case of a second  (non-simultaneous) parsing
		 hostList.clear();
		 connectorEndsList.clear();
		 hostTraceRmap.clear();
		 connectionsList.clear();
		
		try {
			// read all the files in the import directory into an array
				loadStatus = vendorMap();
				if (loadStatus)
					statusMessage = "Vendor file loaded successfully.";

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
	            try{
	            sp.parse(scanFile, handler);
	            
	            
	            }catch (SAXParseException e){
	            	showNonCompatibleFile();
	            }
	            handler.createConnectedElements();
	            

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
//               if (host.getHost().contains("EndPoint"))
//            	   i++;
           } else if (qName.equalsIgnoreCase("tag")) {
        	   // save the name of the attribute name=____ so we determine which value to update
        	   tagName = attributes.getValue("name").toLowerCase();        	   
        	   
        	   switch (tagName)
        	   {
        	   case "host_end": 			bHost_end = true; 			break;
        	   case "host_start":			bHostStart = true;			break;
        	   case "mac-address": 			bMacAddress = true; 		break;
        	   case "host-ip":				bHostIp = true; 			break;
        	   case "os":					bOs = true; 				break;
        	   case "operating-system":		bOperatingSystem = true; 	break;
        	   case "system-type":			bSystemType = true;			break;
        	   case "host-fqdn":			bHostFqdn = true;			break;
        	   }
        	   
        	   if (tagName.contains("cpe-")) {//yes
        		   bInstalledSoftware = true;//yes
        	   } else if (tagName.contains("traceroute-hop")) {//yes
        		   bTraceRouteHops = true;//yes
        	   }
        	   //System.out.println(tagName);
           } else if (qName.equalsIgnoreCase("cvss_base_score")) {
        	   bCvssBaseScore = true;
           } else if (qName.equalsIgnoreCase("cvss_temporal_score")) {
        	   bCvssTemporalScore = true;
           }else if (qName.equalsIgnoreCase("ReportItem")){
        	   String port = attributes.getValue("port");
        	   String service = attributes.getValue("svc_name");
        	   String protocol = attributes.getValue("protocol");
        	  host.setReportItem(port,service, protocol);
//        	  System.out.println(host.getItem().getItemAttributes());
        	  item = host.getItem();
           }else if (qName.equalsIgnoreCase("cve")){
//        	   System.out.println("- ReportItem -");
        	   bCve = true;
           }else if(qName.equalsIgnoreCase("cvss_base_score")){
//        	   System.out.println("base score");
        	   bBaseScore= true;
           }else if (qName.equalsIgnoreCase("cvss_temporal_score")){
//        	   System.out.println("temporal score");
        	   bTemporalScore = true;
           }else if (qName.equalsIgnoreCase("description")){
//        	   System.out.println("description");
        	   bDescription = true;
           }else if (qName.equalsIgnoreCase("vuln_publication_date")){
//        	   System.out.println("vuln publication date");
        	   bVulnPub = true;
           } else if (qName.equalsIgnoreCase("patch_publication_date")){
//        	   System.out.println("patch publication date");
        	   bPatchPub = true;
           }else if (qName.equalsIgnoreCase("solution")){
//        	   System.out.println("solution");
        	   bSolution = true;
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
               setUniqueNames(host);
               //setHostNametoIPMap(host);
               
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
           }else if (bHostStart){
        	   host.setRunDate(temp);
        	   bHostStart = false;
           }else if (bOs) {
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
        	   item.setBaseScore(temp);
        	   bCvssBaseScore = false;
           } else if (bCvssTemporalScore) {
        	   host.setCVSSTemporalScore(temp);
        	   item.setTempScore(temp);
        	   bCvssTemporalScore = false;
//           } else if (bReportHost) {
//        	   String port =  
//        	   host.setReportHost()
           } else if (bCve){
//        	   System.out.println("cve: " + temp);
        	  // host.setCveId(temp);
        	   item.setCveId(temp);
        	   bCve = false;
//           }else if (bBaseScore){
////        	   host.setBaseScore(temp);
//        	   System.out.println("BaseScore: " +temp);
//        	   item.setBaseScore(temp);
//        	   bBaseScore = false;
//           }else if (bTemporalScore){
////        	   host.setTempScore(temp);
//        	   System.out.println("Temporal Score: " +temp);
//        	   item.setTempScore(temp);
//        	   bTemporalScore = false;
           }else if (bDescription){
//        	   host.setDescription(temp);
        	   item.setDescription(temp);
        	   bDescription = false;
           }else if (bVulnPub){
//        	   host.setVulPublicationDate(temp);
        	  item.setVulPublicationDate(temp);
        	   bVulnPub = false;
           }else if (bPatchPub){
//        	   host.setPatchPublicationDate(temp);
        	   item.setPatchPublicationDate(temp);
        	   bPatchPub = false;
           }else if (bSolution){
//        	   host.setSolution(temp);
        	   item.setSolution(temp);
        	   bSolution = false;
           }
           
    } 
    
    /*Goes through current hash map of hosts and their names and creates 
    * a new name for any ip not yet given a unique name */
    public static String getUniqueName(String iP){
    	   String ip= iP.trim();
    	    	Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
    		Matcher matcher = pattern.matcher(ip);
    		String name;
    		if (uniqueNames.keySet().contains(ip)){
    			name = uniqueNames.get(ip);
//    			System.out.println("Name matches. No EndPoint # needed.");
//    			System.out.println("Name: " + name);
    			//System.out.println("already has a name: " + ip );
    	    }else{
    	    	if (matcher.matches()){ //sHost is an ip address
    				uniqueNames.put(ip, "EndPoint_"+ i );
    				i++;
    				//System.out.println("New ip: " + ip );
    			}else{
    				uniqueNames.put(ip, ip);
    				//System.out.println("Not an ip: " + ip );
    			}
    	    }
    		name = uniqueNames.get(ip);
    		//System.out.println("ip: " + ip + " " + name);
    		//System.out.println("Name: " + name);
    		return name;
    	    }

    /* creates a hash map of host names and assigns each host a unique name */
    public void setUniqueNames(ReportHost host){
    	String hostIP = host.getIpAddress();
    	String hostName = host.getHost();
    	
    	Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
    	Matcher matcher = pattern.matcher(hostName);
    	
    	if (matcher.matches()){ //sHost is an ip address
    		uniqueNames.put(hostIP.trim(), "EndPoint_"+ i );
    		i++;
    	}else{
    		uniqueNames.put(hostIP.trim(), host.getHost());
    	} 

    	//readuniqueNames();
    }
    
    /* creates a hash map of host names and their ip's  */
    //currently unused
    public void setHostNametoIPMap(ReportHost host){
    	String sHost = host.getHost();
    	String ip = host.getIpAddress();
    	
    	hostNametoIPMap.put(host.getIpAddress(), uniqueNames.get(sHost));
    	
    //readHostNametoIPMap();	
    }

    /* Creates a hash map of hosts with its trace route 
     * hops used for connector-ends output spreadsheet */
    
    public void createConnectedElements(){
    	
    	//readuniqueNames();
    	//readHostNametoIPMap();
    	
    	//creates a map from host to a list of its trace route hops (hostTraceRmap)
    	isolateTraceRouteHops();
    	//readHostTraceRmap();
    	
    	//creates a list of one-one connections (connectionsList)
    	buildConnectionsList();
    	//readConnectionsList();
    	
    	//creates a map, connecting each source to its list of targets (connectedElementsMap)
    	buildConnectedElementsMap();
    	//readConnectedElementsMap();
    	
    	//creates a list of strings with information needed to fill the connector-ends spreadsheet 
    	addtoConnectorEndsList();
    	//readConnectorEndsList();

    	
    }
  
    //This method extracts the trace route hops from the hosts and creates a map of their host to trace route hops.
    public void isolateTraceRouteHops(){
    	    	
    	Iterator<ReportHost> it = hostList.iterator();
    	ReportHost curHost = new ReportHost();
    	while (it.hasNext()) {
    		curHost = it.next();
    		String routeHops = curHost.getTraceRouteHops();
    		String host = curHost.getHost();
    		String[] routeArray = routeHops.split("->");
    		List<String> routeList = Arrays.asList(routeArray);
    		hostTraceRmap.put(host, routeList);
    		int i = 0;
    	}
    }
    
    //This method builds a list of one-to-one connections from the trace route Hops map;  
    public void buildConnectionsList(){
    	boolean first= true;
    	List<String> values;
    	String source = new String();
    	String target;
    	Connection connection;
    	int i = 0;
	 
    	for (String key : hostTraceRmap.keySet()){
    		values = hostTraceRmap.get(key);
    		Iterator<String> it = values.iterator();
    		while (it.hasNext()){
    			if (first) {
    				source = it.next().trim();
    				first = false;
    			}else{
    				target = it.next().trim();
    				//a list with just the connecting ends. Used for building connected_elements in the database. 
    				connection = new Connection(source,target);
    				if (connectionsList.contains(connection)|| connection.isNull(connection)){
    					continue;
    				}else{
    					connectionsList.add(connection);
    					i++;
    					source = target;
    				}
    			}
    		}
    	}
    }

    //This method builds a map from the list of connections that maps the source to a list of destinations
    public void buildConnectedElementsMap(){
    	String source;
    	String target;
    	Connection connection;
    	boolean first = true;
    	List<String> destinations;
    	
    	Iterator<Connection> it = connectionsList.iterator();
    	
    	while (it.hasNext()){
    		connection = it.next();
    		source = connection.getSource().toString();
    		target = connection.getTarget().toString();
    		
    		if (connectedElementsMap.containsKey(source)){
    			destinations = connectedElementsMap.get(source);
    			if (!(destinations.contains(target))&& (target.length()>1))
    				destinations.add(target);
    				connectedElementsMap.put(source,  destinations);
    		}else{
    			destinations = new ArrayList<String>();
    			if ((target.length()>1) && (source.length()>1)){
    				destinations.add(target);
    				connectedElementsMap.put(source,  destinations);
    			}
    		}		 
    	}
    }

     
    /*creates a list from host and trace-route hops hash map
     *to directly populate the connector-ends spreadsheet*/
    public void addtoConnectorEndsList(){
    	List<String> values;
    	String source = new String();
    	String target;
    	String blockName;
    	String sourceName;
    	String targetName;
    	String owner = "Site";
    	String diagram = "Site::Diagram";
    	String delimiter = "#";
    	//int i = 0; //index for the connectionsList
    	Connection connection;

    	boolean first = true;
    	int index = 0;
    	
    	//create a collection that maps ip to the host name for a lookup for the ip's
    	
    	
    	
    	Iterator<Connection> it = connectionsList.iterator();
//    	System.out.println("Creating Connector Ends: ");
    	while (it.hasNext()){
    		connection= it.next();
//    		for (Connection connection: connectionsList){
    		source = connection.getSource().toString();
    		target = connection.getTarget().toString();
    		
    		if (((source.contains("[0-9a-zA-Z]"))&&(target.contains("[0-9a-zA-Z]")))){
    			continue;
    		}
    	
    	
//    	//=================================================================
//    	for (String key : hostTraceRmap.keySet()){
//    		first = true;
//   		 	values = hostTraceRmap.get(key);
//
//   		 	Iterator<String> it = values.iterator();
//   		 	while (it.hasNext()){
//   		 		if (first) {
//   		 			source = it.next().trim();
//   		 			first = false;
//   		 		}else{
//   		 			target = it.next().trim();
////   		 			//a list with just the connecting ends. Used for building connected_elements in the database. 
////   		 			connection.setSource(source);
////   		 			connection.setTarget(target);
////   		 			connectionsList.add(i, new Connection(source,target));
////  		 			System.out.println("index: " + i + " " +connectionsList.get(i).toString());// prints correctly (929 different connections) last is source: 10.101.0.238 target: 10.106.23.41
////   		 			i++;
//////   		 			System.out.println(connectionsList.size());
//////   		 			System.out.println("Source: " + source + " Target: " + target);
   		 			
   		 		StringBuffer connectorInfo = new StringBuffer();	
   		 		
//   		 		System.out.println("Source: " + source + " Target: " + target);
   		 		
//   		 		System.out.println("Source: " + source);
   		 		if (uniqueNames.containsKey(source)){
   		 			blockName = uniqueNames.get(source);
   		 		}else{
   		 			blockName = getUniqueName(source);
   		 		}
   		 		
   	        	sourceName = "Site::"+blockName;
   	        	
   	        	if (uniqueNames.containsKey(target)){
   	        		targetName = "Site::"+ uniqueNames.get(target);
   	        	}else{
   	        		targetName = getUniqueName(target);
   	        	}
   		 			
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
//   		 	System.out.println("index: " + i + " " +connectionsList.get(i)); //not populated yet
//   		 	}
//   		 System.out.println("index: " + i + " " +connectionsList.get(i)); // prints the indecies 0-3 then nullpointer. 
//    	}
//    	System.out.println(connectionsList.get(900)); //reads source: 10.101.0.238 target: 10.106.23.41 (not good)
    	//buildconnectionsList();

    }
    
    /*
     *  A series of methods that read/ check contents of lists and maps
     */
    
    //reads the contents of the collection mapping the source to its one or more targets
    public void readConnectedElementsMap(){
   	 System.out.println("========== Connected Elements Map ==========");
    	List<String> values = new ArrayList<String>();
    	Iterator<String> it =connectedElementsMap.keySet().iterator();
    	for (String key: connectedElementsMap.keySet()){
    		values = connectedElementsMap.get(key);
    		System.out.println("Source: " +key);
    		for (String value: values){
    			System.out.println("                 "  + " Destinations: " + value);
             }	
        }	
    }
    
    
    //reads a map of all the hosts with a list of their traceroutes. 
    public void readHostTraceRmap() {

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
    //reads the given host names with their unique host name. One was given if the nost name was an IP address.  
    public void readuniqueNames(){
    	System.out.println("========== uniqueNames=========");
    	for (String host: uniqueNames.keySet())
    		System.out.println("Name: " + host + " Unique Name: " + uniqueNames.get(host));
    	System.out.println("Size of uniqueNames: " + uniqueNames.size());
    	
    }
    //reads a list of all the host with their IP addresses.
    public void readHostNametoIPMap(){
    	System.out.println("========== Host to Name to IP Map=========");
    	for (String hostName: hostNametoIPMap.keySet())
    		System.out.println("Name: " + hostName + " IP Address: " + hostNametoIPMap.get(hostName));
    	System.out.println("Size of hostNametoIPMap: " + hostNametoIPMap.size());
    }
    
    //reads a list of all connections as one-to-one connections (source to destination).  
    public void readConnectionsList() {
    	int i = 0; //index for 
    	System.out.println("========== ConnectedEnds List ==========");  
    	Iterator<Connection> it =connectionsList.iterator();
    	for (i=0; i< connectionsList.size(); i++){
    		System.out.println("index: " + i + " " +connectionsList.get(i).toString());
    	}
    	System.out.println("Size of connectionsList: " + connectionsList.size()); //926

    }	
    
    //reads the contents of the list that will populate the connector-ends.csv
    public void readConnectorEndsList(){
    	Iterator<String> it = connectorEndsList.iterator();
    	while (it.hasNext()){
    		String row = it.next();
    		System.out.println(row);
    	}
    }
    
  
    /*
     * A series of methods that writes the spreadsheets for MagicDraw
     */
    
    //writes connector-ends.csv, which includes all the source-target connections
    public static void writeConnectorEndsCsvFile(String saveTo) throws FileNotFoundException {
    	//Delimiter used in CSV file
    	final String COMMA_DELIMITER = ",";
    	final String NEW_LINE_SEPARATOR = "\n";
    	
    	//CSV file header
    	final String[] FILE_HEADER = "Source,SourceName,BlockName,Target,TargetName,Owner,Diagram".split(",");
		
		FileWriter fileWriter = null;
		CSVWriter writer = null;		
//		if (!(connectorEndsList.size()>0))
//			return;
			
		try {
			fileWriter = new FileWriter(saveTo);
			writer = new CSVWriter(fileWriter, ',', '"');
			
			writer.writeNext(FILE_HEADER);
			if (!(connectorEndsList.size()>0))
				return;
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
			System.out.println("saveto: " + saveTo);
			showWarning(saveTo);
			return;
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
		
	} // end method writeMagicDrawConnectorEnds
    
    //creates host-ports.csv 
    public static void writeMagicDrawHostPorts(String saveTo) throws FileNotFoundException {
    	//Delimiter used in CSV file
    	final String COMMA_DELIMITER = ",";
    	final String NEW_LINE_SEPARATOR = "\n";
    	String portsEntry = new String();
    	
    	//CSV file header
    	final String[] FILE_HEADER = "host,ports,serviceName,protocol".split(",");
		
		FileWriter fileWriter = null;
		CSVWriter writer = null;		
		if (!(hostList.size()>0))
			return;
		
		try {
			fileWriter = new FileWriter(saveTo);
			writer = new CSVWriter(fileWriter, ',', '"');
			writer.writeNext(FILE_HEADER);
			
			//Write a new report object list to the CSV file
			Iterator<ReportHost> it = hostList.iterator();
			ReportHost curHost = new ReportHost();
			while(it.hasNext()){
				curHost = it.next();
				List<String> hostPortsInfo = curHost.getHostPortsInfo();
				//returns a unique list of ports,services, and protocols for each host.
				Iterator<String> it2 = hostPortsInfo.iterator();
				while(it2.hasNext()){
					String curInfo = it2.next();
					String row = curHost.getHost()+curInfo;
					String[] rowEntry = row.split("#");
					writer.writeNext(rowEntry);
				}
			}

		    hostPorts = true;
		    System.out.println("ports CSV file was created successfully.");
		}catch (FileNotFoundException e){
			showWarning(saveTo);
			return;
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
		
	} // end method writeMagicDrawHostPorts
    
    //writes importSpreadsheet.csv
    public static void writeMagicDrawCsvFile(String saveTo) throws FileNotFoundException {
        	//Delimiter used in CSV file
        	final String COMMA_DELIMITER = ",";
        	final String NEW_LINE_SEPARATOR = "\n";
        	
        	//CSV file header
        	final String[] FILE_HEADER = "host,vendor,macAddress,qualifiedName,IP-Address,O/S,operatingSystem,systemType,FQDN,scanDate,installedSoftware,traceRouteHops,CVSSBaseScore,CVSSTemporalScore".split(",");
    		
    		FileWriter fileWriter = null;
    		CSVWriter writer = null;		
//    		if (!(hostList.size()>0))
//    			return;
    		
    		try {
    			fileWriter = new FileWriter(saveTo);
    		
    			writer = new CSVWriter(fileWriter, ',', '"');
    			writer.writeNext(FILE_HEADER);
    			
    			if (!(hostList.size()>0))
        			return;
    			
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
    			return;
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
    
    public static void savetoCassandra(){
    	try{
    	UpdateCassandra cassandra = new UpdateCassandra();
    	cassandra.update();// keep this first to update. Otherwise the vulnerability count will x2 or more. 
    	cassandra.updateCvssScores();
    	cassandra.updateConnectedElements();
    	System.out.println("Data saved to Cassandra");
    	}catch(ExceptionInInitializerError e){
    		showAuthenticationError();
    	}
    }
                                                                             
 
	/** Performs lookup on supplied MAC address.
	 * @param macAddress MAC address to lookup.
	 * @return Manufacturer of MAC address. */
	private  String lookupVendor(String macAddress) throws IOException {
		StringBuilder result = new StringBuilder();
		Soundex soundex = new Soundex();
		String firstSix = macAddress.replace(":", "").toUpperCase().substring(0,6);

		try{
			scanner = new Scanner(new FileReader(defaultMacFile));
			while (scanner.hasNextLine()){
			String[] columns = scanner.nextLine().split(",");
			String mac = columns[1]; 
			//took off the vendor name endings so that the soundex would match with the vendor name, which has also been stripped of various vendor name endings. 
			String vendor = columns[2].replaceAll("Inc.", "");
			vendor = vendor.replaceAll("Co.", "");
			vendor = vendor.replaceAll("Ltd.", "");
			vendor = vendor.replaceAll("Corp.","");
			//the oui.csv cuts off the zeros at the front of a mac address, which creates a mismatch for the lookup. 
			//putting back the zeros from the mac address columns allows look up form actual mac address to the first six in the csv
			while (mac.length()<6){
				mac = "0"+mac;
			}
			ouiMacLookUp.put(mac, vendor);
			//System.out.println("VENDOR INFORMATION: "+ columns[1] + " " + columns[2]);
			}
			if (scanner != null)
		    	scanner.close();
		}catch (FileNotFoundException a){
			String addMessage = "\nA new oui.csv can be uploaded at: \nhttp://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries.";
			showFileNotFound("oui.csv", addMessage);	
			System.exit(0);
		}
		 
		 String vendor = ouiMacLookUp.get(firstSix);
		 return vendor;
	}

	/*Uses mac address from parser to look up vendor in oui.csv and uses 
	 * the vendor to get the qualified name from the  pre-loaded vendors */
	private String lookupMagicDrawVendor(String vendorName) {
		try {
			Soundex soundex = new Soundex();
			String result = new String();
			// Is this a vendor we already have in the master list?
			String vendor = soundex.encode(vendorName);
			result = magicDrawVendors.get(vendor);
			

			////////////////////////////The below is used only when the internet is able to be used. ///////////
			//private static final String baseURL = "http://api.macvendors.com/";	
			//StringBuilder result = new StringBuilder();
			//URL url = new URL(baseURL + macAddress);
			//System.out.println(url);
			//HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			//conn.setRequestMethod("GET");
			//BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			//String line;
			//while ((line = rd.readLine()) != null) {
			//	result.append(line);
			//}
			////webVendor
			//rd.close();
			//System.out.println(result);
			//return result.toString();
			////////////////////////////////////////////////////////////////////////////////////////////////////		
			

			return result == null ? "N/A" : result;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "N/A";
		}
	}
	
	/*
	 * getters for the lists/maps
	 */
	 public ArrayList<ReportHost> getHostList() {
	        return hostList;
	    }
	 public HashMap<String, String> getUniqueHostList() {
	        return uniqueNames;
	    }
	 public Map<String, List<String>> getConnectedElements(){
		 return connectedElementsMap;
	 }
	 
	 public HashMap<String,String> getHostNametoIPMap(){
		 return hostNametoIPMap;
	 }
	
	 /*
	  * Warnings used to locate and write specific files
	  */
	 public static void noNessusFile(){
		 JOptionPane noNessus = new JOptionPane();
		 JOptionPane.showMessageDialog(noNessus, "<html>No Data has been found.<br>Try re-uploading your *.nessus file.</html>", "NO DATA", JOptionPane.WARNING_MESSAGE);
	 }
	 
	 public static void showWarning(String filePath){
		JOptionPane fileNotFound = new JOptionPane();
		JOptionPane.showMessageDialog(fileNotFound,
			     "An output file cannot be saved because it is either currently being used by another process or the file path localtion does not enable 'WRITE' permissions. \nAttempted file access: " + filePath,
			    "CANNOT ACCESS FILE",
			    JOptionPane.WARNING_MESSAGE);
	}
	
	public static void showFileNotFound(String fileName, String addMessage){
		JOptionPane fileNotFound = new JOptionPane();
		JOptionPane.showMessageDialog(fileNotFound,
			    "<html><h3>Parser cannot find " + fileName+"</h3></html> \nPlease upload "+ fileName+" to the same file location as this NessusParser executable." + addMessage,
			    "CANNOT FIND " + fileName.toUpperCase(),
			    JOptionPane.WARNING_MESSAGE);
	}
	
	/*Will appear once all the files are actually written */
	 public static void showSaveConfirmation(String directory, Component window){
		 JOptionPane confirm = new JOptionPane();
		 if (importSpreadSheet && connectorEnds && hostPorts){
			 confirm.showMessageDialog(window, "Saved importSpreadsheet.csv, connector-ends.csv, and host-ports.csv to " + directory);
		 }else if(!importSpreadSheet && !connectorEnds && !hostPorts){
			 noNessusFile();
		 }
	 }
	 
	 public void showNonCompatibleFile(){
		 JFrame warn = new JFrame();
		 JOptionPane.showMessageDialog(warn,"Please select a compatable file." , 
					"Error Found", JOptionPane.WARNING_MESSAGE);
	 }
	 //Will show when the user attempts to save information to the database. 
	 public static void showAuthenticationError(){
		 JFrame warn = new JFrame();
		 JOptionPane.showMessageDialog(warn, "You do not have access to the database. \nPlease contact the Chief Data Strategist at G2 Ops for access. ",
				 "Authorization Error", JOptionPane.WARNING_MESSAGE);
	 }
	 
} // end parseNessus
