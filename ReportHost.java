
package src.com.g2.nessus;

//import java.awt.ItemSelectable;
import java.text.SimpleDateFormat;
//import java.text.DateFormat;
import java.text.ParseException;

/*
 * ReportHost class stores host information after parsing the Nessus XML file.
 * This is the java domain object which represents the data we want to parse and extract.
 * 
 * @author Corren McCoy, G2 Ops, Virginia Beach, VA
 * 
 * 
 * 
 * Reference:
 * http://javarevisited.blogspot.com/2011/12/parse-read-xml-file-java-sax-parser.html
 * https://www.tutorialspoint.com/java_xml/java_sax_parse_document.htm
 * http://www.journaldev.com/1198/java-sax-parser-example
 * 
 * Modification History
 * 18-Sept-2017		sara.prokop		Added more attributes and modified data output
 * 
 */

import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.Collection;
import java.util.Collections;
import java.util.Date;
//import java.util.HashMap;
//import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
//import java.util.regex.Matcher;
//import java.util.regex.Pattern;

//import org.apache.commons.lang3.StringUtils;

import com.datastax.driver.core.LocalDate;

public class ReportHost {
/** class variables **/
	//<ReportHost name="192.168.54.2"><HostProperties>
	private String sHost;

	
	// <tag name="host-ip">192.168.54.2</tag>
	private String	sIpAddress;	

	// may need to lookup using the mac address, if available using HTTP GET or POST request to https://macvendors.com/api
	// Sample Java request: http://www.java2blog.com/2016/07/how-to-send-http-request-getpost-in-java.html
	// http://api.macvendors.com/00:80:64:a5:36:33 returns WYSE TECHNOLOGY LLC
	// MAC-Addresses are assigned by IEEE. 
	// Search / browse and download at http://standards.ieee.org/develop/regauth/oui/public.html
	// <tag name="mac-address">00:80:64:a5:36:33</tag>
	private String	sVendor;
	private String 	sMacAddress;
	private String  sQualifiedName;
	
	//This captures the start date on which the scan was run 
	//<tag name="HOST_START">Sat Jan 28 09:00:43 2017</tag>
	private LocalDate ldRunDate;
	//format date from dateParser to newFormat
	private SimpleDateFormat dateParser; 
	private SimpleDateFormat newFormat;
	
	
	
	
	//software
	//<tag name="cpe">cpe:/o:apple</tag>
	private String cpeId;

	// short operating system name
	// <tag name="os">windows</tag>			
	private String	sOs;					
										
	// long operating system name 	
	// <tag name="operating-system">Microsoft Windows Embedded Standard Service Pack 1</tag>
	private String 	sOperatingSystem;

	// fully qualified domain name (fqdn)
	// <tag name="host-fqdn">CSG7BLKTC</tag>
	private String 	sFqdn;				 

	// <tag name="system-type">general-purpose</tag>
	// router, general purpose, etc.									
	private String	sSystemType;			

	// end date for the scan
	// tag name="HOST_END">Fri Nov 18 10:19:53 2016</tag>									
	private String	sScanDate;
	
	
	
										
	// follow the traceroute or 10287 plugin output in <ReportItem>
	// <tag name="traceroute-hop-0">192.168.54.2</tag>
	// <plugin_output>For your information, here is the traceroute from 192.168.54.18 to 192.168.54.2 : 
	// 192.168.54.18
	// 192.168.54.2
	// </plugin_output>
	//private String[] sTraceRouteHops; // = new String[];
	private List<String> sTraceRouteHops = new ArrayList<String>();
	
	// installed software which includes the operating system in a different form
	// <tag name="cpe-2">cpe:/a:microsoft:ie:11.0.9600.18499</tag>
	// <tag name="cpe-1">cpe:/a:adobe:acrobat_reader:11.0.18.21</tag>
	// <tag name="cpe-0">cpe:/o:microsoft:windows::sp1</tag>
	private List<String> sInstalledSoftware = new ArrayList<String>();
	private String installedSoftware = null;
	
	// <ReportItem port="3389" svc_name="msrdp" protocol="tcp" severity="0" pluginID="11219" 
	// pluginName="Nessus SYN scanner" pluginFamily="Port scanners"

	//<cvss_base_score>9.3</cvss_base_score>
	private List<String> cvssBaseScore = new ArrayList<String>(); 

	//<cvss_temporal_score>6.9</cvss_temporal_score>
	private List<String> cvssTemporalScore = new ArrayList<String>();
	private List<String> sPorts = new ArrayList<String>();
	
	//creates a class for Report items so that information can be extracted based on the device. 
	private ReportItem item;
	//stores the list of report items (or devices) per host
	private List<ReportItem> reportItems = new ArrayList<ReportItem>();
	//filters the list of items that only contain a cve score
	private List<ReportItem> itemsWithCve = new ArrayList<ReportItem>();
	//a list of unique Strings that have a unique combination of data points for port, protocol, and service. 
	private List<String> hostPortsInfoList = new ArrayList<String>();
	private static int count = 0;
	
	
	
 
	
	// Class variables already initialized in declaration. Nothing to do in the constructor.
/** Constructor**/
	public ReportHost () {
	}

/** Tools **/
	//replace null strings with the empty string so "null" doesn't print
	public static String replaceNull(String input) {
		  return input == null ? "" : input;
	}
/** Setting and Getting Attributes **/
	//***********Host - name******************//		
	public String getHost() {
        return replaceNull(sHost.trim());
    }
    public void setHost(String sHost) {
    	this.sHost = sHost;	
    }
  //**************Ip Address***********************************
     public String getIpAddress() {
        return replaceNull(sIpAddress);
    }
    public void setIpAddress(String sIpAddress) {
        this.sIpAddress = sIpAddress;
    }
    //**************Run Date***********************************
    public LocalDate getRunDate() {
        //localDate is required by the Cassandra Database
    	return ldRunDate;
   }
   public void setRunDate(String sDate) {
	   //format within the file
	   dateParser = new SimpleDateFormat("EEE MMM d HH:mm:ss yyyy");
	   //desired format
	   newFormat = new SimpleDateFormat("yyyy-MM-dd");
	   Date dDate;
	try {
		dDate = dateParser.parse(sDate);
		String sNewDate = newFormat.format(dDate);
		Date dNewDate = newFormat.parse(sNewDate);
		LocalDate rundate = LocalDate.fromMillisSinceEpoch(dNewDate.getTime()); 
		this.ldRunDate = rundate;
	} catch (ParseException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
   }
  //***********CPE id******************************************
    public String getCpeId() {
        return replaceNull(sIpAddress);
    }
    public void setCpeId(String cpe) {
        this.cpeId = cpe;
    }
	//***********Vendor********************************************
	public String getVendor() {
		return replaceNull(sVendor);
	}
	public void setVendor (String sVendor){
		this.sVendor = sVendor;
	}
	//***********Qualified Name************************************
	//will return "N/A" if the vendor in the vendor.csv does not match the vendor in the oui.csv
	public String getQualifiedName() {
		return replaceNull(sQualifiedName);
	}
	public void setQualifiedName (String sQualifiedName){
		this.sQualifiedName = sQualifiedName;
	}
	//***********MAC Address**************************************
	public String getMacAddress() {
		return replaceNull(sMacAddress);
	}
	public void setMacAddress (String sMacAddress){
 	   // MacAddress can be 1:M
 	   String[] macList = sMacAddress.split("\n");
 	   this.sMacAddress = macList[0];
	}
	//***********OS*********************************
	public String getOs() {
		return replaceNull(sOs);
	}
	public void setOs(String sOs){
		this.sOs = sOs;
	}
	//***********Operating System********************************
	public String getOperatingSystem() {
		return replaceNull(sOperatingSystem);
	}
	public void setOperatingSystem(String sOperatingSystem){
		this.sOperatingSystem = sOperatingSystem;
	}
	//***********FQDN**********************************************
	public String getFqdn() {
		return replaceNull(sFqdn);
	}
	public void setFqdn(String sFqdn){
		this.sFqdn = sFqdn;
	}
	//***********System Type***************************************
	public String getSystemType() {
		return replaceNull(sSystemType);
	}
	public void setSystemType(String sSystemType){
		this.sSystemType = sSystemType;
	}
	//***********Scan Date*****************************************
	public String getScanDate() {
		return replaceNull(sScanDate);
	}
	public void setScanDate(String sScanDate){
		this.sScanDate = sScanDate;
	}
	//***********TraceRoute Hops**********************************
	public String getTraceRouteHops() {
		String hops = "   ";
		String sub;
		// Generate an iterator. Start just after the last element.
		ListIterator li = sTraceRouteHops.listIterator(sTraceRouteHops.size()); //ListIterator li = sTraceRouteHops.listIterator(sTraceRouteHops.size()); 
		
		// Iterate in reverse because the last node is presented first in the nessus file	
		while(li.hasPrevious()) {
			hops = hops + li.previous() + "-> ";
		}
		// Do not include the hops that are a question mark or come after a question mark
		if (hops.contains("?")){
			sub = hops.substring(hops.indexOf("?"), hops.length());
			hops = hops.replace(sub, "");
		}	
		hops = hops.substring(0, hops.length()-3);
		return replaceNull(hops);	
	}

	public void setTraceRouteHops(String sTraceRouteHop) { //(String sTraceRouteHop, String sTagName)
			sTraceRouteHops.add(sTraceRouteHop);
	}
	//************Installed Software*******************************
	public String getInstalledSoftware() {
		String sw = ""; 
		for (String element : sInstalledSoftware) {
		    sw = sw + element + "\n";
		}
		return replaceNull(sw);
	}
		
	public void setInstalledSoftware(String sInstalledSoftware) {
		// add new element to the array
  		this.sInstalledSoftware.add(sInstalledSoftware);
	}
	//***********CVSS Base Score***********************************
	public String getCVSSBaseScore() {
		String base=""; 
		Collections.sort(cvssBaseScore, Collections.reverseOrder());
		if (cvssBaseScore.size() ==0){
			base="";
		}else{
			base = cvssBaseScore.get(0);	
		}

		return replaceNull(base);
	}
	public void setCVSSBaseScore(String cvssBaseScore) {
		// add new element to the array
  		this.cvssBaseScore.add(cvssBaseScore);
	}
	//***********CVSS Temporal Score*******************************
	public String getCVSSTemporalScore() {
		String temporal=""; 
		Collections.sort(cvssTemporalScore, Collections.reverseOrder());
		
		if (cvssTemporalScore.size() ==0){
			temporal="";
		}else{
			temporal = cvssTemporalScore.get(0);	
		}

		return replaceNull(temporal);
	}
	public void setCVSSTemporalScore(String cvssTemporalScore) {
  		this.cvssTemporalScore.add(cvssTemporalScore);
	}
//*************************REPORT ITEM*****************
	//creates a new item with a port, service, and protocol attributes
	public void setReportItem(String port, String service, String protocol){
		this.item = new ReportItem();
		item.setPort(port);
		item.setProtocol(protocol);
		item.setService(service);
		reportItems.add(item);
	}
	public ReportItem getItem(){
		return this.item;
	}
	//returns a list of all ReportItems
	public List<ReportItem> getReportItems(){
		return reportItems;
	}
	//returns a list of unique Strings that have a unique combination of data points for port, protocol, and service. 
	public List<String> getHostPortsInfo(){
		//creates a unique list of report items attributes
		for (ReportItem item : reportItems){
			if (hostPortsInfoList.contains(item.getItemAttributes())){
				continue;
			}else{
				hostPortsInfoList.add(item.getItemAttributes());
			}
		} 
		return  hostPortsInfoList;
	}
	//returns a list of items that have vulnerabilities
	public List<ReportItem> getItemsWithCve(){
		setItemsWithCve();
		return itemsWithCve;
	}
	//creates a unique list of the items that have vulnerabilities
	public void setItemsWithCve(){
		for (ReportItem item: reportItems)
			if (item.getCveId() == null){
				continue;
			}else{
				itemsWithCve.add(item);
			}
	}
	
	//*************Vulnerability Count*************
	public int getVulnerabilityCount(){
		setItemsWithCve();
		count = itemsWithCve.size();
		return count;
	}
	
	@Override
	//This method prepares the information for an output spreadsheet (importStpreadSheet.csv)
	public String toString() {
		StringBuffer hostInfo = new StringBuffer();
		String delimiter = "#";
		//"host,vendor,macAddress,qualifiedName,IP-Address,O/S,operatingSystem,systemType,FQDN,scanDate"
		hostInfo.append(getHost());
		hostInfo.append(delimiter);
		hostInfo.append(getVendor());
		hostInfo.append(delimiter);
		hostInfo.append(getMacAddress());
		hostInfo.append(delimiter);
		hostInfo.append(getQualifiedName());
		hostInfo.append(delimiter);
		hostInfo.append(getIpAddress());
		hostInfo.append(delimiter);
		hostInfo.append(getOs());
		hostInfo.append(delimiter);
		hostInfo.append(getOperatingSystem());
		hostInfo.append(delimiter);
		hostInfo.append(getSystemType());
		hostInfo.append(delimiter);
		hostInfo.append(getFqdn());
		hostInfo.append(delimiter);
		hostInfo.append(getScanDate());
		hostInfo.append(delimiter);
		hostInfo.append(getInstalledSoftware());
		hostInfo.append(delimiter);
		hostInfo.append(getTraceRouteHops());
		hostInfo.append(delimiter);
		hostInfo.append(getCVSSBaseScore());
		hostInfo.append(delimiter);
		hostInfo.append(getCVSSTemporalScore());

		return hostInfo.toString();
	}

	
}  // end of class ReportHost