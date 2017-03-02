package src.com.g2.nessus;

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
 */

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

public class ReportHost {
	
	//<ReportHost name="192.168.54.2"><HostProperties>
	private String sHost;
	
	// <tag name="host-ip">192.168.54.2</tag>
	private String	sIpAddress;	

	// may need to lookup using the mac address, if available using HTTP GET or POST request to https://macvendors.com/api
	// Sample Java request: http://www.java2blog.com/2016/07/how-to-send-http-request-getpost-in-java.html
	// http://api.macvendors.com/00:80:64:a5:36:33 returns WYSE TECHNOLOGY LLC
	// MAC-Addresses are assigned by IEEE. Search / browse and download at http://standards.ieee.org/develop/regauth/oui/public.html
	// <tag name="mac-address">00:80:64:a5:36:33</tag>
	private String	sVendor;

	// short operating system name 				
	private String 	sMacAddress;

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
	private List<String> sTraceRouteHops = new ArrayList<String>();

	// installed software which includes the operating system in a different form
	// <tag name="cpe-2">cpe:/a:microsoft:ie:11.0.9600.18499</tag>
	// <tag name="cpe-1">cpe:/a:adobe:acrobat_reader:11.0.18.21</tag>
	// <tag name="cpe-0">cpe:/o:microsoft:windows::sp1</tag>
	private List<String> sInstalledSoftware = new ArrayList<String>();
	private String installedSoftware = null;
	
	// <ReportItem port="3389" svc_name="msrdp" protocol="tcp" severity="0" pluginID="11219" 
	// pluginName="Nessus SYN scanner" pluginFamily="Port scanners"
	private List<Double> ports = new ArrayList<Double>();

	//<cvss_base_score>9.3</cvss_base_score>
	private List<String> cvssBaseScore = new ArrayList<String>(); 

	//<cvss_temporal_score>6.9</cvss_temporal_score>
	private List<String> cvssTemporalScore = new ArrayList<String>();
	
	// Class variables already initialized in declaration. Nothing to do in the constructor.
	public ReportHost () {
	}

	//replace null strings with the empty string so "null" doesn't print
	public static String replaceNull(String input) {
		  return input == null ? "" : input;
	}
	// **** Setters and Getters for all class variables *****
    public String getHost() {
        return replaceNull(sHost);
    }
    public void setHost(String sHost) {
        this.sHost = sHost;
    }
	//*************************************************************	
    public String getIpAddress() {
        return replaceNull(sIpAddress);
    }
    public void setIpAddress(String sIpAddress) {
        this.sIpAddress = sIpAddress;
    }
	//*************************************************************
	public String getVendor() {
		return replaceNull(sVendor);
	}
	public void setVendor (String sVendor){
		this.sVendor = sVendor;
	}
	//*************************************************************
	public String getMacAddress() {
		return replaceNull(sMacAddress);
	}
	public void setMacAddress (String sMacAddress){
 	   // MacAddress can be 1:M
 	   String[] macList = sMacAddress.split("\n");
 	   this.sMacAddress = macList[0];
	}
	//*************************************************************
	public String getOs() {
		return replaceNull(sOs);
	}
	public void setOs(String sOs){
		this.sOs = sOs;
	}
	//*************************************************************
	public String getOperatingSystem() {
		return replaceNull(sOperatingSystem);
	}
	public void setOperatingSystem(String sOperatingSystem){
		this.sOperatingSystem = sOperatingSystem;
	}
	//*************************************************************
	public String getFqdn() {
		return replaceNull(sFqdn);
	}
	public void setFqdn(String sFqdn){
		this.sFqdn = sFqdn;
	}
	//*************************************************************
	public String getSystemType() {
		return replaceNull(sSystemType);
	}
	public void setSystemType(String sSystemType){
		this.sSystemType = sSystemType;
	}
	//*************************************************************
	public String getScanDate() {
		return replaceNull(sScanDate);
	}
	public void setScanDate(String sScanDate){
		this.sScanDate = sScanDate;
	}
	//*************************************************************
	public String getTraceRouteHops() {
		String hops = "";
		// Generate an iterator. Start just after the last element.
		ListIterator li = sTraceRouteHops.listIterator(sTraceRouteHops.size());

		// Iterate in reverse because the last node is presented first in the nessus file
		while(li.hasPrevious()) {
		    hops = hops + li.previous() + "\n";
		}
		return replaceNull(hops);	
	}
	
	public void setTraceRouteHops(String sTraceRouteHops) {
  		this.sTraceRouteHops.add(sTraceRouteHops);
	}
	//*************************************************************
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
	//*************************************************************
	public String getCVSSBaseScore() {
		String base = ""; 
		for (String element : cvssBaseScore) {
		    base = base + element + "\n";
		}
		return replaceNull(base);
	}
	public void setCVSSBaseScore(String cvssBaseScore) {
		// add new element to the array
  		this.cvssBaseScore.add(cvssBaseScore);
	}
	//*************************************************************
	public String getCVSSTemporalScore() {
		String temporal = ""; 
		for (String element : cvssTemporalScore) {
			temporal = temporal + element + "\n";
		}
		return replaceNull(temporal);
	}
	public void setCVSSTemporalScore(String cvssTemporalScore) {
  		this.cvssTemporalScore.add(cvssTemporalScore);
	}
	
	@Override
	public String toString() {
		StringBuffer hostInfo = new StringBuffer();
		String delimiter = "#";
		//"host,vendor,macAddress,IP-Address,O/S,operatingSystem,systemType,FQDN,scanDate"
		hostInfo.append(getHost());
		hostInfo.append(delimiter);
		hostInfo.append(getVendor());
		hostInfo.append(delimiter);
		hostInfo.append(getMacAddress());
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