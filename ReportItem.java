package src.com.g2.nessus;

/**
 * @author Sara Prokop, G2 Ops, Virginia Beach, VA
 * @date September 18,2017 
 * 
 * @purpose This ReportItem class captures information about each item within each Report Host, 
 * Each ReportItem contains information about cvss scores, which is imported into the database, 
 * as well as ports, services, and protocols, which is used for the host-ports.csv output file. 
 * 
 */

public class ReportItem {
/** class variables **/
	
	//port per item- port
	//<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" 
	private String port;
	
	//service name per item - svc_name
	//<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" 
	private String service;
	
	//protocol per item- protocol
	//<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" 
	private String protocol;
	
	//vulnerability identification
	//<cve>CVE-1999-0524</cve>
	private String cveID;
	
	//cvss base score for a vulnerability
	//<cvss_base_score>5.8</cvss_base_score>
	private double baseScore;
	
	//cvss temporal score for a vulnerability
	//<cvss_temporal_score>7.1</cvss_temporal_score>
	private double tempScore;
		
	//description of the Report Item
	//<description>Makes a traceroute to the remote host.</description>
	private String description;
	
	//vulnerability publication date
	//<vuln_publication_date>2008/11/24</vuln_publication_date>
	private String vulnPub;
	
	//patch publication date
	//<patch_publication_date>2016/12/13</patch_publication_date>
	private String patchPub;
	
	//solution for vulnerability
	//<solution>Microsoft has released a set of patches for Internet Explorer 9, 10, and 11.</solution>
	private String solution;
		
	
	public ReportItem(){
		
	}

/** Tools **/
	//replace null strings with the empty string so "null" doesn't print
	public static String replaceNull(String input) {
		return input == null ? "" : input;
	}
	public static String keepNull(String input){
		if (input == null){
			return input;
		}else{
			return "'"+input+"'";
		}
	}
	
	//creates output for the host-ports output
	public String getItemAttributes(){
		StringBuffer attributes = new StringBuffer();
		String delimiter = "#";
		
		attributes.append(delimiter);
		attributes.append(getPort());
		attributes.append(delimiter);
		attributes.append(getService());
		attributes.append(delimiter);
		attributes.append(getProtocol());
		
		return attributes.toString();
	}


/** Setting and Getting Attributes and Tags **/
	//***********Protocol******************/
	public void setProtocol(String protocol){
		this.protocol = protocol;
	}
	public String getProtocol(){
		return replaceNull(protocol);
	}
	
	//***********Service******************/
	public void setService(String service){
		this.service = service;
	}
	public String getService(){
		return replaceNull(service);
	}
	
	//***********Service******************/
	public void setPort(String port){
		this.port = port;
	}
	public String getPort(){
		return replaceNull(port);
	}

	//***********ID******************//		
	public void setCveId(String id){
//		System.out.println("CVE ID: " + id);
		this.cveID = id;
	}
	public String getCveId(){
		return keepNull(cveID);
	}
	//***********Base Score******************//	
	public void setBaseScore(String base){
//		System.out.println("Base: " + base);
		this.baseScore = Double.parseDouble(base);
	}
	public Double getBaseScore(){
		return baseScore;
	}
	//***********Temp Score******************//	
	public void setTempScore(String temp){
//		System.out.println("Temp: " + temp);
		this.tempScore = Double.parseDouble(temp);
	}
	public Double getTempScore(){
		return tempScore;
	}
	//***********Description******************//	
	public void setDescription(String descript){
		int dot = descript.indexOf(".") + 1;//the +1 to include the period
		this.description = descript.substring(0, dot);
	}
	public String getDescription(){
		return keepNull(description);
	}
	//***********Vulnerability Publication Date******************//	
	public void setVulPublicationDate(String vdate){
		String date = vdate.replaceAll("/", "-");
		
		this.vulnPub = date;
	}
	public String getVulPublicationDate(){
		return keepNull(vulnPub);
	}
	//***********Patch Publication Date******************//	
	public void setPatchPublicationDate(String pdate){
		String date = pdate.replaceAll("/", "-");
		this.patchPub = date;
	}
	public String getPatchPublicationDate(){
		return keepNull(patchPub);
	}
	//***********Solution******************//	
	public void setSolution(String sol){
		int dot = sol.indexOf(".") + 1;//the +1 to include the period
		this.solution = sol.substring(0, dot);
	}
	public String getSolution(){
		return keepNull(solution);
	}
}
