package src.com.g2.nessus;
/**
 * @author Sara Prokop
 * @date 08/18/2017
 * 
 * The purpose of this class is to connect to the Cassandra database and to update hardware table with the data gathered
 * from the nessus file. 
 * 
 * This class is called when the user selects FILE> SAVE RESULTS> CASSANDRA DATABASE
 * 
 * Modification History
 * Date 				Author				Description
 * 9/6/2017				sara.prokop			Added to connected_elements, cvss_scores, updated host information from nessus file. 
 * 
 */


import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;

import com.datastax.driver.core.AuthProvider;
import com.datastax.driver.core.BoundStatement;
import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Host;
import com.datastax.driver.core.LocalDate;
import com.datastax.driver.core.PlainTextAuthProvider;
import com.datastax.driver.core.PreparedStatement;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.TypeCodec;
import com.datastax.driver.extras.codecs.jdk8.InstantCodec;
import com.sun.jmx.snmp.SnmpUnknownSubSystemException;

public class UpdateCassandra {

	/**class variables**/
	private static final String USERNAME = ""; //sara_prokop. changed to disable changes to the database from executable jar
	private static final String PASSWORD = ""; //changme. changed to disable changes to the database from executable jar

	private static String[] CONTACT_POINTS = {"ec2-52-44-86-234.compute-1.amazonaws.com"}; //4.86.18.217
	private static int PORT = 9042;
	private static AuthProvider authProvider = new PlainTextAuthProvider(USERNAME, PASSWORD);
	/*connecting to database*/
	private static Cluster cluster = Cluster.builder().addContactPoints(CONTACT_POINTS).withPort(PORT).withAuthProvider(authProvider).build();
	private static Session session = cluster.connect(""); //vmasc. changed to null to make sure no updates to the database occured 
	
	/*parsed data used to populate database*/
	//maps source to a list of targets
	static Map<String, List<String>> connectedElementsMap = new HashMap<String, List<String>>();
	static List<ReportHost> hostList = new ArrayList<ReportHost>();
	
	//used to retrieve the keys of an ip_address in getKeys(String). They prepared more efficiently if kept as class variables
	private static String statement_keys = "SELECT * FROM hardware_by_ip_address WHERE ip_address = ?";
	private static PreparedStatement prepared_keys = session.prepare(statement_keys); 
	private static BoundStatement bound_keys;
	
	//used to insert new Ip. They prepared more efficiently if kept as class variables
	private static String statement_insertHopIp = "INSERT INTO hardware(ip_address, import_date, internal_system_id, site_or_ou_name,ip_subnet_or_building) "
			+ "values (?, toDate(now()), uuid(), ?, ?)";
	private static PreparedStatement prepared_insertHopIp = session.prepare(statement_insertHopIp); 
	
	//used to assign the site to the item
	private static String site;
	

	
	
	public UpdateCassandra(){
		parseNessus nessus = new parseNessus();
		//updates lists to be referred to when inserting information into the database
		connectedElementsMap = nessus.getConnectedElements();
		hostList = nessus.getHostList();
	}

	//Updates the connected_elements in the hardware table.
	public void updateConnectedElements(){
		System.out.println("=============== Update Connected Elements ===============");

		List<String> destinations;
		Object[] keys; //keys for the source
		Object[] targetKeys; //keys for the target
		UUID targetUUID;
		ResultSet rs;
		Row row;
		//information gathered from select to be used in update
		UUID sourceId;
		String sourceSite;
		String sourceSub;
		//information gathered from Select to be used in the Update statement and populates the connected_elements column
		String destination_id;
  	
		BoundStatement bound_update;
		
		//populates each source with all its connections in the hardware table
		for (String source: connectedElementsMap.keySet()){
			destinations = connectedElementsMap.get(source);

			//keys for the source. If the source IP was not in the table, it was inserted and its keys are returned
			keys = getKeys(source);
			System.out.println("Source: " +source);
			
			//double checks that the ip as a key
			//if there is not a first key, there will not be any keys (and all are needed)
			if (keys[0] == null){
				insertIp(source);
				keys = getKeys(source);
			}
			//assigning keys for the source
			sourceId = (UUID) keys[0];
			sourceSite = (String) keys[1];
			sourceSub = (String) keys[2];
			
			//for each source's targets, the target's Id are retrieved for the connected_elements user-data type
			//and placed into the source's connected_elements column. 
			for(String target : destinations){
				//get the UUID for the target
				targetKeys = getKeys(target);
				
				//double checks that the target as a key
				if (targetKeys[0] == null){
					insertIp(target);
					targetKeys = getKeys(target);
				}
				//only the UUID is needed
				targetUUID = (UUID) targetKeys[0];
				
				//change to a String because data type in the database is a string		
				destination_id = targetUUID.toString();
				
				//query and prepared statement are within the loop because Cassandra does not support binding list literals (which includes connected_elements)
				String query_update = "UPDATE hardware SET "
		  			+ "connected_elements = connected_elements + "
		  			+" [{destination_id: '"+ destination_id +"', mission_support: []}]"
		  			+ " WHERE internal_system_id = ? AND  site_or_ou_name = ? AND ip_subnet_or_building = ?";
				PreparedStatement prepared_update = session.prepare(query_update);
				//updates the hardware table with another entry
				bound_update = prepared_update.bind(sourceId, sourceSite, sourceSub);
				session.execute(bound_update);
				
				System.out.println("Inserted connected_elements");
			
			}
		}
	}
	//This method assigns the site to each new entry
	public void getSite(){
		//currently gets only the first row of the table and uses its site_id
		//This will need to be changed later. 
		String query = "SELECT * FROM sites LIMIT 1";
		PreparedStatement prepared = session.prepare(query);
		BoundStatement bound = prepared.bind();
		ResultSet rs = session.execute(bound);
		
		Row row =rs.one();
		
		site = row.getUUID("site_id").toString();
		
	}
	
	//inserts a new ip into the hardware table with keys and importDate 
	public void insertIp(String ip){
		
		BoundStatement bound_insert;
		ResultSet rs;
		int dot2;
		
		//gets the site from the sites table
		getSite();
		
		//finds the first 2 octets of the ip
		dot2 = StringUtils.ordinalIndexOf(ip, ".", 2);
		String subNet = ip.substring(0,dot2); 
		
		bound_insert = prepared_insertHopIp.bind(ip, site, subNet);
		//inserts the new ip with an import_date, internal_system_id, site_or_ou_name, and ip_subnet_or_building
		rs = session.execute(bound_insert);
	}
	
	//Given an ip_address, its keys are returned in an object array. 
	public Object[] getKeys(String ip){
		Object[] keys = new Object[3];
		ResultSet rs;
		List<Row> row;
		bound_keys = prepared_keys.bind(ip);
		rs = session.execute(bound_keys);
		row = rs.all();
		//if there are no keys for the ip_address one is inserted
		if (row == null){
			System.out.println("Inserting: " + ip);
			insertIp(ip);
			bound_keys = prepared_keys.bind(ip);
			rs = session.execute(bound_keys);
			row = rs.all();
		}
		//captures all rows in a resultset but only one is expected. 
		Iterator<Row> it = row.iterator();
		while (it.hasNext()){
			Row result = it.next();
			//assigns a key to each index of an array
			keys[0] = result.getUUID("internal_system_id");
			System.out.println("ID: " +keys[0]);
			keys[1] = result.getString("site_or_ou_name");
			System.out.println("Site: " + keys [1]);
			keys[2] = result.getString("ip_subnet_or_building");
			System.out.println("Sunb: " + keys[2]);
		}
		//double checks if a key was retrieved. Not sure if this helps
		if (keys[0] == null){
			insertIp(ip);
			getKeys(ip);
		}
		
		return keys;
	}
	
	//updates the cvss_scores in the hardware table
	public void updateCvssScores(){
		//data elements that are captured per host and updated into the database.
		String ip;
		String cveID;
		double baseScore;
		double tempScore;
		String description;
		String vulnPub;
		String patchPub;
		String solution;
		List<ReportItem> items;
		//variables assigned to the keys for each host
		Object[] keys;
		UUID hostId;
		String hostSite;
		String hostSub;
		
		PreparedStatement prepared_addCvss;
		BoundStatement bound_addCvss;
		
		System.out.println("======== UPDATE CVSS SCORE ========");
		//updates the cvss_scores column with vulnerabilities for each host
		for (ReportHost host: hostList){
			//list of vulnerabilities
			items = host.getReportItems(); 
			//gets the keys for each host
			ip = host.getIpAddress();
			keys = getKeys(ip);
			
			//double checks that the ip as a key
			//if there is not a first key, there will not be any keys (and all are needed)
			if(keys[0] == null){
				insertIp(ip);
				keys = getKeys(ip);
			}
			hostId = (UUID) keys[0];
			hostSite = (String) keys[1];
			hostSub = (String) keys[2];
			
			//inserts each vulnerability for each host 
			//items are ReportItems that contain a cveID 
			for (ReportItem item : items){
				String s = "#";
				cveID = item.getCveId();
				baseScore = item.getBaseScore();
				tempScore = item.getTempScore();
				description = item.getDescription();
				vulnPub = item.getVulPublicationDate();
				patchPub = item.getPatchPublicationDate();
				solution = item.getSolution();					
				
				//query and prepared statement are included in the for loop because Cassandra does not allow binding of list literals (which includes the user-type cvss_scores)
				String query_addCvss = "UPDATE hardware SET cvss_scores = cvss_scores + [{cve_id: " + cveID + ", cvss_base_score: " + baseScore+ ", cvss_temporal_score: "+ tempScore+ ", iiv_score: null, "
						+ "cve_description: " + description + ", vuln_publication_date: " + vulnPub + ", patch_publication_date: " + patchPub + ", solution: " + solution+ "}] "
								+ " WHERE internal_system_id = ? and site_or_ou_name = ? and ip_subnet_or_building = ? ;";
				prepared_addCvss = session.prepare(query_addCvss);
				//updates the cvss_scores column in the hardware table with another item.
				bound_addCvss = prepared_addCvss.bind(hostId, hostSite, hostSub);
				session.execute(bound_addCvss);
				
			}
		}
		System.out.println("Updated Cvss Scores.");		
	}
	
	//this method is used to update the hardware table with information taken from each host. 
	public void update(){
		
		System.out.println("======== UPDATE GENERAL ========");
		
		String query_update = "UPDATE hardware "
				+ "SET host_name = ?, " //+ name
				+ " ip_address = ?, "// + ip
				+ " mac_address = ?, "// + mac
				+ " operating_system = ? , "// +operatingSystem
				+ " os_general = ?, "// + os
				+ " vendor = ?, " //+ vendor
				+ " vulnerability_count = ?, "// + count 
				+ " system_type = ?, " //+ systemType 
				+ " run_date = ?, " //+runDate
				+ " import_date = toDate(now()) "
				+ " WHERE internal_system_id = ? and site_or_ou_name = ? and ip_subnet_or_building = ? "; //+ count;
		
		PreparedStatement prepared = session.prepare(query_update);
		
		for (ReportHost host : hostList){
			String name = host.getHost();
			String ip = host.getIpAddress();
			String mac = host.getMacAddress();
			String operatingSystem = host.getOperatingSystem();
			String os = host.getOs();
			String vendor = host.getVendor();
			int count = host.getVulnerabilityCount();
			String systemType = host.getSystemType();
			LocalDate runDate = host.getRunDate(); //LocalDate needed for the Cassandra date data type entry 
			
			//getting the keys for each ip
			Object[] keys = getKeys(ip);
			if (keys[0] == null){
				insertIp(ip);
				keys = getKeys(ip);
			}
			UUID hostId = (UUID) keys[0];
			String hostSite = (String) keys[1];
			String hostSub = (String) keys[2];
			
			BoundStatement bound = prepared.bind(name, ip, mac, operatingSystem, os, vendor, count, systemType, runDate, hostId, hostSite, hostSub); //count after vendor
			session.execute(bound);

		}//for host end
		System.out.println("Done with General Update");
	}//update() end
	
	//if this method is ran separately (without update() or adding the cvss scores or connected elements, it gives the right count. 
	//if it runs after these methods, then the vulnerability count will be a multiple of what it should be. 
	//currently it is not included when the information is saved to the database. 
	public void vulnerabilityCount(){
		
		String vulnerability_query = "UPDATE hardware SET vulnerability_count = ? WHERE internal_system_id = ? and site_or_ou_name = ? and ip_subnet_or_building = ?";
		PreparedStatement prepared = session.prepare(vulnerability_query);
		for (ReportHost host: hostList){
			String ip = host.getIpAddress();
			int count = host.getVulnerabilityCount();
			
			Object[] keys = getKeys(ip);
			if (keys[0] == null){
				insertIp(ip);
				keys = getKeys(ip);
			}
			UUID hostId = (UUID) keys[0];
			String hostSite = (String) keys[1];
			String hostSub = (String) keys[2];
			
		System.out.println("Vulnerability Count: " + count+ " for IP Address: " + ip + " Internal_system_id: " + hostId + " Site_or_ou_name: " + hostSite + " Sub: " + hostSub);
		BoundStatement bound = prepared.bind(count, hostId, hostSite, hostSub);
		session.execute(bound);
		}
	}
	
}
