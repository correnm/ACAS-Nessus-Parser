package src.com.g2.nessus;

import java.io.*;
import java.util.*;

public class loadVendorsCSV {
    public static HashMap<String, String> map = new HashMap<String, String>();
	public static String defaultVendorFile = ".\\import\\parser-data\\vendors.csv";
	public static Scanner scanner = null;
	public static boolean loadStatus = false;
	
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
	    		System.out.println(key);
	    	} // end DEBUGGING
	    	
	    	// close all open resources to avoid compiler warning
		    if (scanner != null)
		    	scanner.close();
		    
		    // Got here without an exception. All good.
		    loadStatus = true;
		    return loadStatus;
		} // end vendorMap
		
		public HashMap<String,String> getVendorMap() {
			return map;
		}
		
		public static void main(String[] args) throws Exception {
			boolean loadStatus;
			
			String errorMessage = null;
			
			try {
				loadStatus = vendorMap();
				if (loadStatus)
					errorMessage = "Vendor file loaded successfully.";
		    } 
		    catch (FileNotFoundException e) {
		    	errorMessage = e.getMessage();
		    } 
		    catch (java.io.IOException e) {
		    	errorMessage = e.getMessage();
		    }
			finally {
				System.out.println("********* Load Status **********");
				System.out.println(errorMessage);
			}
		} // end main

} // end class