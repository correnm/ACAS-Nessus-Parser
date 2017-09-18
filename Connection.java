package src.com.g2.nessus;

/*
 * @author: Sara Prokop
 * @date: 8/15/17
 * 
 * @purpose: This class creates a connection pair from source to target. 
 * It is used within the parseNessus to create a list of connections. 
 * This list is used to populate the connected_elements column in the hardware table in the cassandra databse. 
 */

public class Connection<start, end> {
	private start source;
	private end target;
	
	public Connection(){
		
	}
	
	public Connection(start source, end target){
		super();
			this.source = source;
			this.target = target;
	}
	
	public  String toString(){
		return "source: "+source+" target: "+target;
	}
	
	public boolean equals (Object pair2){
		if (pair2 instanceof Connection){
			Connection connection2 = (Connection) pair2;
			
			//checks the memory location of each of the sources and checks that both are not null and they have meaningful equivalent values
			//and then  checks the same for the target.
			return((this.source == connection2.source || (this.source != null && connection2.source != null 
					&& this.source.equals(connection2.source))) 
					&& (this.target == connection2.target || (this.target != null && connection2.target != null 
					&& this.target.equals(connection2.target)))); 
			//returns false if they point to different memory locations or have different meaningful values. 
			//returns true if they point to the same memory location and have the same meaningful values. 
		}
		return false; //default value
	}
	
	//checks for an empty connection- if either the source or the target is missing. 
	public boolean isNull (Object end){
	
		boolean isnull = false;
		
		if(end instanceof Connection){
			Connection connection = (Connection) end;
			String end1 = connection.getSource().toString();
			String end2 = connection.getTarget().toString();
		
		if (end1.equals("")||end2.equals(""))
			isnull = true;
		if ((end1 == null)||(end2 == null))
			isnull = true;
		}

		return isnull;
	}
	
	public void setSource(start source){
		this.source = source;
	}
	public void setTarget(end target){
		this.target = target;
	}
	public start getSource(){
		return source;
	}
	public end getTarget(){
		return this.target;
	}

}
