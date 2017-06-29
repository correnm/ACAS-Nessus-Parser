package src.com.g2.nessus;

import src.com.g2.nessus.*;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.FileDialog;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.Panel;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.awt.event.MouseMotionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.swing.JFrame;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.border.EmptyBorder;
import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.event.MenuKeyListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.xml.parsers.ParserConfigurationException;

import org.json.simple.JSONObject;
import org.xml.sax.SAXException;

import com.opencsv.CSVReader;

import javax.swing.event.MenuKeyEvent;
import javax.swing.KeyStroke;
import javax.swing.RowFilter;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JInternalFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;


public class MainAppWindow extends JFrame {
Container window = getContentPane();
	private JMenuItem	Open;
	private JMenuItem	Save;
	private JMenuItem	Exit;
	public static String magicDrawImportSpreadsheet = "/importSpreadsheet.csv"; //public static String magicDrawImportSpreadsheet = "./export/importSpreadsheet.csv";
	public static String magicDrawConnectorEnds = "/connector-ends.csv";//public static String magicDrawConnectorEnds = "./export/connector-ends.csv";
	public static String magicDrawSrvProPorts = "/host-ports.csv";

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainAppWindow frame = new MainAppWindow();
					// center the initial JFrame on the screen
					frame.setLocationRelativeTo(null);
					makeFrameHalfSize(frame);
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	private static void makeFrameFullSize(JFrame aFrame){
	  // determine the current screen size, then sets the size of the given JFrame with the setSize method.
	  Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
	  aFrame.setSize(screenSize.width, screenSize.height);
	}
	private static void makeFrameHalfSize(JFrame aFrame){
	  // determine the current screen size, then sets the size of the given JFrame with the setSize method.
	  Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
	  aFrame.setSize(screenSize.width/2, screenSize.height/2);
	}
	public void resizeColumnWidth(JTable table) {
	    final TableColumnModel columnModel = table.getColumnModel();
	    for (int column = 0; column < table.getColumnCount(); column++) {
	        int width = 60; // Min width
	        for (int row = 0; row < table.getRowCount(); row++) {
	            TableCellRenderer renderer = table.getCellRenderer(row, column);
	            Component comp = table.prepareRenderer(renderer, row, column);
	            width = Math.max(comp.getPreferredSize().width +1 , width);
	        }
	        if(width > 200)
	            width=200;
	        columnModel.getColumn(column).setPreferredWidth(width);
	    	}
	} 
	
	public void getData(parseNessus nessus, String text){
		//most importantly removes the last table
		window.removeAll();

		String[] colNames = {"host","vendor","macAddress","qualifiedName","IP-Address","O/S","operatingSystem","systemType","FQDN","scanDate","installedSoftware","traceRouteHops", "CVSSBaseScore", "CVSSTemporalScore"};
		Object [][] data = new String [nessus.getHostList().size()][];
		System.out.println("Size: " + nessus.getHostList().size());
		Iterator<ReportHost> it = nessus.getHostList().iterator();
	    ReportHost curHost = new ReportHost();
	    int rowIndex =0;
	    int index = 0;
	    	
	    while (it.hasNext()) {
	    	curHost = it.next();
	    	String[] entries = curHost.toString().split("#");
	    	for (String entry: entries){
	    		if (entry.toLowerCase().contains(text)){
	    			data[rowIndex]= entries;
	    			rowIndex++;
	    			break;
	    		}
	    	}
	    } 
	    //reconstructs the menu bar
	    createMenuBar();
	   
	    //validate() ensures that the menu bar is always enabled. 
	    window.validate();
	    buildSearchArea(nessus);
	    buildTable(data, colNames);
	    
	    //revalidate() ensures everything is enabled after the search	    
	    window.revalidate();
	}
	public void buildTable(Object[][] data, String[] colNames){
	    DefaultTableModel model = new DefaultTableModel(data, colNames);
		JTable table = new JTable(model);
		resizeColumnWidth(table);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		JScrollPane scrollPane = new JScrollPane(table);
		window.add(scrollPane, BorderLayout.CENTER);
		
	}
	public void buildSearchArea(parseNessus nessus){
		Box searchArea= Box.createHorizontalBox();
		JLabel searchlabel = new JLabel("Search: ", JLabel.RIGHT);
		JTextField searchField = new JTextField(30);
		searchField.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent evt) {
				String text = searchField.getText().toLowerCase();
				getData(nessus, text);
			}
		});
		
		searchArea.add(searchlabel);
		searchArea.add(searchField);
			
		Box singlelineFields = Box.createVerticalBox();
		singlelineFields.add(searchArea);
		JPanel searchPanel = new JPanel();
		searchPanel.add(singlelineFields);
			
		window.add(searchPanel, BorderLayout.PAGE_START);
	}
	
	private void openFiles(){

		JFileChooser fileChooser = new JFileChooser(); 
		fileChooser.setMultiSelectionEnabled(true);
		int result = fileChooser.showOpenDialog(null); //(contentPane)
		
		if (result == JFileChooser.APPROVE_OPTION) {
		    // user selects a file
			 File[] selectedFiles = fileChooser.getSelectedFiles();
				
			 window.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			 //table is created depending on the selected nessus files 
			 parseNessus nessus = new parseNessus();
				try {
					nessus.startParser(selectedFiles);
				window.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
				} catch (IOException e) {
					e.printStackTrace();
				} catch (ParserConfigurationException e) {
					e.printStackTrace();
				} catch (SAXException e) {
					e.printStackTrace();
				}
			getData(nessus, "");

		}	
	}
	//@SuppressWarnings("deprecation")
	private void saveFile(){

		String cEfileName;
		String iSfileName;
		String hpFileName;

		JOptionPane confirm = new JOptionPane();
		String saveToDirectory;
		JFileChooser saveFiles = new JFileChooser();
		
		//Tells the user that the files will be saved as a .csv
		FileNameExtensionFilter filter = new FileNameExtensionFilter("CSV file", ".csv");
		saveFiles.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		saveFiles. setAcceptAllFileFilterUsed(false);
		saveFiles.setFileFilter(filter);
		
		int userSelection = saveFiles.showSaveDialog(null);
		if (userSelection ==JFileChooser.APPROVE_OPTION){
			File folder = saveFiles.getSelectedFile();
			saveToDirectory = folder.getAbsolutePath();
			cEfileName = saveToDirectory + magicDrawConnectorEnds;
			iSfileName = saveToDirectory + magicDrawImportSpreadsheet;
			hpFileName = saveToDirectory + magicDrawSrvProPorts;
			
			parseNessus.writeMagicDrawCsvFile(iSfileName); //saving importspreadsheet.csv
			parseNessus.writeConnectorEndsCsvFile(cEfileName);//saving connector-ends.csv
			parseNessus.writeMagicDrawHostPorts(hpFileName);//saving host-ports.csv
			
			parseNessus.showSaveConfirmation(saveToDirectory, window);
			System.out.println("Save as file: " + folder.getAbsolutePath());
		}
		
	}
	
	public void selectDataFile(){
		try {
			URL url = new URL("https://standards.ieee.org/develop/regauth/oui/oui.csv");
		} catch (MalformedURLException e1) {
			e1.printStackTrace();
		}
		
		
		
		
		Frame frame = new Frame();
		Desktop desktop = Desktop.getDesktop();
		FileDialog dialog = new FileDialog(frame, "Select Parser Data File", FileDialog.LOAD);
		dialog.show();
		String fileName = dialog.getDirectory()+dialog.getFile();
		File selectedFile = new File(fileName);
		try {
			desktop.open(selectedFile);
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println(fileName);
	}
		
	public void createMenuBar(){
		// Define the application menu options
		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);
					
		//File
		JMenu mnFile = new JMenu("File");
		// Set the menu shortcut to use with Alt-
		mnFile.setMnemonic(KeyEvent.VK_F);
		menuBar.add(mnFile);
				
		//FILE>Open
		JMenuItem mntmOpen = new JMenuItem("Open");
		mntmOpen.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openFiles();
			}
		});
		mntmOpen.setToolTipText("Select the input Nessus file(s)");
		mntmOpen.setMnemonic(KeyEvent.VK_O);
		mnFile.add(mntmOpen);
		
//		//FILE>UPDATE MAC ADDRESSES
//		JMenuItem mntmParserData = new JMenuItem("Update MAC Address Data");
//		mntmParserData.addActionListener(new ActionListener() { 
//			public void actionPerformed(ActionEvent e) {
//				selectDataFile();
//			}
//		});
//		mntmParserData.setToolTipText("Save an updated version of a parser data file");
//		mntmParserData.setMnemonic(KeyEvent.VK_O);
//		mnFile.add(mntmParserData);
//		
		//FILE>SAVE RESULTS
		JMenu mnSaveResults = new JMenu("Save Results");
		mnFile.add(mnSaveResults);
		
		//FILE>SAVE RESULTS>MBSE CSV IMPORT
		JMenuItem mntmMbseCsvImport = new JMenuItem("MBSE CSV Import");
		mntmMbseCsvImport.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e){
				saveFile();
			}
		});
		mntmMbseCsvImport.setToolTipText("Select the output directory");
		mnSaveResults.add(mntmMbseCsvImport);
		
		//FILE>SAVE RESULTS>CASSANDRA DATABASE
		JMenuItem mntmCassandraDatabase = new JMenuItem("Cassandra Database");
		mntmCassandraDatabase.setToolTipText("Select the output database");
		mnSaveResults.add(mntmCassandraDatabase);
		
		//TOOLS
		JMenu mnTools = new JMenu("Tools");
		// Set the menu shortcut to use with Alt-
		mnTools.setMnemonic(KeyEvent.VK_T);
		menuBar.add(mnTools);
		
		//TOOLS>TDB
		JMenuItem mntmTbd = new JMenuItem("TBD");
		mnTools.add(mntmTbd);
		
		//HELP
		JMenu mnHelp = new JMenu("Help");
		// Set the menu shortcut to use with Alt-
		mnHelp.setMnemonic(KeyEvent.VK_H);
		menuBar.add(mnHelp);
		
		//HELP>USER'S GUIDE
		JMenuItem mntmUsersGuide = new JMenuItem("User's Guide");
		mnHelp.add(mntmUsersGuide);
		
		//HELP>ABOUT
		JMenuItem mntmAbout = new JMenuItem("About");
		mnHelp.add(mntmAbout);
	}
		/**
		 * Create the frame.
		 * @throws IOException 
		 */
		public MainAppWindow()  { 		
			setName("mainApplicationFrame");
			setTitle("G2 Ops: ACAS/NESSUS File Parser");
			
			// Specify an action for the close button
			setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);		
			setBounds(100, 100, 758, 673);

			createMenuBar();
		}
}



