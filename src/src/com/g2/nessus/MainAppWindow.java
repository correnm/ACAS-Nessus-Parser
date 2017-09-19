package src.com.g2.nessus;

/**
 * @author Corren McCoy G2 Ops, Virginia Beach, VA
 * 
 * @purpose This class creates the graphic user interface for the parser. 
 * The user is able to upload nessus files, parse the information, display select information 
 * on the interface, save output csv files from Magic Draw, as well as save information to 
 * a common database. 
 * 
 * Modification History
 * June 2017	sara.prokop		enabled parsing and saving capabilities
 * 18-Sept-2017 
 */

import src.com.g2.nessus.*;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.FileDialog;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Graphics;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.LayoutManager;
import java.awt.Panel;
import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;

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
import javax.swing.plaf.ProgressBarUI;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.xml.parsers.ParserConfigurationException;

import org.json.simple.JSONObject;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import com.opencsv.CSVReader;



import javax.swing.event.MenuKeyEvent;
import javax.swing.KeyStroke;
import javax.swing.RowFilter;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.GroupLayout;
import javax.swing.ImageIcon;
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
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.WindowConstants;


public class MainAppWindow extends JFrame {
Container window = getContentPane();
	private JMenuItem	Open;
	private JMenuItem	Save;
	private JMenuItem	Exit;
	public static String magicDrawImportSpreadsheet = "importSpreadsheet.csv"; //public static String magicDrawImportSpreadsheet = "./export/importSpreadsheet.csv";
	public static String magicDrawConnectorEnds = "connector-ends.csv";//public static String magicDrawConnectorEnds = "./export/connector-ends.csv";
	public static String magicDrawSrvProPorts = "host-ports.csv";
	public static String USER_GUIDE = "ACAS_Nessus_Parser_User_Guide.pdf";

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
	    window.revalidate();
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
		JTextField searchField = new JTextField(20);
		JButton revert = new JButton("All Results");
		
		
		searchField.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent evt) {
				String text = searchField.getText().toLowerCase();
				getData(nessus, text);
			}
		});
		revert.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent evt){
				getData(nessus,"");
			}
		});
		
		searchArea.add(searchlabel);
		searchArea.add(searchField);
		searchArea.add(revert);
			
		Box singlelineFields = Box.createVerticalBox();
		singlelineFields.add(searchArea);
		JPanel searchPanel = new JPanel();
		searchPanel.add(singlelineFields);
			
		window.add(searchPanel, BorderLayout.PAGE_START);
	}

	private void showBar(JFrame frame){
		//Create and set up the window.
        

        //Create and set up the content pane.
        JComponent newContentPane = new JPanel();
        JProgressBar progressBar = new JProgressBar();
	     progressBar.setIndeterminate(true);
	     progressBar.setStringPainted(true);
	    frame.add(progressBar,BorderLayout.PAGE_START );
	    frame.setLocationRelativeTo(null);

        frame.setContentPane(newContentPane);

        //Display the window.
        frame.setVisible(true);
	}
	
	
	
	
	
	
	
	private void openFiles() throws SAXParseException{

		JFileChooser fileChooser = new JFileChooser(); 
		fileChooser.setMultiSelectionEnabled(true);
		int result = fileChooser.showOpenDialog(null); //(contentPane)
		
		if (result == JFileChooser.APPROVE_OPTION) {
		    // user selects a file
			 File[] selectedFiles = fileChooser.getSelectedFiles();
	
			 JFrame frame = new JFrame("Loading");
			 frame.setSize(500,10);
			 frame.setVisible(true);
			 frame.setLocationRelativeTo(null);
//			 showBar(frame);

			 window.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			 frame.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			 
			 //table is created depending on the selected nessus files 
			 parseNessus nessus = new parseNessus();
				try {
					try {
						nessus.startParser(selectedFiles);
					} catch (SAXException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				window.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
				} catch (IOException e) {
					e.printStackTrace();
				} catch (ParserConfigurationException e) {
					e.printStackTrace();
				} 
				
			getData(nessus, "");
			frame.dispose();
		}	
	}
	//@SuppressWarnings("deprecation")
	private void saveFile() throws FileNotFoundException{

		String cEfileName;
		String iSfileName;
		String hpFileName;
		String delimiter;
		
		JOptionPane confirm = new JOptionPane();
		String saveToDirectory;
		JFileChooser saveFiles = new JFileChooser();
		saveFiles.setDialogTitle("Save: Select a Directory");
		saveFiles.setApproveButtonText("Save");
		
		//Tells the user that the files will be saved as a .csv
		FileNameExtensionFilter filter = new FileNameExtensionFilter("CSV files", ".csv");
		saveFiles.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		saveFiles. setAcceptAllFileFilterUsed(false);
		saveFiles.setFileFilter(filter);
		
		int userSelection = saveFiles.showOpenDialog(null);
		if (userSelection ==JFileChooser.APPROVE_OPTION){
			File folder = saveFiles.getSelectedFile();
			saveToDirectory = folder.getAbsolutePath();
			delimiter = File.separator;
			cEfileName = saveToDirectory + delimiter+ magicDrawConnectorEnds;
			iSfileName = saveToDirectory + delimiter+magicDrawImportSpreadsheet;
			hpFileName = saveToDirectory + delimiter+magicDrawSrvProPorts;

				parseNessus.writeMagicDrawCsvFile(iSfileName);
				parseNessus.writeConnectorEndsCsvFile(cEfileName);
				parseNessus.writeMagicDrawHostPorts(hpFileName);

			parseNessus.showSaveConfirmation(saveToDirectory, window);
			System.out.println("Save as file: " + folder.getAbsolutePath());
		}
		
	}
	
	public void selectDataFile(){
		String instructions = "<html><h3><b>Update oui.csv MAC Address look-up:</b></h3><br>1. Click on the link below.<br>2. Download (as CSV) MAC Address Block Large(MA-L) to the same file location as this NessusParser executable.<br>"
				+ "<h4>This may take a couple of minutes due to the size of the file.</h4></html>";
		String url = "https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries";
		String link = "<html><FONT color = \"#000099\"> <U>IEEE STANDARDS ASSOCIATION: Registration Authority</U></FONT></html>";

		JLabel inst = new JLabel (instructions);
		JLabel hyperlink = new JLabel(link);
		
		GridBagConstraints c = new GridBagConstraints();
		JFrame frame = new JFrame("Update oui.csv");
		
		frame.setLayout(new GridBagLayout());
		//set to fixed size because it becomes deformed if disproportionate. 
		frame.setSize(750, 300); //good for both mac and windows
		frame.setResizable(false);
		frame.setLocationRelativeTo(null);
		
		hyperlink.setCursor(new Cursor(Cursor.HAND_CURSOR));
		hyperlink.setToolTipText(url);
		hyperlink.addMouseListener(new MouseAdapter(){
			public void mouseClicked(MouseEvent e){
				try{
					Desktop.getDesktop().browse(new URI(url));
				}catch(URISyntaxException| IOException ex){
					ex.printStackTrace();
				}
			}
		});
		
		//arranging Layout of the frame
		c.gridx = 0;
	    c.gridy = 0;
		c.ipadx = 2;
		c.anchor = GridBagConstraints.FIRST_LINE_START;
	    frame.add(inst,c);

	    c.anchor = GridBagConstraints.CENTER;
	    c.gridy= 1;
	    frame.add(hyperlink, c);

	    frame.setVisible(true);

	}
	
	public void showAbout(){
		JFrame frame = new JFrame("About");
		String url = "http://www.g2-ops.com/home/";
		frame.setLayout(new GridBagLayout());
		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		frame.setSize(500, 300);
		frame.setResizable(false);
		frame.setLocationRelativeTo(null);
		
		JLabel logo = new JLabel(new ImageIcon("./images/logo.png"));
		JLabel appInfo = new JLabel ("<html><h3><span style =\"background-color:= #FFFFFF\">Nessus Parser 1.0</b><BR>@ 2017 G2 Ops</span></h3></html>");
		JLabel moreInfo = new JLabel("<html><h4>For more information about G2 Ops' products and services, visit our website: <h4></html>");
		JLabel site = new JLabel ("<html><FONT color = \"#000099\"> <U>www.g2-ops.com</U></FONT></html>");

		JPanel about = new JPanel();
	    about.setSize(800, 250); //511,298
	    about.setBorder(BorderFactory.createLoweredBevelBorder());
	    about.setLayout(new GridBagLayout());
	    
		GridBagConstraints c = new GridBagConstraints();
		
		site.setCursor( new Cursor(Cursor.HAND_CURSOR));
		site.setToolTipText(url);
		site.addMouseListener(new MouseAdapter(){
			public void mouseClicked(MouseEvent e){
				try{
					Desktop.getDesktop().browse(new URI(url));
				}catch(URISyntaxException| IOException ex){
					
				}
			}
		});
		
		c.gridx = 0;
		c.gridy = 0;

		c.fill = GridBagConstraints.HORIZONTAL;
	    c.anchor = GridBagConstraints.FIRST_LINE_START;
	    frame.add(logo,c);
	   
	    c.gridy = 1;
	    frame.add(appInfo, c);
		
	    c.gridx = 0;
	    c.gridy =0;
	    c.ipadx = 2;
	    c.anchor = GridBagConstraints.FIRST_LINE_START;
		about.add(moreInfo, c);

		c.ipady = 70;
		c.anchor = GridBagConstraints.PAGE_START;
		about.add(site,c);
		
		c.gridy = 2;
		c.ipady = 0;
		c.gridwidth = 3;
		c.gridheight = 2;
		frame.add(about,c);
		
		frame.setVisible(true);
		
	}
	
	public void openUserGuide(){
		String userGuideFileName;

		try{
			
			//gets file of the parser, then finds and opens the user guide in the same file location
			File locate = new File(parseNessus.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
			String path = locate.getAbsolutePath();
			String file = locate.getName();
			System.out.println("File: " + file);
			userGuideFileName = path.replace(file, "") + USER_GUIDE ;
		    
			System.out.println("userGuideFileName: "+ userGuideFileName);
			
			//opening file
			File userGuide = new File(userGuideFileName);


		    Desktop desktop = Desktop.getDesktop();

		    desktop.open(userGuide);
		    			 
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e){
			parseNessus.showFileNotFound(USER_GUIDE, "");
		}catch (UnsupportedOperationException e){
			JFrame frame = new JFrame();
			JOptionPane.showMessageDialog(frame,"Platform is not supported to open User Guide file" , 
					"UnsupportedOperationException Found", JOptionPane.WARNING_MESSAGE);
		}
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
				try {
					openFiles();
				} catch (SAXParseException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		mntmOpen.setToolTipText("Select the input Nessus file(s)");
		mntmOpen.setMnemonic(KeyEvent.VK_O);
		mnFile.add(mntmOpen);
		
		
		//FILE>SAVE RESULTS
		JMenu mnSaveResults = new JMenu("Save Results");
		mnFile.add(mnSaveResults);
		
		//FILE>SAVE RESULTS>MBSE CSV IMPORT
		JMenuItem mntmMbseCsvImport = new JMenuItem("MBSE CSV Import");
		mntmMbseCsvImport.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e){
				try {
					saveFile();
				} catch (FileNotFoundException e1) {
					JOptionPane fileNotFound = new JOptionPane();
					JOptionPane.showMessageDialog(fileNotFound,
						    "An Output spreadsheet cannot be accessed because it is currently being used by another process.",
						    "CANNOT ACCESS FILE" + magicDrawSrvProPorts,
						    JOptionPane.WARNING_MESSAGE);
				}//saving output spreadsheets
			}
		});
		mntmMbseCsvImport.setToolTipText("Select the output directory");
		mnSaveResults.add(mntmMbseCsvImport);
		
		//FILE>SAVE RESULTS>CASSANDRA DATABASE
		JMenuItem mntmCassandraDatabase = new JMenuItem("Cassandra Database");
		mntmCassandraDatabase.setToolTipText("Select the output database");
		mntmCassandraDatabase.addActionListener(new ActionListener() { 
			public void actionPerformed(ActionEvent e) {
				parseNessus.savetoCassandra();
			}
		});
		mnSaveResults.add(mntmCassandraDatabase);
		
		//TOOLS
		JMenu mnTools = new JMenu("Tools");
		// Set the menu shortcut to use with Alt-
		mnTools.setMnemonic(KeyEvent.VK_T);
		menuBar.add(mnTools);
		
		//TOOLS>UPDATE MAC ADDRESSES
		JMenuItem mntmParserData = new JMenuItem("Update MAC Address Data");
		mntmParserData.addActionListener(new ActionListener() { 
			public void actionPerformed(ActionEvent e) {
				selectDataFile();
			}
		});
		mntmParserData.setToolTipText("Upload a new oui.csv for MAC Address look-up");
		mntmParserData.setMnemonic(KeyEvent.VK_O);
		mnTools.add(mntmParserData);
		
		//TOOLS>TDB
//		JMenuItem mntmTbd = new JMenuItem("TBD");
//		mnTools.add(mntmTbd);
		
		//HELP
		JMenu mnHelp = new JMenu("Help");
		// Set the menu shortcut to use with Alt-
		mnHelp.setMnemonic(KeyEvent.VK_H);
		menuBar.add(mnHelp);
		
		//HELP>USER'S GUIDE
		JMenuItem mntmUsersGuide = new JMenuItem("User's Guide");
		mntmUsersGuide.addActionListener(new ActionListener() { 
			public void actionPerformed(ActionEvent e) {
				openUserGuide();
			}
		});
		mnHelp.add(mntmUsersGuide);
		
		//HELP>ABOUT
		JMenuItem mntmAbout = new JMenuItem("About");
		mnHelp.add(mntmAbout);
		mntmAbout.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				showAbout();
			}
		});
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



