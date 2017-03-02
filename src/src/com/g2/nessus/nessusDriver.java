package src.com.g2.nessus;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class nessusDriver {
  
	   private JFrame mainFrame;
	   private JLabel headerLabel;
	   private JLabel statusLabel;
	   private JPanel controlPanel;

	   public nessusDriver(){
	      prepareGUI();
	   }

	   public static void main(String[] args){
	      nessusDriver nessusDriver = new nessusDriver();      
	      nessusDriver.showFileChooserDemo();
	   }

	   private void prepareGUI(){
	      mainFrame = new JFrame("Nessus File Import");
	      mainFrame.setSize(800,800);
	      mainFrame.setLayout(new GridLayout(3, 1));
	      mainFrame.addWindowListener(new WindowAdapter() {
	         public void windowClosing(WindowEvent windowEvent){
	            System.exit(0);
	         }        
	      });    
	      headerLabel = new JLabel("", JLabel.CENTER);        
	      statusLabel = new JLabel("",JLabel.CENTER);    

	      statusLabel.setSize(350,100);

	      controlPanel = new JPanel();
	      controlPanel.setLayout(new FlowLayout());

	      mainFrame.add(headerLabel);
	      mainFrame.add(controlPanel);
	      mainFrame.add(statusLabel);
	      mainFrame.setVisible(true);  
	   }

	   private void showFileChooserDemo(){
	      headerLabel.setText("Control in action: JFileChooser"); 

	      final JFileChooser  fileDialog = new JFileChooser();
	      JButton showFileDialogButton = new JButton("Open File");
	      showFileDialogButton.addActionListener(new ActionListener() {
	         @Override
	         public void actionPerformed(ActionEvent e) {
	            int returnVal = fileDialog.showOpenDialog(mainFrame);
	            if (returnVal == JFileChooser.APPROVE_OPTION) {
	               java.io.File file = fileDialog.getSelectedFile();
	               statusLabel.setText("File Selected :" 
	               + file.getName());
	            }
	            else{
	               statusLabel.setText("Open command cancelled by user." );           
	            }      
	         }
	      });
	      controlPanel.add(showFileDialogButton);
	      mainFrame.setVisible(true);  
	   }
	}