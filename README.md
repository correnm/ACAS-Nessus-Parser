# ACAS-Nessus-Parser
**Developer:**  Corren McCoy, corren.mccoy@g2-ops.com

**Location:**   G2 Ops, Virginia Beach, VA
- **Purpose**
  - The ACAS-Nessus-Parser is a Java-based utility program designed to extract report items for a .nessus file which is provided in XML format.
- **Functions**
  - The following capabilities are supported by this utility program. Specifically, the parser will:
    - Parse the XML output from supported network discovery into components and associated attributes
    - Correlate a given Mac address with the OUI vendor
	- Match the OUI vendor to MagicDraw master vendor list, if possible
	- Output a formatted CSV file suitable for import into MagicDraw
- **Development Environment for Windows and Mac PCs**
  - Java SE Development Kit (JDK 8u102)
    - Download: http://www.oracle.com/technetwork/java/javase/downloads/index-jsp-138363.html
  - Eclipse IDE (Neon) for Java Developers
  - Download: http://www.eclipse.org/downloads/packages/eclipse-ide-java-developers/keplersr1
- Eclipse Marketplace solutions available within the IDE or
  - Download: https://www.eclipse.org/projects/
  - e(fx)clipse 2.1.0
    - Description: e(fx)clipse provides tooling and runtime components that help developers to create JavaFX applications.
    - Documentation: https://wiki.eclipse.org/Efxclipse
  - Egit - Git Team Provider 4.5.0
    - Description: EGit is an Eclipse Team provider for Git. Git is a distributed SCM, which means every developer has a full copy of all history of every revision of the code, making queries against the history very fast and versatile. The EGit project is implementing Eclipse tooling for the JGit (https://projects.eclipse.org/projects/technology.jgit/) Java implementation of Git.
    -  Documentation: http://wiki.eclipse.org/EGit/User_Guide
- GitHub Desktop for Mac and Windows
  - Download https://desktop.github.com/
  - Documentation https://help.github.com/desktop/