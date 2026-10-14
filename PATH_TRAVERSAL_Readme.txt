StudentPortalServer.java is the vulnerable Java web portal.
StudentPortalServerMitigated.java is the mitigated version.
FileViewer.java / FileViewerMitigated.java are the console equivalents.

IMPORTANT: run these from the src/ folder - the servers look for their data
folders (documents, resources, reports, downloads, attachments, confidential)
one level up, using a relative path.

To run the vulnerable web portal:
1. Open a terminal in path_traversal_demo/src

2. Compile:
   javac *.java

3. Run the vulnerable server:
   java StudentPortalServer

4. Visit http://localhost:8080 in a browser (the login is cosmetic, no
   credentials are checked - you can also go straight to documents.html etc.)

5. On the Documents page, enter this filename to see normal access:
   report.txt

6. Then enter this to exploit the traversal flaw:
   ../confidential/confidential.txt

   The console-based equivalent is:
   java FileViewer
   (then type ../confidential/confidential.txt when prompted)

To run the mitigated version instead:
   Stop the server above, then:
   java StudentPortalServerMitigated
   (or java FileViewerMitigated for the console version)

   Repeat step 6 - the mitigated server responds "Access denied" (HTTP 403)
   and prints a [SECURITY] message in the console instead of returning the file.
