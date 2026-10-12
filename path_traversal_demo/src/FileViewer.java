/*
 * FILE: path_traversal_demo/src/FileViewer.java
 *
 * ISEC3004 Assignment 1 - Vulnerability 2: Path Traversal (CWE-22)
 *
 * REASONING AND PURPOSE:
 *
 * This application simulates a document-viewing feature in which a
 * user can enter a filename to read a document from the documents
 * directory. The intended security boundary is BASE_DIR, meaning
 * users should only be able to access files stored inside that
 * directory.
 *
 * VULNERABILITY:
 *
 * The filename supplied by the user is concatenated directly onto
 * BASE_DIR without validating or canonicalising the resulting path.
 * Consequently, path traversal sequences such as "../" may allow a
 * user to navigate outside the intended directory and read other
 * files that the Java process has permission to access.
 *
 * SECURITY IMPACT:
 *
 * If successfully exploited, this weakness may expose files outside
 * the intended documents directory, including confidential or
 * internal information. The actual impact depends on the files
 * available and the permissions of the Java process.
 *
 * DETECTION AND TRACING:
 *
 * The request log is deliberately retained to record the filename
 * supplied during each test. This supports the exploitation,
 * detection and tracing activities performed as part of the assignment.
 *
 * ASSIGNMENT REFERENCES:
 *
 * - ISEC3004 Assignment 1: Vulnerability 2 - Path Traversal
 * - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 * - ISEC3004 Lecture 7 / Lab 7: Path Traversal
 * - IDS02-J: Do not trust user input when constructing file paths
 *
 * NOTE:
 *
 * This is intentionally vulnerable demonstration code. It is used to
 * demonstrate the weakness before applying and verifying mitigation.
 */

import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Scanner;

public class FileViewer {

    /*
     * Defines the intended base directory for documents.
     *
     * The absolute path is constructed from the current working
     * directory, and a file separator is appended for path construction.
     *
     * SECURITY LIMITATION:
     *
     * Defining a base directory does not enforce access restrictions.
     * The final resolved path must also be checked to ensure that it
     * remains inside the intended directory.
     */
    private static final String BASE_DIR =
            new File("documents").getAbsolutePath()
            + File.separator;

    public static void main(String[] args) {

        /*
         * Creates a Scanner to read the filename entered by the user.
         * This simulates a user requesting a document from the viewer.
         */
        Scanner scanner = new Scanner(System.in);

        System.out.println("======================================");
        System.out.println("   Student Document Viewer");
        System.out.println("   ISEC3004 Path Traversal Demo");
        System.out.println("======================================");

        System.out.print("Enter filename: ");
        String fileName = scanner.nextLine();

        /*
         * DETECTION AND TRACING:
         *
         * Records the user-supplied filename so that normal requests
         * and suspected traversal attempts can be identified during
         * testing. Logging supports investigation but does not itself
         * prevent unauthorised file access.
         */
        System.out.println("[LOG] Requested file: " + fileName);

        /*
         * VULNERABLE LINE:
         *
         * User-controlled input is appended directly to BASE_DIR.
         * No canonicalisation or containment validation is performed.
         *
         * A traversal sequence such as "../" may cause the resulting
         * path to resolve outside the intended documents directory.
         * This insecure file-path construction demonstrates CWE-22.
         */
        File file = new File(BASE_DIR + fileName);

        /*
         * Attempts to open the requested file for reading.
         *
         * If the path resolves to an accessible file, its contents
         * are displayed in the console. The try-with-resources
         * statement automatically closes the reader when finished.
         */
        try (BufferedReader reader =
                     new BufferedReader(new FileReader(file))) {

            String line;

            /*
             * Reads and displays the requested file one line at a time.
             */
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

        } catch (IOException e) {

            /*
             * Handles file-access errors, such as when the file does
             * not exist or cannot be opened.
             *
             * This error handling does not mitigate path traversal.
             * The requested path must be validated before opening
             * the file to prevent access outside the intended directory.
             */
            System.out.println("Error reading file: " + e.getMessage());
        }

        /*
         * Closes the Scanner after the filename has been processed.
         */
        scanner.close();
    }
}