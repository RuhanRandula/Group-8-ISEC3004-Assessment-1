/*
 * FILE: path_traversal_demo/src/FileViewerMitigated.java
 *
 * ISEC3004 Assignment 1 - Path Traversal Mitigation (CWE-22)
 *
 * REASONING AND PURPOSE:
 *
 * This application simulates a document viewer that allows users to
 * read files stored inside the intended documents directory.
 *
 * MITIGATION:
 *
 * Following the IDS02-J technique described in Lab 7, the requested
 * path is canonicalised before it is opened. The canonical path is
 * checked against the canonical base directory to ensure that the
 * requested file remains inside the permitted directory.
 *
 * If the resolved path falls outside the permitted directory, access
 * is denied and a security message is logged.
 *
 * REFERENCES:
 *
 * - ISEC3004 Assignment 1: Path Traversal
 * - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 * - ISEC3004 Lecture 7 / Lab 7
 * - IDS02-J: Canonicalise path names before validating them
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Scanner;

public class FileViewerMitigated {

    /*
     * Defines the intended directory from which users may read files.
     */
    private static final String BASE_DIR =
            new File("documents").getAbsolutePath()
            + File.separator;

    public static void main(String[] args) {

        /*
         * Read the requested filename from the console.
         */
        try (Scanner scanner = new Scanner(System.in)) {

            System.out.println("======================================");
            System.out.println("   Student Document Viewer");
            System.out.println("   Path Traversal Mitigation Demo");
            System.out.println("======================================");

            System.out.print("Enter filename: ");
            String fileName = scanner.nextLine();

            /*
             * Record the filename for security testing and tracing.
             */
            System.out.println("[LOG] Requested file: " + fileName);

            /*
             * Construct the requested path.
             *
             * The input is not trusted. It must be canonicalised
             * and validated before the application opens the file.
             */
            File file = new File(BASE_DIR + fileName);

            /*
             * FIX (IDS02-J):
             *
             * Canonicalise the requested path and base directory.
             * Canonicalisation resolves path components such as ".."
             * and resolves symbolic links where applicable.
             */
            String canonicalPath = file.getCanonicalPath();

            String canonicalBase =
                    new File(BASE_DIR).getCanonicalPath();

            /*
             * VALIDATION:
             *
             * Confirm that the canonical requested path begins with
             * the canonical base directory followed by a separator.
             *
             * Adding the separator prevents sibling directories
             * whose names merely share the same prefix from passing
             * this check.
             *
             * Only open the file if validation succeeds.
             */
            if (!canonicalPath.startsWith(
                    canonicalBase + File.separator)) {

                System.out.println(
                        "[SECURITY] Access denied - path traversal "
                        + "attempt detected for input: " + fileName);

                return;
            }

            /*
             * Check that the requested path identifies an existing
             * regular file before attempting to read its contents.
             */
            File validatedFile = new File(canonicalPath);

            if (!validatedFile.exists() || !validatedFile.isFile()) {
                System.out.println("File not found.");
                return;
            }

            /*
             * The file is opened only after canonicalisation and
             * containment validation have succeeded.
             */
            try (BufferedReader reader =
                         new BufferedReader(
                                 new FileReader(canonicalPath))) {

                String line;

                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }

        } catch (IOException e) {

            /*
             * Handle file-access errors without allowing the program
             * to terminate unexpectedly.
             */
            System.out.println(
                    "Error reading file: " + e.getMessage());
        }
    }
}
