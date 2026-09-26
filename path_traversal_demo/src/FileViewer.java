/*********************************************************************
 * File      : path_traversal_demo/FileViewer.java                   *
 *                                                                   *
 * ISEC3004 Assignment 1 - Vulnerability 2: Path Traversal (CWE-22)  *
 *                                                                   *
 * REASONING:                                                        *
 * Simulates a "view my document" feature. BASE_DIR is meant to be   *
 * the only folder a user can read from. The filename supplied by    *
 * the user is concatenated onto BASE_DIR without validation or      *
 * canonicalisation. A value such as "../secret/confidential.txt"    *
 * can therefore escape BASE_DIR and access files the JVM process    *
 * has permission to open.                                           *
 *                                                                   *
 * Reference: ISEC3004 Lecture 7 / Lab 7, IDS02-J.                   *
 *********************************************************************/

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Scanner;

public class FileViewer {

	/*
     * Base directory where the application expects documents
     * to be stored.
     */
    private static final String BASE_DIR = System.getProperty("user.home")
            + File.separator
            + "Group-8-ISEC3004-Assessment-1"
            + File.separator
            + "path_traversal_demo"
            + File.separator
            + "documents"
            + File.separator;

    public static void main(String[] args) throws IOException {

        Scanner sc = new Scanner(System.in);
        System.out.print("Enter file name to view: ");
        String fileName = sc.nextLine();

        /*
         * [LOG] left in deliberately: Member 4 will use this line
         * as the detection/tracing evidence for the exploit.
         */
        System.out.println("[LOG] Requested file: " + fileName);

        /*
         * VULNERABLE LINE:
         * User input is trusted and concatenated directly into a
         * file system path, with no check that the result still
         * lives inside BASE_DIR.
         */
        File file = new File(BASE_DIR + fileName);

        BufferedReader reader = new BufferedReader(
                new FileReader(file));

        String line;

        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }

        reader.close();
        sc.close();
    }
}