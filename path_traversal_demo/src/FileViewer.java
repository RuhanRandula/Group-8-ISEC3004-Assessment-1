import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Scanner;

/*
 * ISEC3004 Assignment 1 - Path Traversal (CWE-22)
 *
 * This application simulates a document viewer.
 *
 * The filename entered by the user is added to BASE_DIR
 * without checking whether the final path stays inside documents.
 */
public class FileViewer {

    private static final String BASE_DIR =
            new File("..").getAbsolutePath()
            + File.separator
            + "documents"
            + File.separator;

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.println("======================================");
        System.out.println("   Student Document Viewer");
        System.out.println("   ISEC3004 Path Traversal Demo");
        System.out.println("======================================");

        System.out.print("Enter filename: ");
        String fileName = scanner.nextLine();

        System.out.println("[LOG] Requested file: " + fileName);

        // Vulnerable: user input is added directly to BASE_DIR.
        File file = new File(BASE_DIR + fileName);

        try (BufferedReader reader =
                     new BufferedReader(new FileReader(file))) {

            String line;

            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        }

        scanner.close();
    }
}
