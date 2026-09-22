import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Scanner;

public class FileViewer {

    // Base directory where the application expects documents to be stored.
    private static final String BASE_DIR =
            System.getProperty("user.home")
            + File.separator
            + "path_traversal_demo"
            + File.separator
            + "documents"
            + File.separator;

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter filename: ");
        String fileName = scanner.nextLine();

        // Log the requested filename so Member 4 can use it
        // as evidence when detecting and tracing the exploit.
        System.out.println("[LOG] Requested file: " + fileName);

        /*
         * VULNERABLE CODE:
         * The user-controlled filename is directly appended to BASE_DIR.
         * No validation is performed to prevent "../" or "..\\" sequences.
         * This allows the user to traverse outside the documents directory.
         */
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