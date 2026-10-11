/*
 * ISEC3004 Assignment 1 - Path Traversal (CWE-22).
 * This server is intentionally vulnerable for demonstration and testing.
 * Reference: ISEC3004 Lecture 7 / Lab 7, IDS02-J.
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class StudentPortalServer {

    private static final int PORT = 8080;

    private static final File DEMO_ROOT =
            new File("..").getAbsoluteFile();

    private static final File DOCUMENTS_DIR =
            new File(DEMO_ROOT, "documents");

    private static final File DOWNLOADS_DIR =
            new File(DEMO_ROOT, "downloads");

    /* Starts the server and registers the portal endpoints. */
    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(
                new InetSocketAddress(PORT),
                0
        );

        server.createContext("/", StudentPortalServer::serveWebsite);
        server.createContext("/api/document", StudentPortalServer::viewDocument);
        server.createContext("/api/download", StudentPortalServer::downloadFile);
        server.createContext("/api/resource", StudentPortalServer::viewResource);
        server.createContext("/api/report", StudentPortalServer::viewReport);
        server.createContext("/api/attachment", StudentPortalServer::viewAttachment);

        System.out.println("==========================================");
        System.out.println("       CCSEP STUDENT PORTAL SERVER");
        System.out.println("==========================================");
        System.out.println("Server running at:");
        System.out.println("http://localhost:" + PORT);
        System.out.println();
        System.out.println("Path Traversal demonstration server");
        System.out.println("Press Ctrl+C to stop.");
        System.out.println("==========================================");

        server.start();
    }

    /* Serves the portal website files. */
    private static void serveWebsite(HttpExchange exchange)
            throws IOException {
        String requestPath = exchange.getRequestURI().getPath();

        if (requestPath.equals("/")) {
            requestPath = "/index.html";
        }

        File webRoot = new File(DEMO_ROOT, "web");
        File requestedFile = new File(webRoot, requestPath.substring(1));

        if (!requestedFile.exists() || !requestedFile.isFile()) {
            sendResponse(exchange, 404, "Page not found.");
            return;
        }

        String contentType = getContentType(requestedFile);
        byte[] content = Files.readAllBytes(requestedFile.toPath());

        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(200, content.length);

        try (OutputStream output = exchange.getResponseBody()) {
            output.write(content);
        }
    }

    /* Displays a document. The supplied path is not validated. */
    private static void viewDocument(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");

        System.out.println("[DOCUMENT VIEW] Requested file: " + fileName);

        // Vulnerable: the user-supplied path is not validated.
        File requestedFile = new File(DOCUMENTS_DIR, fileName);
        readAndDisplayFile(exchange, requestedFile);
    }

    /* Downloads a file. The supplied path is not validated. */
    private static void downloadFile(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");

        System.out.println("[DOWNLOAD] Requested file: " + fileName);

        // Vulnerable: the final path is not checked.
        File requestedFile = new File(DOWNLOADS_DIR, fileName);

        if (!requestedFile.exists() || !requestedFile.isFile()) {
            sendResponse(exchange, 404, "File not found.");
            return;
        }

        byte[] content = Files.readAllBytes(requestedFile.toPath());

        exchange.getResponseHeaders().set(
                "Content-Type",
                "application/octet-stream"
        );
        exchange.getResponseHeaders().set(
                "Content-Disposition",
                "attachment; filename=\"" + requestedFile.getName() + "\""
        );
        exchange.sendResponseHeaders(200, content.length);

        try (OutputStream output = exchange.getResponseBody()) {
            output.write(content);
        }
    }

    /* Displays a resource. The supplied path is not validated. */
    private static void viewResource(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");

        System.out.println("[RESOURCE] Requested file: " + fileName);

        File resourceDirectory = new File(DEMO_ROOT, "resources");

        // Vulnerable: the resource path is not validated.
        File requestedFile = new File(resourceDirectory, fileName);
        readAndDisplayFile(exchange, requestedFile);
    }

    /* Displays a report. The supplied path is not validated. */
    private static void viewReport(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");

        System.out.println("[REPORT] Requested file: " + fileName);

        File reportDirectory = new File(DEMO_ROOT, "reports");

        // Vulnerable: the report path is not validated.
        File requestedFile = new File(reportDirectory, fileName);
        readAndDisplayFile(exchange, requestedFile);
    }

    /* Displays an attachment. The supplied path is not validated. */
    private static void viewAttachment(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");

        System.out.println("[ATTACHMENT] Requested file: " + fileName);

        File attachmentDirectory = new File(DEMO_ROOT, "attachments");

        // Vulnerable: the attachment path is not validated.
        File requestedFile = new File(attachmentDirectory, fileName);
        readAndDisplayFile(exchange, requestedFile);
    }

    /* Reads an existing file. Existence checks alone do not prevent traversal. */
    private static void readAndDisplayFile(
            HttpExchange exchange,
            File requestedFile) throws IOException {
        if (!requestedFile.exists() || !requestedFile.isFile()) {
            sendResponse(exchange, 404, "File not found.");
            return;
        }

        String content = Files.readString(requestedFile.toPath());
        sendResponse(exchange, 200, content);
    }

    /* Gets and decodes a query parameter. Input must still be validated. */
    private static String getParameter(
            HttpExchange exchange,
            String name) {
        String query = exchange.getRequestURI().getRawQuery();

        if (query == null) {
            return "";
        }

        for (String parameter : query.split("&")) {
            String[] pair = parameter.split("=", 2);

            if (pair.length == 2 && pair[0].equals(name)) {
                return URLDecoder.decode(
                        pair[1],
                        StandardCharsets.UTF_8
                );
            }
        }

        return "";
    }

    /* Sends a text response with an HTTP status code. */
    private static void sendResponse(
            HttpExchange exchange,
            int status,
            String message) throws IOException {
        byte[] content = message.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set(
                "Content-Type",
                "text/plain; charset=UTF-8"
        );
        exchange.sendResponseHeaders(status, content.length);

        try (OutputStream output = exchange.getResponseBody()) {
            output.write(content);
        }
    }

    /* Determines a file content type from its extension. */
    private static String getContentType(File file) {
        String name = file.getName().toLowerCase();

        if (name.endsWith(".html")) {
            return "text/html; charset=UTF-8";
        }

        if (name.endsWith(".css")) {
            return "text/css; charset=UTF-8";
        }

        if (name.endsWith(".js")) {
            return "application/javascript; charset=UTF-8";
        }

        if (name.endsWith(".png")) {
            return "image/png";
        }

        if (name.endsWith(".jpg") || name.endsWith(".jpeg")) {
            return "image/jpeg";
        }

        return "text/plain; charset=UTF-8";
    }
}
