/*
 * ISEC3004 Assignment 1 - Path Traversal (CWE-22).
 * This version uses canonical path validation to prevent path traversal.
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
import java.nio.file.Path;

public class StudentPortalServerMitigated {

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

        server.createContext("/", StudentPortalServerMitigated::serveWebsite);
        server.createContext("/api/document", StudentPortalServerMitigated::viewDocument);
        server.createContext("/api/download", StudentPortalServerMitigated::downloadFile);
        server.createContext("/api/resource", StudentPortalServerMitigated::viewResource);
        server.createContext("/api/report", StudentPortalServerMitigated::viewReport);
        server.createContext("/api/attachment", StudentPortalServerMitigated::viewAttachment);

        System.out.println("==========================================");
        System.out.println("   CCSEP STUDENT PORTAL - MITIGATED");
        System.out.println("==========================================");
        System.out.println("Server running at:");
        System.out.println("http://localhost:" + PORT);
        System.out.println("Path Traversal mitigation server");
        System.out.println("Press Ctrl+C to stop.");
        System.out.println("==========================================");

        server.start();
    }

    /* Serves website files only when their paths stay inside the web directory. */
    private static void serveWebsite(HttpExchange exchange)
            throws IOException {
        String requestPath = exchange.getRequestURI().getPath();

        if (requestPath.equals("/")) {
            requestPath = "/index.html";
        }

        File webRoot = new File(DEMO_ROOT, "web");
        File requestedFile = resolveSafeFile(webRoot, requestPath.substring(1));

        if (requestedFile == null
                || !requestedFile.exists()
                || !requestedFile.isFile()) {
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

    /* Resolves and displays a document safely. */
    private static void viewDocument(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");
        System.out.println("[DOCUMENT VIEW] Requested file: " + fileName);

        File requestedFile = resolveSafeFile(DOCUMENTS_DIR, fileName);

        if (requestedFile == null) {
            sendResponse(exchange, 403, "Access denied.");
            return;
        }

        readAndDisplayFile(exchange, requestedFile);
    }

    /* Resolves and downloads a file safely. */
    private static void downloadFile(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");
        System.out.println("[DOWNLOAD] Requested file: " + fileName);

        File requestedFile = resolveSafeFile(DOWNLOADS_DIR, fileName);

        if (requestedFile == null) {
            sendResponse(exchange, 403, "Access denied.");
            return;
        }

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

    /* Resolves and displays a resource safely. */
    private static void viewResource(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");
        System.out.println("[RESOURCE] Requested file: " + fileName);

        File resourceDirectory = new File(DEMO_ROOT, "resources");
        File requestedFile = resolveSafeFile(resourceDirectory, fileName);

        if (requestedFile == null) {
            sendResponse(exchange, 403, "Access denied.");
            return;
        }

        readAndDisplayFile(exchange, requestedFile);
    }

    /* Resolves and displays a report safely. */
    private static void viewReport(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");
        System.out.println("[REPORT] Requested file: " + fileName);

        File reportDirectory = new File(DEMO_ROOT, "reports");
        File requestedFile = resolveSafeFile(reportDirectory, fileName);

        if (requestedFile == null) {
            sendResponse(exchange, 403, "Access denied.");
            return;
        }

        readAndDisplayFile(exchange, requestedFile);
    }

    /* Resolves and displays an attachment safely. */
    private static void viewAttachment(HttpExchange exchange)
            throws IOException {
        String fileName = getParameter(exchange, "file");
        System.out.println("[ATTACHMENT] Requested file: " + fileName);

        File attachmentDirectory = new File(DEMO_ROOT, "attachments");
        File requestedFile = resolveSafeFile(attachmentDirectory, fileName);

        if (requestedFile == null) {
            sendResponse(exchange, 403, "Access denied.");
            return;
        }

        readAndDisplayFile(exchange, requestedFile);
    }

    /*
     * Resolves a requested path and rejects it if it escapes the base directory.
     */
    private static File resolveSafeFile(File baseDirectory, String userPath)
            throws IOException {
        if (userPath == null || userPath.isEmpty()) {
            return null;
        }

        File canonicalBase = baseDirectory.getCanonicalFile();
        File requestedFile = new File(canonicalBase, userPath);
        File canonicalRequested = requestedFile.getCanonicalFile();

        Path basePath = canonicalBase.toPath().normalize();
        Path requestedPath = canonicalRequested.toPath().normalize();

        // Block paths that resolve outside the intended directory.
        if (!requestedPath.startsWith(basePath) || requestedPath.equals(basePath)) {
            System.out.println("[SECURITY] Blocked path traversal attempt: " + userPath);
            return null;
        }

        return canonicalRequested;
    }

    /* Reads and returns an existing file. */
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

    /* Gets and URL-decodes a query parameter. */
    private static String getParameter(HttpExchange exchange, String name) {
        String query = exchange.getRequestURI().getRawQuery();

        if (query == null) {
            return "";
        }

        for (String parameter : query.split("&")) {
            String[] pair = parameter.split("=", 2);

            if (pair.length == 2 && pair[0].equals(name)) {
                return URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
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

    /* Determines the content type from the file extension. */
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
