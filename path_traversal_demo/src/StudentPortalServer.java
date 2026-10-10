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

public class StudentPortalServer {

    private static final int PORT = 8080;

    private static final File DEMO_ROOT =
            new File("..").getAbsoluteFile();

    private static final File DOCUMENTS_DIR =
            new File(DEMO_ROOT, "documents");

    private static final File DOWNLOADS_DIR =
            new File(DEMO_ROOT, "downloads");

    private static final File CONFIDENTIAL_DIR =
            new File(DEMO_ROOT, "confidential");

    public static void main(String[] args) throws IOException {

        HttpServer server = HttpServer.create(
                new InetSocketAddress(PORT),
                0
        );

        server.createContext("/", StudentPortalServer::serveWebsite);

        server.createContext(
                "/api/document",
                StudentPortalServer::viewDocument
        );

        server.createContext(
                "/api/download",
                StudentPortalServer::downloadFile
        );

        server.createContext(
                "/api/resource",
                StudentPortalServer::viewResource
        );

        server.createContext(
                "/api/report",
                StudentPortalServer::viewReport
        );

        server.createContext(
                "/api/attachment",
                StudentPortalServer::viewAttachment
        );

        System.out.println("==========================================");
        System.out.println("       CCSEP STUDENT PORTAL SERVER");
        System.out.println("==========================================");
        System.out.println("Server running at:");
        System.out.println("http://localhost:" + PORT);
        System.out.println();
        System.out.println("Path Traversal mitigation server");
        System.out.println("Press Ctrl+C to stop.");
        System.out.println("==========================================");

        server.start();
    }

    /*
     * Serves the website files.
     *
     * The requested path is resolved canonically and checked to ensure
     * that it remains inside the web directory.
     */
    private static void serveWebsite(HttpExchange exchange)
            throws IOException {

        String requestPath =
                exchange.getRequestURI().getPath();

        if (requestPath.equals("/")) {
            requestPath = "/index.html";
        }

        File webRoot = new File(DEMO_ROOT, "web");

        File requestedFile =
                resolveSafeFile(webRoot, requestPath.substring(1));

        if (requestedFile == null
                || !requestedFile.exists()
                || !requestedFile.isFile()) {

            sendResponse(
                    exchange,
                    404,
                    "Page not found."
            );

            return;
        }

        String contentType =
                getContentType(requestedFile);

        byte[] content =
                Files.readAllBytes(requestedFile.toPath());

        exchange.getResponseHeaders().set(
                "Content-Type",
                contentType
        );

        exchange.sendResponseHeaders(
                200,
                content.length
        );

        try (OutputStream output =
                     exchange.getResponseBody()) {

            output.write(content);
        }
    }

    /*
     * View a document safely.
     */
    private static void viewDocument(
            HttpExchange exchange)
            throws IOException {

        String fileName =
                getParameter(exchange, "file");

        System.out.println(
                "[DOCUMENT VIEW] Requested file: "
                        + fileName
        );

        File requestedFile =
                resolveSafeFile(DOCUMENTS_DIR, fileName);

        if (requestedFile == null) {
            sendResponse(
                    exchange,
                    403,
                    "Access denied."
            );

            return;
        }

        readAndDisplayFile(exchange, requestedFile);
    }

    /*
     * Download a file safely.
     */
    private static void downloadFile(
            HttpExchange exchange)
            throws IOException {

        String fileName =
                getParameter(exchange, "file");

        System.out.println(
                "[DOWNLOAD] Requested file: "
                        + fileName
        );

        File requestedFile =
                resolveSafeFile(DOWNLOADS_DIR, fileName);

        if (requestedFile == null) {
            sendResponse(
                    exchange,
                    403,
                    "Access denied."
            );

            return;
        }

        if (!requestedFile.exists()
                || !requestedFile.isFile()) {

            sendResponse(
                    exchange,
                    404,
                    "File not found."
            );

            return;
        }

        byte[] content =
                Files.readAllBytes(requestedFile.toPath());

        exchange.getResponseHeaders().set(
                "Content-Type",
                "application/octet-stream"
        );

        exchange.getResponseHeaders().set(
                "Content-Disposition",
                "attachment; filename=\""
                        + requestedFile.getName()
                        + "\""
        );

        exchange.sendResponseHeaders(
                200,
                content.length
        );

        try (OutputStream output =
                     exchange.getResponseBody()) {

            output.write(content);
        }
    }

    /*
     * View a resource safely.
     */
    private static void viewResource(
            HttpExchange exchange)
            throws IOException {

        String fileName =
                getParameter(exchange, "file");

        System.out.println(
                "[RESOURCE] Requested file: "
                        + fileName
        );

        File resourceDirectory =
                new File(DEMO_ROOT, "resources");

        File requestedFile =
                resolveSafeFile(resourceDirectory, fileName);

        if (requestedFile == null) {
            sendResponse(
                    exchange,
                    403,
                    "Access denied."
            );

            return;
        }

        readAndDisplayFile(exchange, requestedFile);
    }

    /*
     * View a report safely.
     */
    private static void viewReport(
            HttpExchange exchange)
            throws IOException {

        String fileName =
                getParameter(exchange, "file");

        System.out.println(
                "[REPORT] Requested file: "
                        + fileName
        );

        File reportDirectory =
                new File(DEMO_ROOT, "reports");

        File requestedFile =
                resolveSafeFile(reportDirectory, fileName);

        if (requestedFile == null) {
            sendResponse(
                    exchange,
                    403,
                    "Access denied."
            );

            return;
        }

        readAndDisplayFile(exchange, requestedFile);
    }

    /*
     * View an attachment safely.
     */
    private static void viewAttachment(
            HttpExchange exchange)
            throws IOException {

        String fileName =
                getParameter(exchange, "file");

        System.out.println(
                "[ATTACHMENT] Requested file: "
                        + fileName
        );

        File attachmentDirectory =
                new File(DEMO_ROOT, "attachments");

        File requestedFile =
                resolveSafeFile(
                        attachmentDirectory,
                        fileName
                );

        if (requestedFile == null) {
            sendResponse(
                    exchange,
                    403,
                    "Access denied."
            );

            return;
        }

        readAndDisplayFile(exchange, requestedFile);
    }

    /*
     * Securely resolve a user-controlled filename.
     *
     * The canonical path of the requested file must remain inside
     * the canonical path of the intended base directory.
     */
    private static File resolveSafeFile(
            File baseDirectory,
            String userPath)
            throws IOException {

        if (userPath == null || userPath.isEmpty()) {
            return null;
        }

        File canonicalBase =
                baseDirectory.getCanonicalFile();

        File requestedFile =
                new File(canonicalBase, userPath);

        File canonicalRequested =
                requestedFile.getCanonicalFile();

        Path basePath =
                canonicalBase.toPath().normalize();

        Path requestedPath =
                canonicalRequested.toPath().normalize();

        /*
         * The requested file must remain inside the
         * intended directory.
         */
        if (!requestedPath.startsWith(basePath)) {
            System.out.println(
                    "[SECURITY] Blocked path traversal attempt: "
                            + userPath
            );

            return null;
        }

        return canonicalRequested;
    }

    /*
     * Read and display a file.
     */
    private static void readAndDisplayFile(
            HttpExchange exchange,
            File requestedFile)
            throws IOException {

        if (!requestedFile.exists()
                || !requestedFile.isFile()) {

            sendResponse(
                    exchange,
                    404,
                    "File not found."
            );

            return;
        }

        String content =
                Files.readString(
                        requestedFile.toPath()
                );

        sendResponse(
                exchange,
                200,
                content
        );
    }

    /*
     * Get a query-string parameter.
     */
    private static String getParameter(
            HttpExchange exchange,
            String name) {

        String query =
                exchange.getRequestURI()
                        .getRawQuery();

        if (query == null) {
            return "";
        }

        for (String parameter : query.split("&")) {

            String[] pair =
                    parameter.split("=", 2);

            if (pair.length == 2
                    && pair[0].equals(name)) {

                return URLDecoder.decode(
                        pair[1],
                        StandardCharsets.UTF_8
                );
            }
        }

        return "";
    }

    /*
     * Send a text response.
     */
    private static void sendResponse(
            HttpExchange exchange,
            int status,
            String message)
            throws IOException {

        byte[] content =
                message.getBytes(
                        StandardCharsets.UTF_8
                );

        exchange.getResponseHeaders().set(
                "Content-Type",
                "text/plain; charset=UTF-8"
        );

        exchange.sendResponseHeaders(
                status,
                content.length
        );

        try (OutputStream output =
                     exchange.getResponseBody()) {

            output.write(content);
        }
    }

    /*
     * Determine the content type of a file.
     */
    private static String getContentType(
            File file) {

        String name =
                file.getName().toLowerCase();

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

        if (name.endsWith(".jpg")
                || name.endsWith(".jpeg")) {
            return "image/jpeg";
        }

        return "text/plain; charset=UTF-8";
    }
}