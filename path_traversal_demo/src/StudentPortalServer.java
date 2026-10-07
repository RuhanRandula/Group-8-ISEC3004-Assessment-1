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
        System.out.println("Path Traversal demonstration server");
        System.out.println("Press Ctrl+C to stop.");
        System.out.println("==========================================");

        server.start();
    }

    private static void serveWebsite(HttpExchange exchange)
            throws IOException {

        String requestPath = exchange.getRequestURI().getPath();

        if (requestPath.equals("/")) {
            requestPath = "/index.html";
        }

        File webRoot = new File(DEMO_ROOT, "web");

        File requestedFile =
                new File(webRoot, requestPath.substring(1));

        if (!requestedFile.exists()
                || !requestedFile.isFile()) {

            sendResponse(
                    exchange,
                    404,
                    "Page not found."
            );

            return;
        }

        String contentType = getContentType(requestedFile);

        byte[] content = Files.readAllBytes(
                requestedFile.toPath()
        );

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

    private static void viewDocument(
            HttpExchange exchange)
            throws IOException {

        String fileName =
                getParameter(exchange, "file");

        System.out.println(
                "[DOCUMENT VIEW] Requested file: "
                        + fileName
        );

        /*
         * Vulnerable code:
         * The user-controlled filename is added directly
         * to the documents directory.
         */
        File requestedFile =
                new File(DOCUMENTS_DIR, fileName);

        readAndDisplayFile(exchange, requestedFile);
    }

    private static void downloadFile(
            HttpExchange exchange)
            throws IOException {

        String fileName =
                getParameter(exchange, "file");

        System.out.println(
                "[DOWNLOAD] Requested file: "
                        + fileName
        );

        /*
         * Vulnerable code:
         * No validation checks whether the final path
         * remains inside the intended directory.
         */
        File requestedFile =
                new File(DOCUMENTS_DIR, fileName);

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

        /*
         * Vulnerable resource loader.
         */
        File requestedFile =
                new File(resourceDirectory, fileName);

        readAndDisplayFile(exchange, requestedFile);
    }

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

        /*
         * Vulnerable report viewer.
         */
        File requestedFile =
                new File(reportDirectory, fileName);

        readAndDisplayFile(exchange, requestedFile);
    }

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

        /*
         * Vulnerable attachment viewer.
         */
        File requestedFile =
                new File(attachmentDirectory, fileName);

        readAndDisplayFile(exchange, requestedFile);
    }

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

    private static void sendResponse(
            HttpExchange exchange,
            int status,
            String message)
            throws IOException {

        byte[] content =
                message.getBytes(StandardCharsets.UTF_8);

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