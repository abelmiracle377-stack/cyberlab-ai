package ai.cyberlab.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;

public final class CyberLabBurpExtension implements BurpExtension {
    private HttpServer server;
    private ExecutorService executor;
    private static final int PORT = 8766;
    private static final Pattern SECRET_QUERY = Pattern.compile(
        "(?i)([?&](?:access_token|api_key|apikey|auth|authorization|code|key|password|passwd|secret|session|signature|sig|token)=)[^&#]*"
    );

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CyberLab AI — Local Burp Connector");
        try {
            String token = token();
            server = HttpServer.create(
                new InetSocketAddress(InetAddress.getByName("127.0.0.1"), PORT), 16
            );
            server.createContext("/v1/health", e -> health(e, token));
            server.createContext("/v1/proxy/history", e -> history(e, token, api));
            server.createContext("/v1/site-map", e -> siteMap(e, token, api));
            server.createContext("/v1/repeater/from-history", e -> repeaterFromHistory(e, token, api));
            executor = Executors.newFixedThreadPool(2, r -> {
                Thread t = new Thread(r, "cyberlab-burp-api");
                t.setDaemon(true);
                return t;
            });
            server.setExecutor(executor);
            server.start();
            api.extension().registerUnloadingHandler(() -> {
                if (server != null) server.stop(0);
                if (executor != null) executor.shutdownNow();
            });
            api.logging().logToOutput("CyberLab local Burp connector listening on 127.0.0.1:"
                + PORT + "; token stored in ~/.config/cyberlab/burp-extension-token.");
        } catch (Exception ex) {
            api.logging().logToError("CyberLab Burp connector failed to start: "
                + ex.getClass().getSimpleName());
        }
    }

    private static void health(HttpExchange e, String token) throws IOException {
        if (!"/v1/health".equals(e.getRequestURI().getPath())) { send(e, 404, "{\\"error\\":\\"not_found\\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"GET".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
        send(e, 200, "{\"status\":\"ok\",\"connector\":\"montoya\",\"read_only\":true}");
    }

    private static void history(HttpExchange e, String token, MontoyaApi api) throws IOException {
        if (!"/v1/proxy/history".equals(e.getRequestURI().getPath())) { send(e, 404, "{\\"error\\":\\"not_found\\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"GET".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
        int limit = limit(e.getRequestURI().getRawQuery());
        List<ProxyHttpRequestResponse> all = api.proxy().history();
        List<String> items = new ArrayList<>();
        for (int i = Math.max(0, all.size() - limit); i < all.size(); i++) {
            ProxyHttpRequestResponse entry = all.get(i);
            try {
                var request = entry.finalRequest();
                if (!request.isInScope()) continue;
                var response = entry.hasResponse() ? entry.response() : null;
                String url = SECRET_QUERY.matcher(request.url()).replaceAll("$1[REDACTED]");
                url = url.replaceFirst("(?i)^(https?://)[^/@]+@", "$1");
                items.add("{\"id\":" + entry.id()
                    + ",\"timestamp\":" + json(entry.time().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
                    + ",\"method\":" + json(request.method())
                    + ",\"url\":" + json(url)
                    + ",\"status_code\":" + (response == null ? "null" : Short.toString(response.statusCode()))
                    + ",\"in_scope\":true}");
            } catch (RuntimeException ignored) { }
        }
        send(e, 200, "{\"status\":\"ok\",\"source\":\"burp_proxy_history\","
            + "\"read_only\":true,\"count\":" + items.size() + ",\"items\":["
            + String.join(",", items) + "]}");
    }

    private static void repeaterFromHistory(HttpExchange e, String token, MontoyaApi api) throws IOException {
        if (!"/v1/repeater/from-history".equals(e.getRequestURI().getPath())) { send(e, 404, "{\\"error\\":\\"not_found\\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\\"error\\":\\"unauthorized\\"}"); return; }
        if (!"POST".equals(e.getRequestMethod())) { send(e, 405, "{\\"error\\":\\"method_not_allowed\\"}"); return; }
        String query = e.getRequestURI().getRawQuery();
        int historyId = -1;
        boolean confirmed = false;
        if (query != null) for (String pair : query.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2 && "id".equals(parts[0])) {
                try { historyId = Integer.parseInt(parts[1]); } catch (NumberFormatException ignored) { }
            }
            if (parts.length == 2 && "confirm".equals(parts[0])) confirmed = "true".equals(parts[1]);
        }
        if (historyId < 1 || !confirmed) {
            send(e, 400, "{\\"error\\":\\"history_id_and_explicit_confirmation_required\\"}");
            return;
        }
        for (ProxyHttpRequestResponse entry : api.proxy().history()) {
            if (entry.id() != historyId) continue;
            var request = entry.finalRequest();
            if (!request.isInScope()) {
                send(e, 403, "{\\"error\\":\\"out_of_scope_request_blocked\\"}");
                return;
            }
            api.repeater().sendToRepeater(request, "CyberLab · Proxy #" + historyId);
            send(e, 200, "{\\"status\\":\\"opened_in_repeater\\",\\"history_id\\":"
                + historyId + ",\\"request_sent\\":false}");
            return;
        }
        send(e, 404, "{\\"error\\":\\"proxy_history_item_not_found\\"}");
    }

    private static void siteMap(HttpExchange e, String token, MontoyaApi api) throws IOException {
        if (!"/v1/site-map".equals(e.getRequestURI().getPath())) { send(e, 404, "{\\"error\\":\\"not_found\\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\\"error\\":\\"unauthorized\\"}"); return; }
        if (!"GET".equals(e.getRequestMethod())) { send(e, 405, "{\\"error\\":\\"method_not_allowed\\"}"); return; }
        List<burp.api.montoya.http.message.HttpRequestResponse> all = api.siteMap().requestResponses();
        List<String> items = new ArrayList<>();
        int start = Math.max(0, all.size() - limit(e.getRequestURI().getRawQuery()));
        for (int i = start; i < all.size(); i++) {
            var entry = all.get(i);
            try {
                var request = entry.request();
                if (!request.isInScope()) continue;
                String url = SECRET_QUERY.matcher(request.url()).replaceAll("$1[REDACTED]");
                url = url.replaceFirst("(?i)^(https?://)[^/@]+@", "$1");
                var response = entry.response();
                items.add("{\\"method\\":" + json(request.method())
                    + ",\\"url\\":" + json(url)
                    + ",\\"status_code\\":" + (response == null ? "null" : Short.toString(response.statusCode()))
                    + ",\\"in_scope\\":true}");
            } catch (RuntimeException ignored) { }
        }
        send(e, 200, "{\\"status\\":\\"ok\\",\\"source\\":\\"burp_site_map\\","
            + "\\"read_only\\":true,\\"count\\":" + items.size() + ",\\"items\\":["
            + String.join(",", items) + "]}");
    }

    private static int limit(String query) {
        if (query != null) for (String pair : query.split("&")) {
            String[] p = pair.split("=", 2);
            if (p.length == 2 && p[0].equals("limit")) {
                try { return Math.max(1, Math.min(100, Integer.parseInt(p[1]))); }
                catch (NumberFormatException ignored) { return 50; }
            }
        }
        return 50;
    }

    private static boolean authorized(HttpExchange e, String token) {
        String h = e.getRequestHeaders().getFirst("Authorization");
        return h != null && h.startsWith("Bearer ")
            && MessageDigest.isEqual(token.getBytes(StandardCharsets.UTF_8),
                h.substring(7).getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange e, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        e.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        e.getResponseHeaders().set("Cache-Control", "no-store");
        e.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        e.sendResponseHeaders(code, b.length);
        try (var out = e.getResponseBody()) { out.write(b); }
    }

    private static String json(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default: if (c < 32) b.append(String.format("\\u%04x", (int)c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String token() throws IOException {
        Path dir = Path.of(System.getProperty("user.home"), ".config", "cyberlab");
        Files.createDirectories(dir);
        Path file = dir.resolve("burp-extension-token");
        if (Files.isSymbolicLink(file)) throw new IOException("Refusing symbolic-link token file");
        if (!Files.exists(file)) {
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            String generated = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            try { Files.writeString(file, generated, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); }
            catch (FileAlreadyExistsException ignored) { }
        }
        try {
            Files.setPosixFilePermissions(dir, EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
            Files.setPosixFilePermissions(file, EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException ignored) { }
        String value = Files.readString(file).trim();
        if (value.length() < 32 || value.length() > 128 || !value.matches("[A-Za-z0-9_-]+"))
            throw new IOException("Invalid local token file");
        return value;
    }
}
