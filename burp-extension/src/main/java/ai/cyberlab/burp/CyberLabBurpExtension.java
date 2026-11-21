package ai.cyberlab.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.Audit;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.ScanTask;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;

public final class CyberLabBurpExtension implements BurpExtension {
    private HttpServer server;
    private ExecutorService executor;
    private static final int PORT = 8766;
    private static final Map<String, ScanTask> SCAN_TASKS = new ConcurrentHashMap<>();
    private static final Map<String, String> SCAN_KINDS = new ConcurrentHashMap<>();
    private static final Map<String, String> SCAN_TARGETS = new ConcurrentHashMap<>();
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
            server.createContext("/v1/issues", e -> issues(e, token, api));
            server.createContext("/v1/repeater/from-history", e -> repeaterFromHistory(e, token, api));
            server.createContext("/v1/send-request", e -> sendInScopeRequest(e, token, api));
            server.createContext("/v1/intruder/from-history", e -> intruderFromHistory(e, token, api));
            server.createContext("/v1/scanner/crawl", e -> startScannerTask(e, token, api, "crawl"));
            server.createContext("/v1/scanner/audit", e -> startScannerTask(e, token, api, "audit"));
            server.createContext("/v1/scanner/tasks", e -> scannerTasks(e, token));
            server.createContext("/v1/scanner/cancel", e -> cancelScannerTask(e, token));
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
        if (!"/v1/health".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"GET".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
        send(e, 200, "{\"status\":\"ok\",\"connector\":\"montoya\",\"read_only\":false,\"capabilities\":[\"proxy_history\",\"site_map\",\"audit_issues\",\"repeater_handoff\",\"confirmed_single_request_replay\"]}");
    }

    private static void history(HttpExchange e, String token, MontoyaApi api) throws IOException {
        if (!"/v1/proxy/history".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
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
        if (!"/v1/repeater/from-history".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"POST".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
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
            send(e, 400, "{\"error\":\"history_id_and_explicit_confirmation_required\"}");
            return;
        }
        for (ProxyHttpRequestResponse entry : api.proxy().history()) {
            if (entry.id() != historyId) continue;
            var request = entry.finalRequest();
            if (!request.isInScope()) {
                send(e, 403, "{\"error\":\"out_of_scope_request_blocked\"}");
                return;
            }
            api.repeater().sendToRepeater(request, "CyberLab · Proxy #" + historyId);
            send(e, 200, "{\"status\":\"opened_in_repeater\",\"history_id\":"
                + historyId + ",\"request_sent\":false}");
            return;
        }
        send(e, 404, "{\"error\":\"proxy_history_item_not_found\"}");
    }

    // Active capability: replay one explicitly confirmed in-scope proxy-history
    // request through Burp and return bounded response metadata. Out-of-scope
    // requests are refused; no request body or response body is returned.
    private static void sendInScopeRequest(HttpExchange e, String token, MontoyaApi api) throws IOException {
        if (!"/v1/send-request".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"POST".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
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
            send(e, 400, "{\"error\":\"history_id_and_explicit_confirmation_required\"}");
            return;
        }
        for (ProxyHttpRequestResponse entry : api.proxy().history()) {
            if (entry.id() != historyId) continue;
            var request = entry.finalRequest();
            if (!request.isInScope()) {
                send(e, 403, "{\"error\":\"out_of_scope_request_blocked\"}");
                return;
            }
            try {
                var result = api.http().sendRequest(request);
                var response = result.response();
                if (response == null) {
                    send(e, 502, "{\"status\":\"sent\",\"history_id\":" + historyId + ",\"response\":null}");
                    return;
                }
                int bodyLength = response.body() == null ? 0 : response.body().length();
                send(e, 200, "{\"status\":\"sent\",\"history_id\":" + historyId
                    + ",\"method\":" + json(request.method())
                    + ",\"status_code\":" + Short.toString(response.statusCode())
                    + ",\"mime_type\":" + json(String.valueOf(response.statedMimeType()))
                    + ",\"body_length\":" + bodyLength
                    + ",\"in_scope\":true}");
            } catch (RuntimeException ex) {
                send(e, 502, "{\"error\":\"send_failed\",\"reason\":" + json(ex.getClass().getSimpleName()) + "}");
            }
            return;
        }
        send(e, 404, "{\"error\":\"proxy_history_item_not_found\"}");
    }

    private static void siteMap(HttpExchange e, String token, MontoyaApi api) throws IOException {
        if (!"/v1/site-map".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"GET".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
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
                items.add("{\"method\":" + json(request.method())
                    + ",\"url\":" + json(url)
                    + ",\"status_code\":" + (response == null ? "null" : Short.toString(response.statusCode()))
                    + ",\"in_scope\":true}");
            } catch (RuntimeException ignored) { }
        }
        send(e, 200, "{\"status\":\"ok\",\"source\":\"burp_site_map\","
            + "\"read_only\":true,\"count\":" + items.size() + ",\"items\":["
            + String.join(",", items) + "]}");
    }

    private static void issues(HttpExchange e, String token, MontoyaApi api) throws IOException {
        if (!"/v1/issues".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"GET".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
        List<burp.api.montoya.scanner.audit.issues.AuditIssue> all = api.siteMap().issues();
        List<String> items = new ArrayList<>();
        int max = limit(e.getRequestURI().getRawQuery());
        for (var issue : all) {
            try {
                boolean inScope = issue.requestResponses() != null
                    && issue.requestResponses().stream().anyMatch(rr -> rr.request().isInScope());
                if (!inScope) continue;
                String baseUrl = issue.baseUrl() == null ? "" : SECRET_QUERY.matcher(issue.baseUrl()).replaceAll("$1[REDACTED]");
                baseUrl = baseUrl.replaceFirst("(?i)^(https?://)[^/@]+@", "$1");
                String name = issue.name() == null ? "Unnamed issue" : issue.name();
                items.add("{\"name\":" + json(name.substring(0, Math.min(200, name.length())))
                    + ",\"base_url\":" + json(baseUrl.substring(0, Math.min(2048, baseUrl.length())))
                    + ",\"severity\":" + json(String.valueOf(issue.severity()))
                    + ",\"confidence\":" + json(String.valueOf(issue.confidence()))
                    + ",\"in_scope\":true}");
                if (items.size() >= max) break;
            } catch (RuntimeException ignored) { }
        }
        send(e, 200, "{\"status\":\"ok\",\"source\":\"burp_site_map_issues\","
            + "\"read_only\":true,\"count\":" + items.size() + ",\"items\":["
            + String.join(",", items) + "]}");
    }


    // Intruder handoff opens the native Burp Intruder tab with a captured,
    // in-scope request. Payload positions and attack configuration remain
    // analyst-controlled in Burp; Montoya does not expose an attack-start API.
    private static void intruderFromHistory(HttpExchange e, String token, MontoyaApi api) throws IOException {
        if (!"/v1/intruder/from-history".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"POST".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
        Map<String,String> q = query(e.getRequestURI().getRawQuery());
        int historyId = parsePositiveInt(q.get("id"));
        if (historyId < 1 || !"true".equals(q.get("confirm")) || !validApproval(q.get("authorizationReference"))) {
            send(e, 400, "{\"error\":\"history_id_confirmation_and_authorization_reference_required\"}"); return;
        }
        for (ProxyHttpRequestResponse entry : api.proxy().history()) {
            if (entry.id() != historyId) continue;
            var request = entry.finalRequest();
            if (!request.isInScope() || !api.scope().isInScope(request.url())) {
                send(e, 403, "{\"error\":\"out_of_scope_request_blocked\"}"); return;
            }
            api.intruder().sendToIntruder(request, "CyberLab · approved history #" + historyId);
            api.logging().logToOutput("CyberLab: approved Intruder handoff for in-scope request #" + historyId
                + " (authorization reference " + safeLog(q.get("authorizationReference")) + ").");
            send(e, 200, "{\"status\":\"opened_in_intruder\",\"history_id\":" + historyId
                + ",\"attack_started\":false,\"note\":\"Request placed in Burp Intruder. Configure payload positions and attack settings, then start the attack in Burp. No payloads were sent by this handoff.\"}");
            return;
        }
        send(e, 404, "{\"error\":\"proxy_history_item_not_found\"}");
    }

    // Start a real Burp Professional crawl or active audit. The target must
    // already be inside Burp's Suite scope; this endpoint never changes scope.
    private static void startScannerTask(HttpExchange e, String token, MontoyaApi api, String kind) throws IOException {
        String expected = "/v1/scanner/" + kind;
        if (!expected.equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"POST".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
        Map<String,String> q = query(e.getRequestURI().getRawQuery());
        String target = q.getOrDefault("url", "").trim();
        if (!"true".equals(q.get("confirm")) || !validApproval(q.get("authorizationReference")) || target.length() > 2048) {
            send(e, 400, "{\"error\":\"explicit_confirmation_authorization_reference_and_target_required\"}"); return;
        }
        final URI uri;
        try {
            uri = URI.create(target);
            if (!("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                || uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null) {
                throw new IllegalArgumentException();
            }
        } catch (RuntimeException ex) {
            send(e, 400, "{\"error\":\"target_must_be_an_absolute_http_or_https_url_without_credentials_or_fragment\"}"); return;
        }
        if (!api.scope().isInScope(target)) {
            send(e, 403, "{\"error\":\"target_not_in_burp_suite_scope; add_it_in_burp_and_refresh\"}"); return;
        }
        try {
            ScanTask task;
            if ("crawl".equals(kind)) {
                Crawl crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(target));
                task = crawl;
            } else {
                Audit audit = api.scanner().startAudit(
                    AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
                audit.addRequest(HttpRequest.httpRequestFromUrl(target));
                task = audit;
            }
            String id = UUID.randomUUID().toString();
            SCAN_TASKS.put(id, task);
            SCAN_KINDS.put(id, kind);
            SCAN_TARGETS.put(id, target);
            api.logging().logToOutput("CyberLab: started Burp Professional " + kind + " for in-scope target "
                + uri.getScheme() + "://" + uri.getAuthority() + " (authorization reference "
                + safeLog(q.get("authorizationReference")) + ").");
            send(e, 202, "{\"status\":\"started\",\"task_id\":" + json(id)
                + ",\"kind\":" + json(kind) + ",\"target\":" + json(uri.getScheme() + "://" + uri.getAuthority())
                + ",\"note\":\"A real Burp Scanner task was started. Poll task status in CyberLab; Burp remains the execution engine.\"}");
        } catch (UnsupportedOperationException ex) {
            send(e, 501, "{\"status\":\"edition_unavailable\",\"error\":\"Burp Scanner requires a compatible Professional edition.\"}");
        } catch (RuntimeException ex) {
            send(e, 502, "{\"status\":\"start_failed\",\"error\":" + json(ex.getClass().getSimpleName()) + "}");
        }
    }

    private static void scannerTasks(HttpExchange e, String token) throws IOException {
        if (!"/v1/scanner/tasks".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"GET".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
        List<String> items = new ArrayList<>();
        for (String id : SCAN_TASKS.keySet()) {
            ScanTask task = SCAN_TASKS.get(id);
            if (task == null) continue;
            String message;
            try { message = task.statusMessage(); } catch (RuntimeException ex) { message = "Status message unavailable from this Burp API version."; }
            int issueCount = 0;
            if (task instanceof Audit audit) {
                try { issueCount = audit.issues().size(); } catch (RuntimeException ignored) { }
            }
            items.add("{\"task_id\":" + json(id) + ",\"kind\":" + json(SCAN_KINDS.getOrDefault(id, "unknown"))
                + ",\"target\":" + json(SCAN_TARGETS.getOrDefault(id, ""))
                + ",\"request_count\":" + task.requestCount() + ",\"error_count\":" + task.errorCount()
                + ",\"issue_count\":" + issueCount + ",\"status_message\":" + json(message == null ? "" : message) + "}");
        }
        send(e, 200, "{\"status\":\"ok\",\"tasks\":[" + String.join(",", items) + "]}");
    }

    private static void cancelScannerTask(HttpExchange e, String token) throws IOException {
        if (!"/v1/scanner/cancel".equals(e.getRequestURI().getPath())) { send(e, 404, "{\"error\":\"not_found\"}"); return; }
        if (!authorized(e, token)) { send(e, 401, "{\"error\":\"unauthorized\"}"); return; }
        if (!"POST".equals(e.getRequestMethod())) { send(e, 405, "{\"error\":\"method_not_allowed\"}"); return; }
        Map<String,String> q = query(e.getRequestURI().getRawQuery());
        String id = q.getOrDefault("id", "");
        if (!"true".equals(q.get("confirm"))) { send(e, 400, "{\"error\":\"cancellation_confirmation_required\"}"); return; }
        ScanTask task = SCAN_TASKS.remove(id);
        if (task == null) { send(e, 404, "{\"error\":\"unknown_or_expired_task\"}"); return; }
        try { task.delete(); } catch (RuntimeException ex) {
            SCAN_TASKS.put(id, task);
            send(e, 502, "{\"error\":\"cancel_failed\"}"); return;
        }
        SCAN_KINDS.remove(id); SCAN_TARGETS.remove(id);
        send(e, 200, "{\"status\":\"cancel_requested\",\"task_id\":" + json(id) + "}");
    }

    private static Map<String,String> query(String raw) {
        Map<String,String> result = new HashMap<>();
        if (raw == null || raw.isEmpty()) return result;
        for (String pair : raw.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2) {
                try { result.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(parts[1], StandardCharsets.UTF_8)); } catch (IllegalArgumentException ignored) { }
            }
        }
        return result;
    }

    private static int parsePositiveInt(String value) {
        try { int parsed = Integer.parseInt(value); return parsed > 0 ? parsed : -1; }
        catch (RuntimeException ex) { return -1; }
    }

    private static boolean validApproval(String reference) {
        return reference != null && reference.trim().length() >= 3 && reference.trim().length() <= 160
            && reference.indexOf('\r') < 0 && reference.indexOf('\n') < 0;
    }

    private static String safeLog(String value) {
        if (value == null) return "none";
        String clean = value.replaceAll("[^A-Za-z0-9._:/-]", "_");
        return clean.substring(0, Math.min(80, clean.length()));
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
