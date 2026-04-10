package com.mockedlabs.scopeproof.persistence;

import com.mockedlabs.scopeproof.model.AttackPattern;
import com.mockedlabs.scopeproof.model.TrafficRecord;
import com.mockedlabs.scopeproof.parser.TrafficParser;
import com.google.gson.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Saves and restores captured traffic data between Burp restarts.
 * Data is stored as JSON in ~/.scopeproof/.
 */
public class Persistence {

    private static final String DATA_DIR_NAME = ".scopeproof";
    private static final String RECORDS_FILE = "scopeproof_records.json";
    private static final String ANNOTATIONS_FILE = "scopeproof_annotations.json";

    private final File dataDir;
    private final File recordsFile;
    private final File annotationsFile;
    private final Gson gson;

    public Persistence() {
        this.dataDir = new File(System.getProperty("user.home"), DATA_DIR_NAME);
        this.recordsFile = new File(dataDir, RECORDS_FILE);
        this.annotationsFile = new File(dataDir, ANNOTATIONS_FILE);
        this.gson = new Gson();
    }

    private void ensureDir() {
        if (!dataDir.exists()) dataDir.mkdirs();
    }

    // --- Save ---

    public boolean saveRecords(List<TrafficRecord> records) {
        try {
            ensureDir();
            List<Map<String, Object>> serialized = new ArrayList<>();
            for (TrafficRecord rec : records) {
                try {
                    serialized.add(serializeRecord(rec));
                } catch (Exception e) {
                    System.err.println("ScopeProof: Failed to serialize record: " + e.getMessage());
                }
            }

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("version", "1.0");
            data.put("saved_at", System.currentTimeMillis());
            data.put("record_count", serialized.size());
            data.put("records", serialized);

            writeAtomic(recordsFile, gson.toJson(data));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean saveAnnotations(Map<String, String> notes, Map<String, String> tags) {
        try {
            ensureDir();
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("version", "1.0");
            data.put("notes", notes);
            data.put("tags", tags);

            writeAtomic(annotationsFile, gson.toJson(data));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public void saveAll(List<TrafficRecord> records, Map<String, String> notes,
                        Map<String, String> tags) {
        saveRecords(records);
        saveAnnotations(notes, tags);
    }

    // --- Load ---

    public List<TrafficRecord> loadRecords() {
        List<TrafficRecord> results = new ArrayList<>();
        if (!recordsFile.exists()) return results;

        try (Reader reader = new InputStreamReader(
                new FileInputStream(recordsFile), StandardCharsets.UTF_8)) {
            JsonObject data = JsonParser.parseReader(reader).getAsJsonObject();
            JsonArray records = data.getAsJsonArray("records");
            if (records != null) {
                for (JsonElement elem : records) {
                    try {
                        results.add(deserializeRecord(elem.getAsJsonObject()));
                    } catch (Exception e) {
                        System.err.println("ScopeProof: Failed to deserialize record: " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("ScopeProof: Failed to load records file: " + e.getMessage());
        }
        return results;
    }

    public Annotations loadAnnotations() {
        Map<String, String> notes = new HashMap<>();
        Map<String, String> tags = new HashMap<>();

        if (!annotationsFile.exists()) {
            return new Annotations(notes, tags);
        }

        try (Reader reader = new InputStreamReader(
                new FileInputStream(annotationsFile), StandardCharsets.UTF_8)) {
            JsonObject data = JsonParser.parseReader(reader).getAsJsonObject();
            JsonObject notesObj = data.getAsJsonObject("notes");
            if (notesObj != null) {
                for (Map.Entry<String, JsonElement> e : notesObj.entrySet()) {
                    notes.put(e.getKey(), e.getValue().getAsString());
                }
            }
            JsonObject tagsObj = data.getAsJsonObject("tags");
            if (tagsObj != null) {
                for (Map.Entry<String, JsonElement> e : tagsObj.entrySet()) {
                    tags.put(e.getKey(), e.getValue().getAsString());
                }
            }
        } catch (Exception e) {
            System.err.println("ScopeProof: Failed to load annotations: " + e.getMessage());
        }

        return new Annotations(notes, tags);
    }

    // --- Serialization ---

    private Map<String, Object> serializeRecord(TrafficRecord rec) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("host", rec.getHost());
        out.put("path", rec.getPath());
        out.put("full_url", rec.getFullUrl());
        out.put("method", rec.getMethod());
        out.put("status_code", rec.getStatusCode());
        out.put("request_size", rec.getRequestSize());
        out.put("response_size", rec.getResponseSize());
        out.put("normalized_endpoint", rec.getNormalizedEndpoint());
        out.put("timestamp", rec.getTimestamp());
        out.put("query_params", rec.getQueryParams());
        out.put("param_values", rec.getParamValues());
        out.put("authenticated", rec.isAuthenticated());
        out.put("auth_header_value", rec.getAuthHeaderValue());
        out.put("content_type", rec.getContentType());
        out.put("tool_name", rec.getToolName());
        out.put("edited_proxy", rec.isEditedProxy());
        out.put("decoder_used", rec.isDecoderUsed());
        out.put("port", rec.getPort());
        out.put("secure", rec.isSecure());

        // Attack patterns
        Map<String, Map<String, Object>> patterns = new LinkedHashMap<>();
        for (Map.Entry<String, AttackPattern> e : rec.getAttackPatterns().entrySet()) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("match", e.getValue().getMatch());
            p.put("offset", e.getValue().getOffset());
            patterns.put(e.getKey(), p);
        }
        out.put("attack_patterns", patterns);

        // Base64 encode request/response bytes
        if (rec.getRequestBytes() != null) {
            out.put("request_bytes", Base64.getEncoder().encodeToString(rec.getRequestBytes()));
        }
        if (rec.getResponseBytes() != null) {
            out.put("response_bytes", Base64.getEncoder().encodeToString(rec.getResponseBytes()));
        }

        return out;
    }

    private TrafficRecord deserializeRecord(JsonObject obj) {
        TrafficRecord rec = new TrafficRecord();
        rec.setHost(getStr(obj, "host"));
        rec.setPath(getStr(obj, "path"));
        rec.setFullUrl(getStr(obj, "full_url"));
        rec.setMethod(getStr(obj, "method"));
        rec.setStatusCode(getInt(obj, "status_code"));
        rec.setRequestSize(getInt(obj, "request_size"));
        rec.setResponseSize(getInt(obj, "response_size"));
        rec.setNormalizedEndpoint(getStr(obj, "normalized_endpoint"));
        if (obj.has("timestamp") && !obj.get("timestamp").isJsonNull()) {
            rec.setTimestamp(obj.get("timestamp").getAsLong());
        }
        rec.setAuthenticated(getBool(obj, "authenticated"));
        rec.setAuthHeaderValue(getStr(obj, "auth_header_value"));
        rec.setContentType(getStr(obj, "content_type"));
        rec.setToolName(getStr(obj, "tool_name"));
        rec.setToolType(TrafficParser.getToolType(rec.getToolName()));
        rec.setEditedProxy(getBool(obj, "edited_proxy"));
        rec.setDecoderUsed(getBool(obj, "decoder_used"));
        rec.setPort(obj.has("port") ? getInt(obj, "port") : 443);
        rec.setSecure(obj.has("secure") ? getBool(obj, "secure") : true);

        // Query params
        if (obj.has("query_params") && !obj.get("query_params").isJsonNull()) {
            JsonArray qpArr = obj.getAsJsonArray("query_params");
            if (qpArr != null) {
                List<String> params = new ArrayList<>();
                for (JsonElement e : qpArr) {
                    params.add(e.getAsString());
                }
                rec.setQueryParams(params);
            }
        }

        // Param values
        if (obj.has("param_values") && !obj.get("param_values").isJsonNull()) {
            JsonObject pvObj = obj.getAsJsonObject("param_values");
            if (pvObj != null) {
                Map<String, String> values = new HashMap<>();
                for (Map.Entry<String, JsonElement> e : pvObj.entrySet()) {
                    values.put(e.getKey(), e.getValue().getAsString());
                }
                rec.setParamValues(values);
            }
        }

        // Attack patterns
        if (obj.has("attack_patterns")) {
            Map<String, AttackPattern> patterns = new LinkedHashMap<>();
            JsonObject pObj = obj.getAsJsonObject("attack_patterns");
            if (pObj != null) {
                for (Map.Entry<String, JsonElement> e : pObj.entrySet()) {
                    JsonObject p = e.getValue().getAsJsonObject();
                    patterns.put(e.getKey(), new AttackPattern(
                        getStr(p, "match"), getInt(p, "offset")));
                }
            }
            rec.setAttackPatterns(patterns);
        }

        // Decode bytes
        if (obj.has("request_bytes") && !obj.get("request_bytes").isJsonNull()) {
            rec.setRequestBytes(Base64.getDecoder().decode(obj.get("request_bytes").getAsString()));
        }
        if (obj.has("response_bytes") && !obj.get("response_bytes").isJsonNull()) {
            rec.setResponseBytes(Base64.getDecoder().decode(obj.get("response_bytes").getAsString()));
        }

        return rec;
    }

    // --- Helpers ---

    private static String getStr(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : "";
    }

    private static int getInt(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsInt() : 0;
    }

    private static boolean getBool(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() && obj.get(key).getAsBoolean();
    }

    private void writeAtomic(File target, String content) throws IOException {
        File tmp = new File(target.getAbsolutePath() + ".tmp");
        try (Writer w = new OutputStreamWriter(
                new FileOutputStream(tmp), StandardCharsets.UTF_8)) {
            w.write(content);
        }
        java.nio.file.Files.move(tmp.toPath(), target.toPath(),
            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    // --- Annotations result container ---

    public static class Annotations {
        private final Map<String, String> notes;
        private final Map<String, String> tags;

        public Annotations(Map<String, String> notes, Map<String, String> tags) {
            this.notes = notes;
            this.tags = tags;
        }

        public Map<String, String> getNotes() { return notes; }
        public Map<String, String> getTags() { return tags; }
    }

    // --- Auto-save thread ---

    public static class AutoSaver {
        private final Runnable saveAction;
        private final int intervalSeconds;
        private final AtomicBoolean dirty = new AtomicBoolean(false);
        private volatile boolean stopped = false;
        private Thread thread;

        public AutoSaver(Runnable saveAction, int intervalSeconds) {
            this.saveAction = saveAction;
            this.intervalSeconds = intervalSeconds;
        }

        public void start() {
            thread = new Thread(() -> {
                while (!stopped) {
                    try {
                        Thread.sleep(intervalSeconds * 1000L);
                    } catch (InterruptedException e) {
                        break;
                    }
                    if (dirty.getAndSet(false) && !stopped) {
                        try { saveAction.run(); } catch (Exception e) {
                            System.err.println("ScopeProof: Auto-save error: " + e.getMessage());
                        }
                    }
                }
            }, "ScopeProof-AutoSave");
            thread.setDaemon(true);
            thread.start();
        }

        public void markDirty() { dirty.set(true); }

        public void stop() {
            stopped = true;
            if (thread != null) thread.interrupt();
        }

        public void forceSave() {
            dirty.set(false);
            try { saveAction.run(); } catch (Exception e) {
                System.err.println("ScopeProof: Force-save error: " + e.getMessage());
            }
        }
    }
}
