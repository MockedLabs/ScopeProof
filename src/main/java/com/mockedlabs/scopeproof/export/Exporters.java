package com.mockedlabs.scopeproof.export;

import com.mockedlabs.scopeproof.model.EndpointRow;
import com.mockedlabs.scopeproof.parser.TrafficParser;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Export coverage data in JSON and CSV formats.
 */
public class Exporters {

    // --- JSON ---

    public static boolean exportJson(String filepath, TrafficParser.Summary summary,
                                      List<EndpointRow> rows, Map<String, String> meta) {
        try {
            Map<String, Object> data = buildExportData(summary, rows, meta);
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            try (Writer w = new OutputStreamWriter(
                    new FileOutputStream(filepath), StandardCharsets.UTF_8)) {
                gson.toJson(data, w);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static Map<String, Object> buildExportData(TrafficParser.Summary summary,
                                                        List<EndpointRow> rows,
                                                        Map<String, String> meta) {
        if (meta == null) meta = Collections.emptyMap();
        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("report_type", "scopeproof");
        data.put("version", "3.0.0");
        data.put("generated_at", timestamp);

        String tester = meta.getOrDefault("tester", "");
        String client = meta.getOrDefault("client", "");
        String engagement = meta.getOrDefault("engagement", "");
        if (!tester.isEmpty() || !client.isEmpty() || !engagement.isEmpty()) {
            Map<String, String> eng = new LinkedHashMap<>();
            eng.put("tester", tester);
            eng.put("client", client);
            eng.put("engagement_name", engagement);
            data.put("engagement", eng);
        }

        Map<String, Object> summaryMap = new LinkedHashMap<>();
        summaryMap.put("total_requests", summary.getTotalRequests());
        summaryMap.put("unique_hosts", summary.getUniqueHosts());
        summaryMap.put("unique_raw_urls", summary.getUniqueRawUrls());
        summaryMap.put("unique_endpoints", summary.getUniqueEndpoints());
        summaryMap.put("status_codes", summary.getStatusCounts());
        data.put("summary", summaryMap);

        List<Map<String, Object>> endpoints = new ArrayList<>();
        for (EndpointRow row : rows) {
            Map<String, Object> ep = new LinkedHashMap<>();
            ep.put("host", row.getHost());
            ep.put("endpoint", row.getEndpoint());
            ep.put("methods", row.getMethods());
            ep.put("request_count", row.getRequestCount());
            ep.put("status_codes", row.getStatusCodes());
            ep.put("first_seen", row.getFirstSeen());
            ep.put("last_seen", row.getLastSeen());
            ep.put("query_params", row.getQueryParams());
            ep.put("auth_states", row.getAuthStates());
            ep.put("content_types", row.getContentTypes());
            ep.put("tested_by", row.getTestedBy());
            ep.put("testing_depth", row.getTestingDepth());
            ep.put("priority", row.getPriority());
            ep.put("tests_detected", row.getTestsDetected());
            ep.put("tag", row.getTag());
            ep.put("notes", row.getNotes());
            endpoints.add(ep);
        }
        data.put("endpoints", endpoints);
        return data;
    }

    // --- CSV ---

    public static boolean exportCsv(String filepath, List<EndpointRow> rows) {
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(filepath), StandardCharsets.UTF_8))) {
            // Header
            w.println("Host,Endpoint,Methods,Requests,Priority,Tested By,"
                + "Testing Depth,Status Codes,Tests Detected,First Seen,"
                + "Last Seen,Parameters,Auth States,Content Types,Tag,Notes");

            for (EndpointRow row : rows) {
                List<String> scParts = new ArrayList<>();
                for (Map.Entry<String, Integer> e :
                        new TreeMap<>(row.getStatusCodes()).entrySet()) {
                    scParts.add(e.getKey() + "(" + e.getValue() + ")");
                }
                w.printf("%s,%s,%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s%n",
                    csvEscape(row.getHost()),
                    csvEscape(row.getEndpoint()),
                    csvEscape(String.join(", ", row.getMethods())),
                    row.getRequestCount(),
                    csvEscape(row.getPriority()),
                    csvEscape(row.getTestedBy()),
                    csvEscape(row.getTestingDepth()),
                    csvEscape(String.join(", ", scParts)),
                    csvEscape(String.join(", ", row.getTestsDetected())),
                    csvEscape(row.getFirstSeen()),
                    csvEscape(row.getLastSeen()),
                    csvEscape(String.join(", ", row.getQueryParams())),
                    csvEscape(String.join(", ", row.getAuthStates())),
                    csvEscape(String.join(", ", row.getContentTypes())),
                    csvEscape(row.getTag()),
                    csvEscape(row.getNotes())
                );
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String csvEscape(String s) {
        if (s == null) return "\"\"";
        // Prevent CSV formula injection — prefix dangerous leading characters with a single quote
        if (!s.isEmpty()) {
            char first = s.charAt(0);
            if (first == '=' || first == '+' || first == '-' || first == '@'
                    || first == '\t' || first == '\r') {
                s = "'" + s;
            }
        }
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

}
