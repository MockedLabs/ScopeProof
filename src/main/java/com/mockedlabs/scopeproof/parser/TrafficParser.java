package com.mockedlabs.scopeproof.parser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.mockedlabs.scopeproof.model.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Extracts TrafficRecord from Burp HTTP messages and aggregates records into EndpointRows for
 * display.
 */
public class TrafficParser {

  // Synthetic tool type for edited proxy requests
  public static final String TOOL_EDITED_PROXY = "Edited Proxy";

  private final AttackDetector attackDetector;

  public TrafficParser(AttackDetector attackDetector) {
    this.attackDetector = attackDetector;
  }

  public AttackDetector getAttackDetector() {
    return attackDetector;
  }

  // --- Tool name mapping ---

  // Reverse mapping: tool name string → ToolType (for deserialization)
  private static final Map<String, ToolType> NAME_TO_TOOL = new HashMap<>();

  static {
    NAME_TO_TOOL.put("Proxy", ToolType.PROXY);
    NAME_TO_TOOL.put("Repeater", ToolType.REPEATER);
    NAME_TO_TOOL.put("Intruder", ToolType.INTRUDER);
    NAME_TO_TOOL.put("Active Scan", ToolType.SCANNER);
    NAME_TO_TOOL.put("Extender", ToolType.EXTENSIONS);
    NAME_TO_TOOL.put("Target", ToolType.TARGET);
    NAME_TO_TOOL.put("Sequencer", ToolType.SEQUENCER);
    NAME_TO_TOOL.put("Decoder", ToolType.DECODER);
    NAME_TO_TOOL.put("Comparer", ToolType.COMPARER);
  }

  public static String getToolName(ToolType tool) {
    if (tool == null) return "Unknown";
    switch (tool) {
      case PROXY:
        return "Proxy";
      case REPEATER:
        return "Repeater";
      case INTRUDER:
        return "Intruder";
      case SCANNER:
        return "Active Scan";
      case EXTENSIONS:
        return "Extender";
      case TARGET:
        return "Target";
      case SEQUENCER:
        return "Sequencer";
      case DECODER:
        return "Decoder";
      case COMPARER:
        return "Comparer";
      default:
        return tool.name();
    }
  }

  public static ToolType getToolType(String toolName) {
    if (toolName == null) return null;
    return NAME_TO_TOOL.get(toolName);
  }

  public static ToolType identifyTool(HttpResponseReceived response) {
    for (ToolType type : ToolType.values()) {
      try {
        if (response.toolSource().isFromTool(type)) return type;
      } catch (Exception ignored) {
      }
    }
    return null;
  }

  // --- Extract from live HTTP handler ---

  public TrafficRecord extractFromResponse(HttpResponseReceived response) {
    try {
      HttpRequest request = response.initiatingRequest();
      ToolType tool = identifyTool(response);

      return buildRecord(request, response, tool);
    } catch (Exception e) {
      return null;
    }
  }

  // --- Batch: extract from proxy history ---

  public List<TrafficRecord> parseProxyHistory(MontoyaApi api) {
    List<TrafficRecord> results = new ArrayList<>();
    Set<String> seenKeys = new HashSet<>();

    try {
      List<ProxyHttpRequestResponse> history = api.proxy().history();
      for (ProxyHttpRequestResponse entry : history) {
        try {
          HttpRequest req = entry.finalRequest();
          HttpResponse resp = entry.originalResponse();
          if (req == null || resp == null) continue;

          TrafficRecord record = buildRecord(req, resp, ToolType.PROXY);
          if (record != null) {
            String key = record.getMethod() + "|" + record.getFullUrl();
            if (!seenKeys.contains(key)) {
              seenKeys.add(key);
              results.add(record);
            }
          }
        } catch (Exception e) {
          System.err.println("ScopeProof: Failed to parse proxy entry: " + e.getMessage());
        }
      }
    } catch (Exception e) {
      System.err.println("ScopeProof: Failed to read proxy history: " + e.getMessage());
    }

    // Site map
    try {
      List<HttpRequestResponse> siteMap = api.siteMap().requestResponses();
      for (HttpRequestResponse entry : siteMap) {
        try {
          HttpRequest req = entry.request();
          HttpResponse resp = entry.response();
          if (req == null) continue;

          TrafficRecord record = buildRecord(req, resp, ToolType.TARGET);
          if (record != null) {
            String key = record.getMethod() + "|" + record.getFullUrl();
            if (!seenKeys.contains(key)) {
              seenKeys.add(key);
              results.add(record);
            }
          }
        } catch (Exception e) {
          System.err.println("ScopeProof: Failed to parse site map entry: " + e.getMessage());
        }
      }
    } catch (Exception e) {
      System.err.println("ScopeProof: Failed to read site map: " + e.getMessage());
    }

    return results;
  }

  // --- Core record extraction ---

  private TrafficRecord buildRecord(HttpRequest request, HttpResponse response, ToolType tool) {
    if (request == null) return null;

    try {
      String host = request.httpService().host();
      int port = request.httpService().port();
      boolean secure = request.httpService().secure();
      String method = request.method();
      String rawUrl = request.url();

      // Parse path from URL
      String path = "/";
      String fullUrl = rawUrl;
      try {
        URI parsed = new URI(rawUrl);
        path = parsed.getPath();
        if (path == null || path.isEmpty()) path = "/";
      } catch (Exception e) {
        // Relative URL — strip query
        int qi = rawUrl.indexOf('?');
        path = qi >= 0 ? rawUrl.substring(0, qi) : rawUrl;
        String scheme = secure ? "https" : "http";
        fullUrl = scheme + "://" + host + ":" + port + rawUrl;
      }

      int requestSize = request.toByteArray().length();

      // Timestamp
      long timestamp = System.currentTimeMillis();

      // Parameters
      List<String> queryParams = new ArrayList<>();
      Map<String, String> paramValues = new HashMap<>();
      try {
        for (ParsedHttpParameter param : request.parameters()) {
          HttpParameterType ptype = param.type();
          if (ptype == HttpParameterType.URL || ptype == HttpParameterType.BODY) {
            String name = param.name();
            if (name != null && !name.isEmpty()) {
              queryParams.add(name);
              try {
                paramValues.put(name, param.value());
              } catch (Exception ignored) {
              }
            }
          }
        }
      } catch (Exception e) {
        System.err.println("ScopeProof: Failed to parse parameters: " + e.getMessage());
      }
      Collections.sort(queryParams);

      // Auth state
      boolean authenticated = false;
      String authHeaderValue = "";
      for (var header : request.headers()) {
        String hName = header.name().toLowerCase();
        if ("authorization".equals(hName) || "cookie".equals(hName)) {
          authenticated = true;
          authHeaderValue = header.value();
          break;
        }
      }

      // Attack patterns (skip proxy/target — just normal browsing)
      Map<String, AttackPattern> attackPatterns = new HashMap<>();
      if (tool != ToolType.PROXY && tool != ToolType.TARGET) {
        try {
          String reqStr = new String(request.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
          attackPatterns = attackDetector.detect(reqStr);
        } catch (Exception e) {
          System.err.println("ScopeProof: Attack detection error: " + e.getMessage());
        }
      }

      // Response parsing
      int statusCode = 0;
      int responseSize = 0;
      String contentType = "";
      if (response != null) {
        try {
          statusCode = response.statusCode();
          responseSize = response.toByteArray().length();
          for (var header : response.headers()) {
            if ("content-type".equalsIgnoreCase(header.name())) {
              String ct = header.value();
              int semi = ct.indexOf(';');
              contentType = (semi >= 0 ? ct.substring(0, semi) : ct).trim();
              break;
            }
          }
        } catch (Exception e) {
          System.err.println("ScopeProof: Response parse error: " + e.getMessage());
        }
      }

      // Normalize — aggressive for Intruder/Scanner so payload iterations collapse
      boolean aggressive = tool == ToolType.INTRUDER || tool == ToolType.SCANNER;
      String normalized = PathNormalizer.normalizePath(path, aggressive);

      // Build record
      TrafficRecord rec = new TrafficRecord();
      rec.setHost(host);
      rec.setPath(path);
      rec.setFullUrl(fullUrl);
      rec.setMethod(method);
      rec.setStatusCode(statusCode);
      rec.setRequestSize(requestSize);
      rec.setResponseSize(responseSize);
      rec.setNormalizedEndpoint(normalized);
      rec.setTimestamp(timestamp);
      rec.setQueryParams(queryParams);
      rec.setParamValues(paramValues);
      rec.setAuthenticated(authenticated);
      rec.setAuthHeaderValue(authHeaderValue);
      rec.setContentType(contentType);
      rec.setToolType(tool);
      rec.setToolName(getToolName(tool));
      rec.setAttackPatterns(attackPatterns);
      rec.setPort(port);
      rec.setSecure(secure);

      // Store raw bytes for persistence and editor reconstruction
      rec.setRequestBytes(request.toByteArray().getBytes());
      if (response != null) {
        rec.setResponseBytes(response.toByteArray().getBytes());
      }

      return rec;
    } catch (Exception e) {
      return null;
    }
  }

  // --- Aggregation ---

  public static AggregationResult aggregate(
      List<TrafficRecord> records, Map<String, String> notesStore, Map<String, String> tagsStore) {
    Summary summary = new Summary();
    List<EndpointRow> rows = new ArrayList<>();

    if (records == null || records.isEmpty()) {
      return new AggregationResult(summary, rows);
    }

    int totalRequests = records.size();
    Set<String> uniqueHosts = new HashSet<>();
    Set<String> uniqueRawUrls = new HashSet<>();
    Set<String> uniqueEndpoints = new HashSet<>();
    Map<String, Integer> statusCounts = new TreeMap<>();
    Map<String, AggEntry> endpointMap = new LinkedHashMap<>();

    for (TrafficRecord rec : records) {
      String host = rec.getHost();
      String fullUrl = rec.getFullUrl();
      String method = rec.getMethod();
      int status = rec.getStatusCode();
      String endpoint = rec.getNormalizedEndpoint();
      Long ts = rec.getTimestamp();

      uniqueHosts.add(host);
      uniqueRawUrls.add(fullUrl);
      uniqueEndpoints.add(host + "|" + endpoint);
      String statusKey = String.valueOf(status);
      statusCounts.merge(statusKey, 1, Integer::sum);

      String groupKey = host + "|" + endpoint;
      AggEntry entry = endpointMap.computeIfAbsent(groupKey, k -> new AggEntry());
      entry.host = host;
      entry.endpoint = endpoint;
      entry.methods.add(method);
      entry.requestCount++;
      entry.statusCodes.merge(statusKey, 1, Integer::sum);

      if (ts != null) {
        if (entry.firstSeen == null || ts < entry.firstSeen) entry.firstSeen = ts;
        if (entry.lastSeen == null || ts > entry.lastSeen) entry.lastSeen = ts;
      }

      for (String p : rec.getQueryParams()) entry.queryParams.add(p);

      if (rec.isAuthenticated()) entry.authYes = true;
      else entry.authNo = true;

      String ct = rec.getContentType();
      if (ct != null && !ct.isEmpty()) entry.contentTypes.add(ct);

      // Tool tracking
      ToolType toolType = rec.getToolType();
      String effectiveToolName = rec.getToolName();
      if (rec.isEditedProxy() && toolType == ToolType.PROXY) {
        effectiveToolName = TOOL_EDITED_PROXY;
      }
      if (toolType != null) entry.toolFlags.add(toolType);
      entry.toolNames.merge(effectiveToolName, 1, Integer::sum);

      if (rec.isDecoderUsed()) entry.decoderUsed = true;

      // JWT/token detection
      String ahv = rec.getAuthHeaderValue();
      if (ahv != null && !ahv.isEmpty() && !entry.hasEncodedToken) {
        String stripped = ahv.trim();
        if (stripped.toLowerCase().startsWith("bearer ")) {
          String token = stripped.substring(7).trim();
          if (token.contains(".") && token.indexOf('.') != token.lastIndexOf('.')) {
            entry.hasEncodedToken = true;
          } else if (token.length() > 20) {
            entry.hasEncodedToken = true;
          }
        }
      }

      // Attack patterns
      for (String cat : rec.getAttackPatterns().keySet()) {
        entry.attackCounts.merge(cat, 1, Integer::sum);
      }

      if (rec.isEditedProxy()) entry.hasEditedProxy = true;
    }

    // Build summary
    summary.setTotalRequests(totalRequests);
    summary.setUniqueHosts(uniqueHosts.size());
    summary.setUniqueRawUrls(uniqueRawUrls.size());
    summary.setUniqueEndpoints(uniqueEndpoints.size());
    summary.setStatusCounts(statusCounts);

    // Build endpoint rows
    for (AggEntry entry : endpointMap.values()) {
      List<String> authStates = new ArrayList<>();
      if (entry.authYes) authStates.add("Auth");
      if (entry.authNo) authStates.add("Unauth");

      List<String> methodsList = new ArrayList<>(entry.methods);
      Collections.sort(methodsList);
      List<String> paramsList = new ArrayList<>(entry.queryParams);
      Collections.sort(paramsList);

      String storeKey = entry.host + "|" + entry.endpoint;
      String depth = classifyDepth(entry.toolFlags, entry.hasEditedProxy, entry.requestCount);

      // Tests detected
      Set<String> tests = new TreeSet<>(entry.attackCounts.keySet());
      if (entry.decoderUsed) tests.add("Decoder");
      if (entry.hasEncodedToken && !entry.decoderUsed) tests.add("Encoded Token");

      // Tool counts display
      String testedBy = formatToolCounts(entry.toolNames);

      EndpointRow row = new EndpointRow();
      row.setHost(entry.host);
      row.setEndpoint(entry.endpoint);
      row.setMethods(methodsList);
      row.setRequestCount(entry.requestCount);
      row.setStatusCodes(entry.statusCodes);
      row.setFirstSeen(formatTimestamp(entry.firstSeen));
      row.setLastSeen(formatTimestamp(entry.lastSeen));
      row.setQueryParams(paramsList);
      row.setAuthStates(authStates);
      row.setContentTypes(new ArrayList<>(entry.contentTypes));
      row.setToolFlags(entry.toolFlags);
      row.setTestedBy(testedBy);
      row.setTestingDepth(depth);
      row.setPriority(
          classifyPriority(methodsList, paramsList, authStates, entry.statusCodes, depth));
      row.setTestsDetected(new ArrayList<>(tests));
      row.setNotes(notesStore.getOrDefault(storeKey, ""));
      row.setTag(tagsStore.getOrDefault(storeKey, ""));

      rows.add(row);
    }

    rows.sort(Comparator.comparing(EndpointRow::getHost).thenComparing(r -> -r.getRequestCount()));

    return new AggregationResult(summary, rows);
  }

  // --- Depth classification ---

  public static String classifyDepth(
      Set<ToolType> toolFlags, boolean hasEditedProxy, int requestCount) {
    boolean hasFuzz = toolFlags.contains(ToolType.INTRUDER) || toolFlags.contains(ToolType.SCANNER);
    boolean hasManual =
        toolFlags.contains(ToolType.REPEATER)
            || toolFlags.contains(ToolType.EXTENSIONS)
            || hasEditedProxy;

    if (hasFuzz && hasManual && requestCount >= 10) return "Thoroughly Tested";
    if (hasFuzz) return "Fuzz Tested";
    if (hasManual) return "Manually Tested";
    if (requestCount >= 3) return "Observed";
    return "Untested";
  }

  // --- Priority classification ---

  private static final Set<String> WRITE_METHODS =
      new HashSet<>(Arrays.asList("POST", "PUT", "DELETE", "PATCH"));

  private static final Map<String, Integer> DEPTH_TIERS = new HashMap<>();

  static {
    DEPTH_TIERS.put("Thoroughly Tested", 3);
    DEPTH_TIERS.put("Fuzz Tested", 2);
    DEPTH_TIERS.put("Manually Tested", 1);
    DEPTH_TIERS.put("Observed", 0);
    DEPTH_TIERS.put("Untested", 0);
  }

  public static String classifyPriority(
      List<String> methods,
      List<String> queryParams,
      List<String> authStates,
      Map<String, Integer> statusCodes,
      String testingDepth) {
    boolean hasWrite = methods.stream().anyMatch(WRITE_METHODS::contains);
    boolean hasParams = !queryParams.isEmpty();
    boolean hasAuth = authStates.contains("Auth");
    boolean hasAuthzCodes = statusCodes.containsKey("401") || statusCodes.containsKey("403");

    int risk = 0;
    if (hasWrite) risk += 3;
    if (hasParams) risk += 2;
    if (hasAuth) risk += 1;
    if (hasAuthzCodes) risk += 1;
    if (queryParams.size() >= 3) risk += 1;

    int tier = risk >= 5 ? 2 : (risk >= 3 ? 1 : 0);

    int depth = DEPTH_TIERS.getOrDefault(testingDepth, 0);

    int gap = tier - depth;
    if (gap >= 2) return "Critical";
    if (gap == 1) return "High";
    if (gap == 0 && tier >= 1) return "Medium";
    return "Low";
  }

  // --- Helpers ---

  public static String formatTimestamp(Long epochMs) {
    if (epochMs == null) return "";
    try {
      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
      return sdf.format(new Date(epochMs));
    } catch (Exception e) {
      return "";
    }
  }

  private static String formatToolCounts(Map<String, Integer> toolNames) {
    List<String> parts = new ArrayList<>();
    List<String> sortedTools = new ArrayList<>(toolNames.keySet());
    Collections.sort(sortedTools);
    for (String tool : sortedTools) {
      parts.add(tool + "(" + toolNames.get(tool) + ")");
    }
    return String.join(", ", parts);
  }

  // --- Internal aggregation structure ---

  private static class AggEntry {
    String host;
    String endpoint;
    Set<String> methods = new LinkedHashSet<>();
    int requestCount;
    Map<String, Integer> statusCodes = new TreeMap<>();
    Long firstSeen;
    Long lastSeen;
    Set<String> queryParams = new LinkedHashSet<>();
    boolean authYes, authNo;
    Set<String> contentTypes = new LinkedHashSet<>();
    Set<ToolType> toolFlags = new HashSet<>();
    Map<String, Integer> toolNames = new LinkedHashMap<>();
    Map<String, Integer> attackCounts = new LinkedHashMap<>();
    boolean decoderUsed;
    boolean hasEncodedToken;
    boolean hasEditedProxy;
  }

  // --- Result containers ---

  public static class Summary {
    private int totalRequests;
    private int uniqueHosts;
    private int uniqueRawUrls;
    private int uniqueEndpoints;
    private Map<String, Integer> statusCounts = new TreeMap<>();

    public int getTotalRequests() {
      return totalRequests;
    }

    public void setTotalRequests(int v) {
      this.totalRequests = v;
    }

    public int getUniqueHosts() {
      return uniqueHosts;
    }

    public void setUniqueHosts(int v) {
      this.uniqueHosts = v;
    }

    public int getUniqueRawUrls() {
      return uniqueRawUrls;
    }

    public void setUniqueRawUrls(int v) {
      this.uniqueRawUrls = v;
    }

    public int getUniqueEndpoints() {
      return uniqueEndpoints;
    }

    public void setUniqueEndpoints(int v) {
      this.uniqueEndpoints = v;
    }

    public Map<String, Integer> getStatusCounts() {
      return statusCounts;
    }

    public void setStatusCounts(Map<String, Integer> v) {
      this.statusCounts = v;
    }
  }

  public static class AggregationResult {
    private final Summary summary;
    private final List<EndpointRow> endpointRows;

    public AggregationResult(Summary summary, List<EndpointRow> endpointRows) {
      this.summary = summary;
      this.endpointRows = endpointRows;
    }

    public Summary getSummary() {
      return summary;
    }

    public List<EndpointRow> getEndpointRows() {
      return endpointRows;
    }
  }
}
