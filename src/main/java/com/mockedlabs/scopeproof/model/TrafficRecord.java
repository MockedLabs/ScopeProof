package com.mockedlabs.scopeproof.model;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import java.util.*;

/**
 * Represents a single captured HTTP request/response pair with all extracted metadata. Equivalent
 * to the Python record dict.
 */
public class TrafficRecord {

  private String host = "";
  private String path = "/";
  private String fullUrl = "";
  private String method = "GET";
  private int statusCode;
  private int requestSize;
  private int responseSize;
  private String normalizedEndpoint = "/";
  private Long timestamp;
  private List<String> queryParams = new ArrayList<>();
  private Map<String, String> paramValues = new HashMap<>();
  private boolean authenticated;
  private String authHeaderValue = "";
  private String contentType = "";
  private String toolName = "Unknown";
  private Map<String, AttackPattern> attackPatterns = new HashMap<>();
  private boolean editedProxy;
  private boolean decoderUsed;

  // Live Burp objects — not serialized
  private transient ToolType toolType;
  private transient HttpRequestResponse httpRequestResponse;

  // Persistence: raw bytes + service info for reconstruction
  private byte[] requestBytes;
  private byte[] responseBytes;
  private int port = 443;
  private boolean secure = true;

  // --- Getters and setters ---

  public String getHost() {
    return host;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public String getFullUrl() {
    return fullUrl;
  }

  public void setFullUrl(String fullUrl) {
    this.fullUrl = fullUrl;
  }

  public String getMethod() {
    return method;
  }

  public void setMethod(String method) {
    this.method = method;
  }

  public int getStatusCode() {
    return statusCode;
  }

  public void setStatusCode(int statusCode) {
    this.statusCode = statusCode;
  }

  public int getRequestSize() {
    return requestSize;
  }

  public void setRequestSize(int requestSize) {
    this.requestSize = requestSize;
  }

  public int getResponseSize() {
    return responseSize;
  }

  public void setResponseSize(int responseSize) {
    this.responseSize = responseSize;
  }

  public String getNormalizedEndpoint() {
    return normalizedEndpoint;
  }

  public void setNormalizedEndpoint(String normalizedEndpoint) {
    this.normalizedEndpoint = normalizedEndpoint;
  }

  public Long getTimestamp() {
    return timestamp;
  }

  public void setTimestamp(Long timestamp) {
    this.timestamp = timestamp;
  }

  public List<String> getQueryParams() {
    return queryParams;
  }

  public void setQueryParams(List<String> queryParams) {
    this.queryParams = queryParams;
  }

  public Map<String, String> getParamValues() {
    return paramValues;
  }

  public void setParamValues(Map<String, String> paramValues) {
    this.paramValues = paramValues;
  }

  public boolean isAuthenticated() {
    return authenticated;
  }

  public void setAuthenticated(boolean authenticated) {
    this.authenticated = authenticated;
  }

  public String getAuthHeaderValue() {
    return authHeaderValue;
  }

  public void setAuthHeaderValue(String authHeaderValue) {
    this.authHeaderValue = authHeaderValue;
  }

  public String getContentType() {
    return contentType;
  }

  public void setContentType(String contentType) {
    this.contentType = contentType;
  }

  public ToolType getToolType() {
    return toolType;
  }

  public void setToolType(ToolType toolType) {
    this.toolType = toolType;
  }

  public String getToolName() {
    return toolName;
  }

  public void setToolName(String toolName) {
    this.toolName = toolName;
  }

  public Map<String, AttackPattern> getAttackPatterns() {
    return attackPatterns;
  }

  public void setAttackPatterns(Map<String, AttackPattern> attackPatterns) {
    this.attackPatterns = attackPatterns;
  }

  public boolean isEditedProxy() {
    return editedProxy;
  }

  public void setEditedProxy(boolean editedProxy) {
    this.editedProxy = editedProxy;
  }

  public boolean isDecoderUsed() {
    return decoderUsed;
  }

  public void setDecoderUsed(boolean decoderUsed) {
    this.decoderUsed = decoderUsed;
  }

  public HttpRequestResponse getHttpRequestResponse() {
    return httpRequestResponse;
  }

  public void setHttpRequestResponse(HttpRequestResponse httpRequestResponse) {
    this.httpRequestResponse = httpRequestResponse;
  }

  public byte[] getRequestBytes() {
    return requestBytes;
  }

  public void setRequestBytes(byte[] requestBytes) {
    this.requestBytes = requestBytes;
  }

  public byte[] getResponseBytes() {
    return responseBytes;
  }

  public void setResponseBytes(byte[] responseBytes) {
    this.responseBytes = responseBytes;
  }

  public int getPort() {
    return port;
  }

  public void setPort(int port) {
    this.port = port;
  }

  public boolean isSecure() {
    return secure;
  }

  public void setSecure(boolean secure) {
    this.secure = secure;
  }
}
