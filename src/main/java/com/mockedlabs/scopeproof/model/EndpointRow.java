package com.mockedlabs.scopeproof.model;

import burp.api.montoya.core.ToolType;
import java.util.*;

/**
 * Aggregated endpoint data shown in the main table. One row per unique (host, normalizedEndpoint)
 * pair.
 */
public class EndpointRow {

  private String host = "";
  private String endpoint = "";
  private List<String> methods = new ArrayList<>();
  private int requestCount;
  private Map<String, Integer> statusCodes = new HashMap<>();
  private String firstSeen = "";
  private String lastSeen = "";
  private List<String> queryParams = new ArrayList<>();
  private List<String> authStates = new ArrayList<>();
  private List<String> contentTypes = new ArrayList<>();
  private Set<ToolType> toolFlags = new HashSet<>();
  private String testedBy = "";
  private String testingDepth = "";
  private String priority = "";
  private List<String> testsDetected = new ArrayList<>();
  private String notes = "";
  private String tag = "";
  private String baselineStatus = ""; // "", "Covered", "Missing", "Partial"
  private Set<String> exploitsConfirmed = new HashSet<>(); // categories where payload worked

  // --- Getters and setters ---

  public String getHost() {
    return host;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public String getEndpoint() {
    return endpoint;
  }

  public void setEndpoint(String endpoint) {
    this.endpoint = endpoint;
  }

  public List<String> getMethods() {
    return methods;
  }

  public void setMethods(List<String> methods) {
    this.methods = methods;
  }

  public int getRequestCount() {
    return requestCount;
  }

  public void setRequestCount(int requestCount) {
    this.requestCount = requestCount;
  }

  public Map<String, Integer> getStatusCodes() {
    return statusCodes;
  }

  public void setStatusCodes(Map<String, Integer> statusCodes) {
    this.statusCodes = statusCodes;
  }

  public String getFirstSeen() {
    return firstSeen;
  }

  public void setFirstSeen(String firstSeen) {
    this.firstSeen = firstSeen;
  }

  public String getLastSeen() {
    return lastSeen;
  }

  public void setLastSeen(String lastSeen) {
    this.lastSeen = lastSeen;
  }

  public List<String> getQueryParams() {
    return queryParams;
  }

  public void setQueryParams(List<String> queryParams) {
    this.queryParams = queryParams;
  }

  public List<String> getAuthStates() {
    return authStates;
  }

  public void setAuthStates(List<String> authStates) {
    this.authStates = authStates;
  }

  public List<String> getContentTypes() {
    return contentTypes;
  }

  public void setContentTypes(List<String> contentTypes) {
    this.contentTypes = contentTypes;
  }

  public Set<ToolType> getToolFlags() {
    return toolFlags;
  }

  public void setToolFlags(Set<ToolType> toolFlags) {
    this.toolFlags = toolFlags;
  }

  public String getTestedBy() {
    return testedBy;
  }

  public void setTestedBy(String testedBy) {
    this.testedBy = testedBy;
  }

  public String getTestingDepth() {
    return testingDepth;
  }

  public void setTestingDepth(String testingDepth) {
    this.testingDepth = testingDepth;
  }

  public String getPriority() {
    return priority;
  }

  public void setPriority(String priority) {
    this.priority = priority;
  }

  public List<String> getTestsDetected() {
    return testsDetected;
  }

  public void setTestsDetected(List<String> testsDetected) {
    this.testsDetected = testsDetected;
  }

  public String getNotes() {
    return notes;
  }

  public void setNotes(String notes) {
    this.notes = notes;
  }

  public String getTag() {
    return tag;
  }

  public void setTag(String tag) {
    this.tag = tag;
  }

  public String getBaselineStatus() {
    return baselineStatus;
  }

  public void setBaselineStatus(String baselineStatus) {
    this.baselineStatus = baselineStatus;
  }

  public Set<String> getExploitsConfirmed() {
    return exploitsConfirmed;
  }

  public void setExploitsConfirmed(Set<String> exploitsConfirmed) {
    this.exploitsConfirmed = exploitsConfirmed;
  }
}
