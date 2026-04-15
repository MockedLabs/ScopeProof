package com.mockedlabs.scopeproof.model;

import java.util.ArrayList;
import java.util.List;

/** A single endpoint parsed from a Swagger/OpenAPI spec, used as the coverage baseline. */
public class SwaggerEndpoint {

  private String host = "";
  private String path = "";
  private String method = "";
  private String normalizedPath = "";
  private String operationId = "";
  private String summary = "";
  private List<String> tags = new ArrayList<>();
  private String applicationName = "";

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

  public String getMethod() {
    return method;
  }

  public void setMethod(String method) {
    this.method = method;
  }

  public String getNormalizedPath() {
    return normalizedPath;
  }

  public void setNormalizedPath(String normalizedPath) {
    this.normalizedPath = normalizedPath;
  }

  public String getOperationId() {
    return operationId;
  }

  public void setOperationId(String operationId) {
    this.operationId = operationId;
  }

  public String getSummary() {
    return summary;
  }

  public void setSummary(String summary) {
    this.summary = summary;
  }

  public List<String> getTags() {
    return tags;
  }

  public void setTags(List<String> tags) {
    this.tags = tags;
  }

  public String getApplicationName() {
    return applicationName;
  }

  public void setApplicationName(String applicationName) {
    this.applicationName = applicationName;
  }
}
