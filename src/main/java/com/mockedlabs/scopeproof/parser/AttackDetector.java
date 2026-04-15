package com.mockedlabs.scopeproof.parser;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.mockedlabs.scopeproof.model.AttackPattern;
import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Detects user-defined payload strings in HTTP request content. Categories are fully customizable —
 * pentesters can add their own beyond the defaults (XSS, SQLi, etc.).
 */
public class AttackDetector {

  private static final List<String> DEFAULT_CATEGORIES =
      Arrays.asList("XSS", "SQLi", "Path Traversal", "CMDi", "SSTI", "SSRF", "XXE");

  // Ordered list of all categories (defaults + custom)
  private final List<String> categories = new ArrayList<>();

  // User-defined payloads per category
  private final Map<String, Set<String>> payloads = new LinkedHashMap<>();
  private final File payloadFile;
  private final Gson gson = new Gson();

  public AttackDetector(File extensionDir) {
    this.payloadFile = new File(extensionDir, "payloads.json");
    for (String cat : DEFAULT_CATEGORIES) {
      categories.add(cat);
      payloads.put(cat, new LinkedHashSet<>());
    }
    loadPayloads();
  }

  /** Returns the current list of all categories (defaults + custom). */
  public synchronized List<String> getCategories() {
    return new ArrayList<>(categories);
  }

  /** Add a new custom category. Returns false if it already exists. */
  public synchronized boolean addCategory(String name) {
    name = name.trim();
    if (name.isEmpty()) return false;
    // Case-insensitive duplicate check
    for (String existing : categories) {
      if (existing.equalsIgnoreCase(name)) return false;
    }
    categories.add(name);
    payloads.put(name, new LinkedHashSet<>());
    savePayloads();
    return true;
  }

  /** Remove a custom category and its payloads. Default categories cannot be removed. */
  public synchronized boolean removeCategory(String name) {
    if (DEFAULT_CATEGORIES.contains(name)) return false;
    if (!categories.remove(name)) return false;
    payloads.remove(name);
    savePayloads();
    return true;
  }

  /**
   * Detect user-defined payloads in request content. Returns {category: AttackPattern} for each
   * category matched.
   */
  public synchronized Map<String, AttackPattern> detect(String requestStr) {
    Map<String, AttackPattern> results = new LinkedHashMap<>();
    if (requestStr == null || requestStr.isEmpty()) return results;

    for (Map.Entry<String, Set<String>> entry : payloads.entrySet()) {
      String cat = entry.getKey();
      for (String payload : entry.getValue()) {
        int pos = requestStr.indexOf(payload);
        if (pos >= 0) {
          results.put(cat, new AttackPattern(payload, pos));
          break;
        }
      }
    }

    return results;
  }

  // --- Payload management ---

  public synchronized boolean addPayload(String category, String text) {
    text = text.trim();
    if (text.isEmpty() || !payloads.containsKey(category)) return false;
    if (payloads.get(category).contains(text)) return false;
    payloads.get(category).add(text);
    savePayloads();
    return true;
  }

  public synchronized int addPayloads(String category, List<String> texts) {
    if (!payloads.containsKey(category)) return 0;
    int added = 0;
    for (String text : texts) {
      text = text.trim();
      if (!text.isEmpty() && !payloads.get(category).contains(text)) {
        payloads.get(category).add(text);
        added++;
      }
    }
    if (added > 0) savePayloads();
    return added;
  }

  public synchronized boolean removePayload(String category, String text) {
    Set<String> set = payloads.get(category);
    if (set != null && set.remove(text)) {
      savePayloads();
      return true;
    }
    return false;
  }

  public synchronized Map<String, List<String>> getPayloads() {
    Map<String, List<String>> result = new LinkedHashMap<>();
    for (String cat : categories) {
      List<String> items = new ArrayList<>(payloads.getOrDefault(cat, Collections.emptySet()));
      result.put(cat, items);
    }
    return result;
  }

  public synchronized void clearPayloads(String category) {
    Set<String> set = payloads.get(category);
    if (set != null) {
      set.clear();
      savePayloads();
    }
  }

  public synchronized void clearAllPayloads() {
    for (Set<String> set : payloads.values()) {
      set.clear();
    }
    savePayloads();
  }

  // Keep old method name as delegate for context menu compatibility
  public boolean addCustomSignature(String category, String text) {
    return addPayload(category, text);
  }

  // --- Persistence ---

  private void loadPayloads() {
    // Try new file first, fall back to old signatures.json for migration
    File toLoad = payloadFile;
    if (!toLoad.exists()) {
      File legacy = new File(payloadFile.getParentFile(), "signatures.json");
      if (legacy.exists()) toLoad = legacy;
      else return;
    }

    try (Reader reader =
        new InputStreamReader(new FileInputStream(toLoad), StandardCharsets.UTF_8)) {
      Type type = new TypeToken<Map<String, List<String>>>() {}.getType();
      Map<String, List<String>> data = gson.fromJson(reader, type);
      if (data != null) {
        for (Map.Entry<String, List<String>> entry : data.entrySet()) {
          String cat = entry.getKey();
          // Add category if it's new (custom category from saved data)
          if (!categories.contains(cat)) {
            categories.add(cat);
          }
          if (entry.getValue() != null) {
            payloads.put(cat, new LinkedHashSet<>(entry.getValue()));
          } else {
            payloads.putIfAbsent(cat, new LinkedHashSet<>());
          }
        }
      }
    } catch (Exception e) {
      System.err.println("ScopeProof: Failed to load payloads: " + e.getMessage());
    }
  }

  private void savePayloads() {
    try {
      payloadFile.getParentFile().mkdirs();
      Map<String, List<String>> data = new LinkedHashMap<>();
      for (String cat : categories) {
        data.put(cat, new ArrayList<>(payloads.getOrDefault(cat, Collections.emptySet())));
      }
      // Atomic write: temp file then rename to prevent corruption on crash
      File tmp = new File(payloadFile.getAbsolutePath() + ".tmp");
      try (Writer writer =
          new OutputStreamWriter(new FileOutputStream(tmp), StandardCharsets.UTF_8)) {
        gson.toJson(data, writer);
      }
      java.nio.file.Files.move(
          tmp.toPath(), payloadFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    } catch (Exception e) {
      System.err.println("ScopeProof: Failed to save payloads: " + e.getMessage());
    }
  }
}
