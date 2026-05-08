package com.mockedlabs.scopeproof;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.*;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.ui.contextmenu.*;
import burp.api.montoya.ui.menu.BasicMenuItem;
import burp.api.montoya.ui.menu.Menu;
import com.mockedlabs.scopeproof.model.TrafficRecord;
import com.mockedlabs.scopeproof.parser.TrafficParser;
import com.mockedlabs.scopeproof.ui.ScopeProofTab;
import java.awt.Component;
import java.util.*;
import javax.swing.*;

/**
 * ScopeProof - Burp Suite Extension (Montoya API)
 *
 * <p>Provides pentesters with a proof-of-testing coverage summary directly from the active Burp
 * project.
 *
 * <p>Install: Extensions > Add > Java > ScopeProof.jar
 */
public class ScopeProofExtension implements BurpExtension {

  private static final String NAME = "ScopeProof";

  @Override
  public void initialize(MontoyaApi api) {
    api.extension().setName(NAME);

    // Build the tab
    ScopeProofTab tab = new ScopeProofTab(api);
    TrafficParser parser = tab.getParser();

    // Register UI tab
    api.userInterface().registerSuiteTab(NAME, tab.getComponent());

    // Edited proxy detection: stores original request bytes keyed by messageId
    // Self-evicting LRU map — automatically removes oldest entries beyond capacity
    final int PENDING_PROXY_CAP = 5000;
    final Map<Integer, byte[]> pendingProxy =
        Collections.synchronizedMap(
            new LinkedHashMap<Integer, byte[]>(256, 0.75f, false) {
              @Override
              protected boolean removeEldestEntry(Map.Entry<Integer, byte[]> eldest) {
                return size() > PENDING_PROXY_CAP;
              }
            });

    // --- HTTP handler: captures traffic from ALL tools ---
    api.http()
        .registerHttpHandler(
            new HttpHandler() {
              @Override
              public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                return RequestToBeSentAction.continueWith(request);
              }

              @Override
              public ResponseReceivedAction handleHttpResponseReceived(
                  HttpResponseReceived response) {
                try {
                  TrafficRecord record = parser.extractFromResponse(response);
                  if (record != null) {
                    // Check for edited proxy
                    if (response.toolSource().isFromTool(ToolType.PROXY)) {
                      byte[] original = pendingProxy.remove(response.messageId());
                      if (original != null) {
                        byte[] current = response.initiatingRequest().toByteArray().getBytes();
                        if (!Arrays.equals(original, current)) {
                          record.setEditedProxy(true);
                          // Run attack detection on edited proxy requests
                          try {
                            String reqStr =
                                new String(current, java.nio.charset.StandardCharsets.ISO_8859_1);
                            var patterns = parser.getAttackDetector().detect(reqStr);
                            if (!patterns.isEmpty()) {
                              record.getAttackPatterns().putAll(patterns);
                            }
                          } catch (Exception ex) {
                            api.logging()
                                .logToError(NAME + " attack detect error: " + ex.getMessage());
                          }
                        }
                      }
                    }
                    tab.addLiveRecord(record);
                  }
                } catch (Exception e) {
                  api.logging().logToError(NAME + " capture error: " + e.getMessage());
                }
                return ResponseReceivedAction.continueWith(response);
              }
            });

    // --- Proxy handler: detect edited proxy requests ---
    api.proxy()
        .registerRequestHandler(
            new ProxyRequestHandler() {
              @Override
              public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
                try {
                  byte[] snapshot = request.toByteArray().getBytes();
                  pendingProxy.put(request.messageId(), snapshot);
                } catch (Exception ex) {
                  api.logging().logToError(NAME + " proxy snapshot error: " + ex.getMessage());
                }
                return ProxyRequestReceivedAction.continueWith(request);
              }

              @Override
              public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
                return ProxyRequestToBeSentAction.continueWith(request);
              }
            });

    // --- Context menu ---
    api.userInterface()
        .registerContextMenuItemsProvider(
            new ContextMenuItemsProvider() {
              @Override
              public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> items = new ArrayList<>();

                // Mark as Tested
                JMenuItem markTested = new JMenuItem("Mark as Tested (ScopeProof)");
                markTested.addActionListener(
                    e -> {
                      for (HttpRequestResponse msg : event.selectedRequestResponses()) {
                        try {
                          TrafficRecord record = buildManualRecord(msg, parser);
                          if (record != null) {
                            record.setToolName("Manual");
                            tab.addLiveRecord(record);
                          }
                        } catch (Exception ex) {
                          api.logging().logToError(NAME + " mark tested error: " + ex.getMessage());
                        }
                      }
                      api.logging()
                          .logToOutput(
                              "Marked "
                                  + event.selectedRequestResponses().size()
                                  + " item(s) as tested.");
                    });
                items.add(markTested);

                // Mark Decoder Used
                JMenuItem markDecoder = new JMenuItem("Mark Decoder Used (ScopeProof)");
                markDecoder.addActionListener(
                    e -> {
                      for (HttpRequestResponse msg : event.selectedRequestResponses()) {
                        try {
                          TrafficRecord record = buildManualRecord(msg, parser);
                          if (record != null) {
                            record.setToolName("Manual");
                            record.setDecoderUsed(true);
                            tab.addLiveRecord(record);
                          }
                        } catch (Exception ex) {
                          api.logging()
                              .logToError(NAME + " mark decoder error: " + ex.getMessage());
                        }
                      }
                    });
                items.add(markDecoder);

                // Flag for Review
                JMenuItem flagReview = new JMenuItem("Flag for Review (ScopeProof)");
                flagReview.addActionListener(
                    e -> {
                      List<HttpRequestResponse> msgs =
                          new java.util.ArrayList<>(event.selectedRequestResponses());
                      if (msgs.isEmpty() && event.messageEditorRequestResponse().isPresent()) {
                        msgs.add(event.messageEditorRequestResponse().get().requestResponse());
                      }
                      for (HttpRequestResponse msg : msgs) {
                        if (msg == null || msg.request() == null) continue;
                        try {
                          String host = msg.request().httpService().host();
                          String rawUrl = msg.request().url();
                          String path = "/";
                          try {
                            java.net.URI parsed = new java.net.URI(rawUrl);
                            path = parsed.getPath();
                            if (path == null || path.isEmpty()) path = "/";
                          } catch (Exception ex2) {
                            int qi = rawUrl.indexOf('?');
                            path = qi >= 0 ? rawUrl.substring(0, qi) : rawUrl;
                          }
                          String normalized =
                              com.mockedlabs.scopeproof.parser.PathNormalizer.normalizePath(path);
                          tab.flagForReview(host, normalized);
                        } catch (Exception ex) {
                          api.logging().logToError(NAME + " flag review error: " + ex.getMessage());
                        }
                      }
                    });
                items.add(flagReview);

                // --- separator: testing vs. reporting ---
                items.add(new JSeparator());

                // Report Finding to ScopeProof Pro
                JMenuItem reportFinding = new JMenuItem("Report Finding (ScopeProof Pro)");
                reportFinding.addActionListener(
                    e -> {
                      HttpRequestResponse evidence = null;
                      // Try selected request/responses first (history list)
                      List<HttpRequestResponse> selected = event.selectedRequestResponses();
                      if (!selected.isEmpty()) {
                        evidence = selected.get(0);
                      }
                      // Fallback: try the message editor (request/response pane)
                      if (evidence == null) {
                        var editorMsg = event.messageEditorRequestResponse();
                        if (editorMsg.isPresent()) {
                          evidence = editorMsg.get().requestResponse();
                        }
                      }
                      if (evidence != null) {
                        tab.reportFindingToPro(evidence);
                      }
                    });
                items.add(reportFinding);

                // --- separator: reporting vs. analysis ---
                items.add(new JSeparator());

                // Mark Exploited submenu — flag a confirmed vulnerability
                if (!event.selectedRequestResponses().isEmpty()) {
                  JMenu exploitMenu = new JMenu("Mark Exploited (ScopeProof)");
                  for (String cat : tab.getAttackDetector().getCategories()) {
                    JMenuItem catItem = new JMenuItem(cat);
                    catItem.addActionListener(
                        e -> {
                          for (HttpRequestResponse msg : event.selectedRequestResponses()) {
                            if (msg == null || msg.request() == null) continue;
                            try {
                              String host = msg.request().httpService().host();
                              String rawUrl = msg.request().url();
                              String path = "/";
                              try {
                                java.net.URI parsed = new java.net.URI(rawUrl);
                                path = parsed.getPath();
                                if (path == null || path.isEmpty()) path = "/";
                              } catch (Exception ex2) {
                                int qi = rawUrl.indexOf('?');
                                path = qi >= 0 ? rawUrl.substring(0, qi) : rawUrl;
                              }
                              String normalized =
                                  com.mockedlabs.scopeproof.parser.PathNormalizer.normalizePath(
                                      path);
                              tab.markExploitConfirmed(host, normalized, cat);
                            } catch (Exception ex) {
                              api.logging()
                                  .logToError(NAME + " mark exploited error: " + ex.getMessage());
                            }
                          }
                        });
                    exploitMenu.add(catItem);
                  }
                  items.add(exploitMenu);
                }

                // Tag Payload submenu
                var editorMsg = event.messageEditorRequestResponse();
                if (editorMsg.isPresent()) {
                  var selRange = editorMsg.get().selectionOffsets();
                  if (selRange.isPresent()) {
                    JMenu tagMenu = new JMenu("Tag Payload (ScopeProof)");
                    for (String cat : tab.getAttackDetector().getCategories()) {
                      JMenuItem catItem = new JMenuItem(cat);
                      catItem.addActionListener(
                          e -> {
                            try {
                              var selOff = editorMsg.get().selectionOffsets();
                              if (!selOff.isPresent()) return;
                              var range = selOff.get();
                              var reqResp = editorMsg.get().requestResponse();
                              byte[] raw = reqResp.request().toByteArray().getBytes();
                              String selected =
                                  new String(
                                          raw,
                                          range.startIndexInclusive(),
                                          range.endIndexExclusive() - range.startIndexInclusive(),
                                          java.nio.charset.StandardCharsets.ISO_8859_1)
                                      .trim();
                              if (!selected.isEmpty()) {
                                boolean added =
                                    tab.getAttackDetector().addCustomSignature(cat, selected);
                                if (added) {
                                  api.logging()
                                      .logToOutput("Added " + cat + " payload: " + selected);
                                  SwingUtilities.invokeLater(tab::reaggregateAndUpdate);
                                }
                              }
                            } catch (Exception ex) {
                              api.logging()
                                  .logToError(NAME + " tag payload error: " + ex.getMessage());
                            }
                          });
                      tagMenu.add(catItem);
                    }
                    items.add(tagMenu);
                  }
                }

                return items;
              }
            });

    // --- Intruder payload generators ---
    // Register a single "All Payloads" generator plus one per category at load time.
    // Custom categories added mid-session need extension reload for Intruder,
    // but the "All" generator always includes everything.
    api.intruder()
        .registerPayloadGeneratorProvider(
            new PayloadGeneratorProvider() {
              @Override
              public String displayName() {
                return NAME + " - All Payloads";
              }

              @Override
              public PayloadGenerator providePayloadGenerator(
                  AttackConfiguration attackConfiguration) {
                List<String> all = new ArrayList<>();
                for (List<String> items : tab.getAttackDetector().getPayloads().values()) {
                  all.addAll(items);
                }
                Iterator<String> iter = all.iterator();
                return insertionPoint -> {
                  if (iter.hasNext()) {
                    return GeneratedPayload.payload(iter.next());
                  }
                  return GeneratedPayload.end();
                };
              }
            });
    for (String category : tab.getAttackDetector().getCategories()) {
      api.intruder()
          .registerPayloadGeneratorProvider(
              new PayloadGeneratorProvider() {
                @Override
                public String displayName() {
                  return NAME + " - " + category;
                }

                @Override
                public PayloadGenerator providePayloadGenerator(
                    AttackConfiguration attackConfiguration) {
                  List<String> payloads =
                      tab.getAttackDetector()
                          .getPayloads()
                          .getOrDefault(category, Collections.emptyList());
                  Iterator<String> iter = payloads.iterator();
                  return insertionPoint -> {
                    if (iter.hasNext()) {
                      return GeneratedPayload.payload(iter.next());
                    }
                    return GeneratedPayload.end();
                  };
                }
              });
    }

    // --- Menu bar ---
    var menuReg =
        api.userInterface()
            .menuBar()
            .registerMenu(
                Menu.menu(NAME)
                    .withMenuItems(
                        BasicMenuItem.basicMenuItem("Refresh")
                            .withAction(() -> SwingUtilities.invokeLater(tab::refreshFromMenu)),
                        BasicMenuItem.basicMenuItem("Export JSON")
                            .withAction(() -> SwingUtilities.invokeLater(tab::exportJsonFromMenu)),
                        BasicMenuItem.basicMenuItem("Export CSV")
                            .withAction(() -> SwingUtilities.invokeLater(tab::exportCsvFromMenu)),
                        BasicMenuItem.basicMenuItem("Sync Swagger Baseline")
                            .withAction(() -> tab.syncSwaggerBaseline()),
                        BasicMenuItem.basicMenuItem("Sync Scope from Pro")
                            .withAction(() -> tab.syncScopeFromPro()),
                        BasicMenuItem.basicMenuItem("Settings")
                            .withAction(() -> SwingUtilities.invokeLater(tab::openSettings))));

    // --- Unload handler ---
    api.extension()
        .registerUnloadingHandler(
            () -> {
              tab.shutdown();
              menuReg.deregister();
            });

    api.logging().logToOutput(NAME + " v" + ScopeProofTab.VERSION + " loaded successfully.");
    api.logging()
        .logToOutput(
            "Real-time capture active. Traffic from Repeater, Intruder, "
                + "and all tools will be tracked automatically.");
  }

  private static TrafficRecord buildManualRecord(HttpRequestResponse msg, TrafficParser parser) {
    if (msg == null || msg.request() == null) return null;
    HttpRequest req = msg.request();
    var resp = msg.response();

    // Use the parser's buildRecord via extractFromResponse won't work here
    // since this isn't an HttpResponseReceived. Build manually.
    TrafficRecord rec = new TrafficRecord();
    try {
      rec.setHost(req.httpService().host());
      rec.setPort(req.httpService().port());
      rec.setSecure(req.httpService().secure());
      rec.setMethod(req.method());

      String rawUrl = req.url();
      String path = "/";
      try {
        java.net.URI parsed = new java.net.URI(rawUrl);
        path = parsed.getPath();
        if (path == null || path.isEmpty()) path = "/";
      } catch (Exception e) {
        int qi = rawUrl.indexOf('?');
        path = qi >= 0 ? rawUrl.substring(0, qi) : rawUrl;
      }
      rec.setPath(path);
      rec.setFullUrl(rawUrl);
      rec.setNormalizedEndpoint(
          com.mockedlabs.scopeproof.parser.PathNormalizer.normalizePath(path));
      rec.setRequestSize(req.toByteArray().length());
      rec.setTimestamp(System.currentTimeMillis());

      // Parameters
      List<String> params = new ArrayList<>();
      for (var p : req.parameters()) {
        var ptype = p.type();
        if (ptype == burp.api.montoya.http.message.params.HttpParameterType.URL
            || ptype == burp.api.montoya.http.message.params.HttpParameterType.BODY) {
          params.add(p.name());
        }
      }
      Collections.sort(params);
      rec.setQueryParams(params);

      if (resp != null) {
        rec.setStatusCode(resp.statusCode());
        rec.setResponseSize(resp.toByteArray().length());
        // Content-type
        for (var header : resp.headers()) {
          if ("content-type".equalsIgnoreCase(header.name())) {
            String ct = header.value();
            int semi = ct.indexOf(';');
            rec.setContentType(semi >= 0 ? ct.substring(0, semi).trim() : ct.trim());
            break;
          }
        }
      }

      // Auth detection
      for (var header : req.headers()) {
        String hName = header.name().toLowerCase();
        if ("authorization".equals(hName) || "cookie".equals(hName)) {
          rec.setAuthenticated(true);
          rec.setAuthHeaderValue(header.value());
          break;
        }
      }

      rec.setRequestBytes(req.toByteArray().getBytes());
      if (resp != null) rec.setResponseBytes(resp.toByteArray().getBytes());

      // Attack detection
      try {
        String reqStr =
            new String(rec.getRequestBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
        var patterns = parser.getAttackDetector().detect(reqStr);
        if (!patterns.isEmpty()) {
          rec.setAttackPatterns(patterns);
        }
      } catch (Exception ex) {
        // Non-critical — record is still valid without attack patterns
      }

    } catch (Exception e) {
      return null;
    }
    return rec;
  }
}
