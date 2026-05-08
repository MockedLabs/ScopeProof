package com.mockedlabs.scopeproof.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.mockedlabs.scopeproof.export.Exporters;
import com.mockedlabs.scopeproof.model.*;
import com.mockedlabs.scopeproof.parser.*;
import com.mockedlabs.scopeproof.persistence.Persistence;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.filechooser.FileNameExtensionFilter;

/** Main ScopeProof tab panel — equivalent to the Python CoverageUI class. */
public class ScopeProofTab {

  // Branding
  private static final String PRODUCT_NAME = "ScopeProof";
  private static final String BRAND_URL = "scopeproof.io";
  private static final String SAAS_NAME = "ScopeProof Pro";
  public static final String VERSION = "1.1.0";
  private static final String DEFAULT_UPLOAD_URL = "https://app.scopeproof.io/api/upload/";

  // Colors
  private static final Color CLR_BRAND = new Color(26, 86, 219);
  private static final Color CLR_BG = new Color(250, 250, 252);
  private static final Color CLR_BORDER = new Color(218, 222, 230);
  private static final Color CLR_TEXT = new Color(30, 30, 40);
  private static final Color CLR_TEXT_SEC = new Color(110, 115, 130);

  // Fonts
  private static final Font FONT_BODY = new Font("SansSerif", Font.PLAIN, 12);
  private static final Font FONT_SMALL = new Font("SansSerif", Font.PLAIN, 11);
  private static final Font FONT_CARD_VAL = new Font("SansSerif", Font.BOLD, 18);
  private static final Font FONT_CARD_LBL = new Font("SansSerif", Font.PLAIN, 10);

  // Depth keys — used for aggregation counts
  private static final String[] DEPTH_KEYS = {
    "Thoroughly Tested", "Fuzz Tested", "Manually Tested", "Observed", "Untested"
  };

  // Static/noise filter sets
  private static final Set<String> STATIC_EXTS =
      new HashSet<>(
          Arrays.asList(
              ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
              ".ttf", ".eot", ".otf", ".map", ".webp", ".mp4", ".mp3", ".avi", ".mov", ".pdf",
              ".zip", ".gz"));
  private static final Set<String> NOISE_DOMAINS =
      new HashSet<>(
          Arrays.asList(
              "fonts.googleapis.com",
              "fonts.gstatic.com",
              "ajax.googleapis.com",
              "cdn.jsdelivr.net",
              "cdnjs.cloudflare.com",
              "unpkg.com",
              "www.google-analytics.com",
              "www.googletagmanager.com",
              "connect.facebook.net",
              "platform.twitter.com",
              "www.gstatic.com",
              "apis.google.com",
              "maps.googleapis.com",
              "translate.googleapis.com",
              "accounts.google.com",
              "ssl.gstatic.com",
              "www.google.com",
              "cdn.segment.com",
              "api.segment.io",
              "browser.sentry-cdn.com",
              "sentry.io",
              "js.stripe.com",
              "m.stripe.network",
              "challenges.cloudflare.com",
              "static.cloudflareinsights.com"));
  private static final String[] TAG_OPTIONS = {
    "",
    "Needs Retest",
    "Critical Area",
    "Out of Scope",
    "Auth Bypass Target",
    "IDOR Target",
    "Injection Target",
    "Business Logic",
    "File Upload",
    "Custom..."
  };

  // Burp API
  private final MontoyaApi api;
  private final TrafficParser parser;
  private final AttackDetector attackDetector;
  private final Persistence persistence;

  // Data — capped to prevent unbounded memory growth during long engagements
  private static final int MAX_RECORDS = 50_000;
  private final List<TrafficRecord> allRecords = new CopyOnWriteArrayList<>();
  private TrafficParser.Summary summary = new TrafficParser.Summary();
  private final Object endpointLock = new Object();
  private List<EndpointRow> endpointRows = new ArrayList<>();
  private Map<String, String> notesStore = new java.util.concurrent.ConcurrentHashMap<>();
  private Map<String, String> tagsStore = new java.util.concurrent.ConcurrentHashMap<>();
  // host|endpoint → comma-separated confirmed exploit categories
  private Map<String, String> exploitsStore = new java.util.concurrent.ConcurrentHashMap<>();
  private static final String FLAGGED_TAG = "Flagged";
  // Index: host|endpoint → list of matching records (rebuilt on reaggregate)
  private Map<String, List<TrafficRecord>> recordIndex = new HashMap<>();
  private boolean excludeStatic = false;
  private boolean excludeNoise = false;

  // Swagger baseline for coverage comparison
  private final List<com.mockedlabs.scopeproof.model.SwaggerEndpoint> swaggerBaseline =
      new CopyOnWriteArrayList<>();
  // Key format: "host|normalizedPath" — for fast lookup during reaggregation
  private final Set<String> baselinePathKeys =
      Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());
  // Key format: "host|normalizedPath|METHOD" — for per-method coverage tracking
  private final Set<String> baselineMethodKeys =
      Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

  // Auto-save
  private final Persistence.AutoSaver autoSaver;

  // Debounce timer for live traffic updates (500ms coalesce window, 2s max-wait)
  private final javax.swing.Timer debounceTimer;
  private final javax.swing.Timer maxWaitTimer;

  // UI components
  private final JPanel mainPanel;
  private final CoverageTableModel tableModel;
  private JTable mainTable;
  private final RequestListTableModel reqListModel;
  private JTable reqListTable;
  private final HttpRequestEditor requestEditor;
  private final HttpResponseEditor responseEditor;

  // Summary labels
  private JLabel lblTotal, lblHosts, lblEndpoints, lblCoverage;
  private JLabel statusLabel;
  private JLabel reqListLabel;
  private JLabel emptyStateLabel;
  private JButton btnRefresh;

  // Filter chips
  private JPanel chipPanel;
  private String activeChip = "All"; // currently selected chip filter
  private final Map<String, JButton> chipButtons = new LinkedHashMap<>();

  // Settings fields
  private JTextField fieldTester = new JTextField("", 20);
  private JTextField fieldClient = new JTextField("", 20);
  private JTextField fieldEngagement = new JTextField("", 20);
  private JTextField fieldUploadUrl = new JTextField(DEFAULT_UPLOAD_URL, 20);
  private JPasswordField fieldApiToken = new JPasswordField("", 20);
  private JCheckBox chkExcludeStatic;
  private JCheckBox chkExcludeNoise;
  private JTextField scopeField;
  private JTextField filterField;
  private JPanel summaryPanel;

  public ScopeProofTab(MontoyaApi api) {
    this.api = api;
    this.attackDetector =
        new AttackDetector(new File(System.getProperty("user.home"), ".scopeproof"));
    this.parser = new TrafficParser(attackDetector, msg -> api.logging().logToError(msg));
    this.persistence = new Persistence();

    // Table models
    tableModel = new CoverageTableModel();
    reqListModel = new RequestListTableModel();

    // Burp native editors
    requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
    responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

    // Max-wait timer must be initialized first (referenced by debounce action)
    maxWaitTimer = new javax.swing.Timer(2000, null);
    maxWaitTimer.setRepeats(false);
    // Debounce timer: fires on EDT after 500ms of no new records
    debounceTimer =
        new javax.swing.Timer(
            500,
            e -> {
              maxWaitTimer.stop();
              reaggregateAndUpdate();
            });
    debounceTimer.setRepeats(false);
    // Max-wait action: force-fires the debounce to guarantee updates within 2s
    maxWaitTimer.addActionListener(
        e -> {
          debounceTimer.stop();
          reaggregateAndUpdate();
        });

    // Build UI
    mainPanel = buildMainPanel();

    // Restore persisted data
    restoreData();

    // Auto-import proxy history on first load if no data was restored
    if (allRecords.isEmpty()) {
      SwingUtilities.invokeLater(
          () -> {
            statusLabel.setText("Importing proxy history...");
            onRefresh();
          });
    }

    // Auto-save
    autoSaver = new Persistence.AutoSaver(this::doSave, 30);
    autoSaver.start();
  }

  public JComponent getComponent() {
    return mainPanel;
  }

  public TrafficParser getParser() {
    return parser;
  }

  public AttackDetector getAttackDetector() {
    return attackDetector;
  }

  // Expose fields for SettingsDialog
  public JTextField getFieldTester() {
    return fieldTester;
  }

  public JTextField getFieldClient() {
    return fieldClient;
  }

  public JTextField getFieldEngagement() {
    return fieldEngagement;
  }

  public JTextField getFieldUploadUrl() {
    return fieldUploadUrl;
  }

  public JPasswordField getFieldApiToken() {
    return fieldApiToken;
  }

  public JCheckBox getChkExcludeStatic() {
    return chkExcludeStatic;
  }

  public JCheckBox getChkExcludeNoise() {
    return chkExcludeNoise;
  }

  public String getScopeText() {
    return scopeField.getText();
  }

  public void setScopeText(String text) {
    scopeField.setText(text);
  }

  // --- Public API ---

  public void addLiveRecord(TrafficRecord record) {
    allRecords.add(record);
    // FIFO eviction — drop oldest records when cap is exceeded
    while (allRecords.size() > MAX_RECORDS) {
      allRecords.remove(0);
    }
    autoSaver.markDirty();
    // Debounce with max-wait: restart the 500ms timer but guaranteed to fire within 2s
    SwingUtilities.invokeLater(
        () -> {
          debounceTimer.restart();
          if (!maxWaitTimer.isRunning()) {
            maxWaitTimer.start();
          }
        });
  }

  public void shutdown() {
    debounceTimer.stop();
    maxWaitTimer.stop();
    autoSaver.stop();
    autoSaver.forceSave();
  }

  public void refreshFromMenu() {
    onRefresh();
  }

  public void exportJsonFromMenu() {
    doExport("JSON", "json", true);
  }

  public void exportCsvFromMenu() {
    doExport("CSV", "csv", false);
  }

  public void openSettings() {
    Frame frame = (Frame) SwingUtilities.getWindowAncestor(mainPanel);
    new SettingsDialog(frame, this).setVisible(true);
  }

  public void reaggregateAndUpdate() {
    persistNotesAndTags();
    List<TrafficRecord> filtered = filterRecords(new ArrayList<>(allRecords));
    TrafficParser.AggregationResult result =
        TrafficParser.aggregate(filtered, notesStore, tagsStore);
    this.summary = result.getSummary();
    // Rebuild record index for fast row selection lookups
    Map<String, List<TrafficRecord>> idx = new HashMap<>();
    for (TrafficRecord rec : filtered) {
      String key = rec.getHost() + "|" + rec.getNormalizedEndpoint();
      idx.computeIfAbsent(key, k -> new ArrayList<>()).add(rec);
    }
    synchronized (endpointLock) {
      this.endpointRows = result.getEndpointRows();
      this.recordIndex = idx;
    }

    // Apply confirmed exploits from the store
    synchronized (endpointLock) {
      for (EndpointRow row : endpointRows) {
        String key = row.getHost() + "|" + row.getEndpoint();
        String confirmed = exploitsStore.getOrDefault(key, "");
        if (!confirmed.isEmpty()) {
          Set<String> set = new HashSet<>();
          for (String c : confirmed.split(",")) {
            c = c.trim();
            if (!c.isEmpty()) set.add(c);
          }
          row.setExploitsConfirmed(set);
        }
      }
      // Create synthetic rows for "Flagged" endpoints not yet in traffic data
      Set<String> existingKeys = new HashSet<>();
      for (EndpointRow row : endpointRows) {
        existingKeys.add(row.getHost() + "|" + row.getEndpoint());
      }
      for (Map.Entry<String, String> entry : tagsStore.entrySet()) {
        if (!FLAGGED_TAG.equals(entry.getValue())) continue;
        if (existingKeys.contains(entry.getKey())) continue;
        int sep = entry.getKey().indexOf('|');
        if (sep < 0) continue;
        String host = entry.getKey().substring(0, sep);
        String endpoint = entry.getKey().substring(sep + 1);
        EndpointRow row = new EndpointRow();
        row.setHost(host);
        row.setEndpoint(endpoint);
        row.setTag(FLAGGED_TAG);
        row.setRequestCount(0);
        row.setTestingDepth("Untested");
        row.setPriority("High");
        row.setPriorityScore(50);
        row.setPriorityReasons(
            new ArrayList<>(Arrays.asList("Manually flagged for review", "Untested")));
        endpointRows.add(row);
      }
    }

    // Merge swagger baseline — mark observed rows and inject missing ones
    if (!swaggerBaseline.isEmpty()) {
      // Build set of observed host|normalizedPath keys
      Set<String> observedPaths = new HashSet<>();
      // Build set of observed host|normalizedPath|METHOD keys
      Set<String> observedMethods = new HashSet<>();
      synchronized (endpointLock) {
        for (EndpointRow row : endpointRows) {
          String pathKey = row.getHost() + "|" + row.getEndpoint();
          observedPaths.add(pathKey);
          for (String m : row.getMethods()) {
            observedMethods.add(pathKey + "|" + m);
          }
          // Mark baseline status on observed rows
          if (baselinePathKeys.contains(pathKey)) {
            // Check if all expected methods are covered
            boolean allCovered = true;
            for (String bk : baselineMethodKeys) {
              if (bk.startsWith(pathKey + "|")) {
                String expectedMethod = bk.substring(pathKey.length() + 1);
                if (!row.getMethods().contains(expectedMethod)) {
                  allCovered = false;
                  break;
                }
              }
            }
            row.setBaselineStatus(allCovered ? "Covered" : "Partial");
          }
        }
      }

      // Inject missing baseline endpoints as synthetic rows
      // Group by host|normalizedPath so we create one row per path
      Map<String, List<com.mockedlabs.scopeproof.model.SwaggerEndpoint>> missingByPath =
          new LinkedHashMap<>();
      for (com.mockedlabs.scopeproof.model.SwaggerEndpoint ep : swaggerBaseline) {
        String pathKey = ep.getHost() + "|" + ep.getNormalizedPath();
        if (!observedPaths.contains(pathKey)) {
          missingByPath.computeIfAbsent(pathKey, k -> new ArrayList<>()).add(ep);
        }
      }

      synchronized (endpointLock) {
        for (Map.Entry<String, List<com.mockedlabs.scopeproof.model.SwaggerEndpoint>> entry :
            missingByPath.entrySet()) {
          List<com.mockedlabs.scopeproof.model.SwaggerEndpoint> eps = entry.getValue();
          com.mockedlabs.scopeproof.model.SwaggerEndpoint first = eps.get(0);
          EndpointRow row = new EndpointRow();
          row.setHost(first.getHost());
          row.setEndpoint(first.getNormalizedPath());
          List<String> methods = new ArrayList<>();
          for (com.mockedlabs.scopeproof.model.SwaggerEndpoint ep : eps) {
            if (!methods.contains(ep.getMethod())) methods.add(ep.getMethod());
          }
          row.setMethods(methods);
          row.setRequestCount(0);
          row.setTestingDepth("Missing");
          row.setPriority("High");
          row.setBaselineStatus("Missing");
          row.setTag("Swagger Baseline");
          // Use summary/operationId as notes
          String note = first.getSummary();
          if (note.isEmpty()) note = first.getOperationId();
          if (!note.isEmpty() && !first.getApplicationName().isEmpty()) {
            note = "[" + first.getApplicationName() + "] " + note;
          }
          row.setNotes(note);
          endpointRows.add(row);
        }
      }
    }

    updateSummary();
    updateChipCounts();
    applyTableFilter();
    emptyStateLabel.setVisible(endpointRows.isEmpty());
    statusLabel.setText(
        String.format(
            "%d requests | %d endpoints | %d hosts",
            summary.getTotalRequests(), summary.getUniqueEndpoints(), summary.getUniqueHosts()));
  }

  // --- UI Construction ---

  private JPanel buildMainPanel() {
    JPanel panel = new JPanel(new BorderLayout(0, 4));
    panel.setBackground(CLR_BG);
    panel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

    panel.add(buildToolbar(), BorderLayout.NORTH);
    panel.add(buildCentre(), BorderLayout.CENTER);
    panel.add(buildStatusBar(), BorderLayout.SOUTH);

    return panel;
  }

  private JPanel buildToolbar() {
    JPanel toolbar = new JPanel(new BorderLayout(8, 0));
    toolbar.setBackground(CLR_BG);
    toolbar.setBorder(BorderFactory.createEmptyBorder(2, 0, 6, 0));

    // Left: brand + scope + search
    JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    left.setBackground(CLR_BG);

    JLabel brand = new JLabel(PRODUCT_NAME + "  ");
    brand.setFont(new Font("SansSerif", Font.BOLD, 14));
    brand.setForeground(CLR_BRAND);
    left.add(brand);

    left.add(new JLabel("Scope:"));
    scopeField = new JTextField("", 18);
    scopeField.setFont(FONT_BODY);
    scopeField.setEditable(false);
    scopeField.setFocusable(false);
    scopeField.setBackground(CLR_BG);
    scopeField.setBorder(
        BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CLR_BORDER),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)));
    scopeField.setForeground(CLR_TEXT);
    scopeField.getDocument().addDocumentListener(new SimpleDocListener(e -> applyScopeFilter()));
    left.add(scopeField);

    JLabel scopeEdit = new JLabel("Edit");
    scopeEdit.setFont(FONT_SMALL);
    scopeEdit.setForeground(CLR_BRAND);
    scopeEdit.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    scopeEdit.setToolTipText("Open Settings to configure scope hosts");
    scopeEdit.addMouseListener(
        new MouseAdapter() {
          @Override
          public void mouseClicked(MouseEvent e) {
            Frame frame = (Frame) SwingUtilities.getWindowAncestor(mainPanel);
            new SettingsDialog(frame, ScopeProofTab.this).setVisible(true);
          }
        });
    left.add(scopeEdit);

    left.add(Box.createHorizontalStrut(8));
    left.add(new JLabel("Search:"));
    filterField = new JTextField("", 14);
    filterField.setFont(FONT_BODY);
    filterField.getDocument().addDocumentListener(new SimpleDocListener(e -> applyTableFilter()));
    left.add(filterField);

    toolbar.add(left, BorderLayout.WEST);

    // Right: buttons
    JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
    right.setBackground(CLR_BG);

    btnRefresh = new JButton("Refresh");
    btnRefresh.setFont(FONT_BODY);
    btnRefresh.addActionListener(e -> onRefresh());
    right.add(btnRefresh);

    right.add(Box.createHorizontalStrut(4));

    JButton btnUpload = new JButton("Upload to Pro");
    btnUpload.setFont(new Font("SansSerif", Font.BOLD, 12));
    btnUpload.setForeground(CLR_BRAND);
    btnUpload.addActionListener(e -> onUpload());
    right.add(btnUpload);

    right.add(Box.createHorizontalStrut(4));

    JButton btnSettings = new JButton("Settings");
    btnSettings.setFont(FONT_BODY);
    btnSettings.addActionListener(
        e -> {
          Frame frame = (Frame) SwingUtilities.getWindowAncestor(mainPanel);
          new SettingsDialog(frame, this).setVisible(true);
        });
    right.add(btnSettings);

    toolbar.add(right, BorderLayout.EAST);
    return toolbar;
  }

  private JPanel buildCentre() {
    JPanel centre = new JPanel(new BorderLayout(0, 4));
    centre.setBackground(CLR_BG);

    // Summary cards
    summaryPanel = new JPanel(new GridLayout(1, 4, 8, 0));
    summaryPanel.setBackground(CLR_BG);
    summaryPanel.setPreferredSize(new Dimension(0, 56));
    lblTotal = makeCard("Requests", "0");
    lblHosts = makeCard("Hosts", "0");
    lblEndpoints = makeCard("Endpoints", "0");
    lblCoverage = makeCard("Coverage", "-");

    // Filter chips — sit between summary cards and the table
    chipPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
    chipPanel.setBackground(CLR_BG);
    String[] chipNames = {
      "All",
      "Next Up",
      "Untested",
      "Missing",
      "High Priority",
      "Has Exploits",
      "Auth Only",
      "Tested"
    };
    for (String name : chipNames) {
      JButton chip = new JButton(name);
      chip.setFont(FONT_SMALL);
      chip.setFocusPainted(false);
      chip.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
      chip.setBorder(
          BorderFactory.createCompoundBorder(
              BorderFactory.createLineBorder(CLR_BORDER),
              BorderFactory.createEmptyBorder(3, 10, 3, 10)));
      chip.addActionListener(e -> onChipClicked(name));
      chipButtons.put(name, chip);
      chipPanel.add(chip);
    }
    styleChips(); // set initial active state

    JPanel topSection = new JPanel(new BorderLayout(0, 2));
    topSection.setBackground(CLR_BG);
    topSection.add(summaryPanel, BorderLayout.NORTH);
    topSection.add(chipPanel, BorderLayout.SOUTH);
    centre.add(topSection, BorderLayout.NORTH);

    // Filter checkboxes (used by SettingsDialog)
    chkExcludeStatic = new JCheckBox("Hide static resources", false);
    chkExcludeStatic.addActionListener(
        e -> {
          excludeStatic = chkExcludeStatic.isSelected();
          if (!allRecords.isEmpty()) reaggregateAndUpdate();
        });
    chkExcludeNoise = new JCheckBox("Hide noise domains", false);
    chkExcludeNoise.addActionListener(
        e -> {
          excludeNoise = chkExcludeNoise.isSelected();
          if (!allRecords.isEmpty()) reaggregateAndUpdate();
        });

    // Main table
    mainTable = new JTable(tableModel);
    mainTable.setAutoCreateRowSorter(true);
    mainTable.setRowHeight(22);
    mainTable.setFont(FONT_BODY);
    mainTable.getTableHeader().setFont(FONT_SMALL);
    mainTable.setGridColor(new Color(235, 237, 242));
    mainTable.setShowGrid(true);

    //        0    1    2    3    4    5     6     7    8    9   10   11
    // Host Endpt Meth Reqs Prio Depth TstBy Auth  SC  Tests Tag Notes
    int[] widths = {130, 200, 65, 40, 60, 90, 120, 75, 85, 95, 65, 120};
    for (int i = 0; i < widths.length; i++) {
      mainTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
    }
    mainTable.getColumnModel().getColumn(2).setCellRenderer(new CellRenderers.MethodCellRenderer());
    mainTable
        .getColumnModel()
        .getColumn(4)
        .setCellRenderer(new CellRenderers.PriorityCellRenderer());
    mainTable.getColumnModel().getColumn(5).setCellRenderer(new CellRenderers.DepthCellRenderer());
    mainTable.getColumnModel().getColumn(7).setCellRenderer(new CellRenderers.AuthCellRenderer());
    mainTable.getColumnModel().getColumn(9).setCellRenderer(new CellRenderers.TestsCellRenderer());

    // Apply baseline row tint to columns without a custom renderer
    // Columns 2,4,5,7,9 already have custom renderers
    for (int c : new int[] {0, 1, 3, 6, 8, 10, 11}) {
      mainTable
          .getColumnModel()
          .getColumn(c)
          .setCellRenderer(
              new CellRenderers.BaselineRowRenderer(
                  mainTable.getColumnModel().getColumn(c).getCellRenderer()));
    }

    // Column header tooltips — use a custom renderer for per-column tooltips
    mainTable
        .getTableHeader()
        .setDefaultRenderer(new CellRenderers.HeaderTooltipRenderer(mainTable.getTableHeader()));

    // Tag double-click
    mainTable.addMouseListener(
        new MouseAdapter() {
          @Override
          public void mouseClicked(MouseEvent e) {
            if (e.getClickCount() == 2) {
              int row = mainTable.rowAtPoint(e.getPoint());
              int col = mainTable.columnAtPoint(e.getPoint());
              if (col == 10 && row >= 0) onTagEdit(row);
            }
          }
        });

    // Request list
    reqListTable = new JTable(reqListModel);
    reqListTable.setRowHeight(20);
    reqListTable.setFont(FONT_SMALL);
    reqListTable.getTableHeader().setFont(FONT_SMALL);
    reqListTable.setGridColor(new Color(235, 237, 242));
    reqListTable.setShowGrid(true);
    reqListTable.setAutoCreateRowSorter(true);

    int[] rlWidths = {28, 65, 45, 40, 45, 100, 95};
    for (int i = 0; i < rlWidths.length; i++) {
      reqListTable.getColumnModel().getColumn(i).setPreferredWidth(rlWidths[i]);
    }
    reqListTable
        .getColumnModel()
        .getColumn(5)
        .setCellRenderer(new CellRenderers.TestsCellRenderer());

    // Request list header
    JPanel reqListHeader = new JPanel(new BorderLayout(6, 0));
    reqListHeader.setBackground(new Color(245, 245, 248));
    reqListHeader.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));
    reqListLabel = new JLabel("Select an endpoint to view requests");
    reqListLabel.setFont(FONT_SMALL);
    reqListLabel.setForeground(CLR_TEXT_SEC);
    reqListHeader.add(reqListLabel, BorderLayout.WEST);

    JPanel reqListPanel = new JPanel(new BorderLayout());
    reqListPanel.add(reqListHeader, BorderLayout.NORTH);
    reqListPanel.add(new JScrollPane(reqListTable), BorderLayout.CENTER);

    // Request/Response split
    JSplitPane reqRespSplit =
        new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent());
    reqRespSplit.setResizeWeight(0.5);

    // Detail pane
    JPanel detailPanel = new JPanel(new BorderLayout(0, 2));
    detailPanel.setBackground(CLR_BG);
    reqListPanel.setPreferredSize(new Dimension(0, 130));
    reqListPanel.setMinimumSize(new Dimension(0, 80));
    detailPanel.add(reqListPanel, BorderLayout.NORTH);
    detailPanel.add(reqRespSplit, BorderLayout.CENTER);

    // Selection listeners
    reqListTable
        .getSelectionModel()
        .addListSelectionListener(
            e -> {
              if (!e.getValueIsAdjusting()) onRequestListSelected();
            });
    mainTable
        .getSelectionModel()
        .addListSelectionListener(
            e -> {
              if (!e.getValueIsAdjusting()) onRowSelected();
            });

    // Table scroll pane with empty-state message
    JScrollPane tableScroll = new JScrollPane(mainTable);
    emptyStateLabel =
        new JLabel(
            "Traffic will appear here automatically as you browse. "
                + "Click Refresh to import existing proxy history.",
            SwingConstants.CENTER);
    emptyStateLabel.setFont(FONT_BODY);
    emptyStateLabel.setForeground(CLR_TEXT_SEC);
    emptyStateLabel.setBackground(CLR_BG);
    emptyStateLabel.setOpaque(true);
    emptyStateLabel.setBorder(BorderFactory.createEmptyBorder(40, 20, 40, 20));
    JPanel tableWrapper = new JPanel(new BorderLayout());
    tableWrapper.add(emptyStateLabel, BorderLayout.NORTH);
    tableWrapper.add(tableScroll, BorderLayout.CENTER);

    // Main split
    JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableWrapper, detailPanel);
    mainSplit.setResizeWeight(0.45);
    mainSplit.setDividerLocation(280);

    centre.add(mainSplit, BorderLayout.CENTER);
    return centre;
  }

  private JPanel buildStatusBar() {
    JPanel bar = new JPanel(new BorderLayout(6, 0));
    bar.setBackground(new Color(245, 245, 248));
    bar.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

    statusLabel = new JLabel("Ready. Traffic is captured automatically.");
    statusLabel.setFont(FONT_SMALL);
    statusLabel.setForeground(CLR_TEXT_SEC);
    bar.add(statusLabel, BorderLayout.WEST);

    JLabel footer = new JLabel(PRODUCT_NAME + " v" + VERSION + " | " + BRAND_URL);
    footer.setFont(new Font("SansSerif", Font.PLAIN, 10));
    footer.setForeground(new Color(170, 175, 185));
    bar.add(footer, BorderLayout.EAST);

    return bar;
  }

  private static final String DEPTH_TOOLTIP =
      "<html>"
          + "<b>Testing Depth Legend</b><br><br>"
          + "<b>Thoroughly Tested</b> — Repeater + Intruder + attack payloads detected<br>"
          + "<b>Fuzz Tested</b> — Intruder or Scanner was used on this endpoint<br>"
          + "<b>Manually Tested</b> — Sent through Repeater or edited in Proxy<br>"
          + "<b>Observed</b> — Traffic seen but no manual testing actions<br>"
          + "<b>Untested</b> — In scope but no traffic captured<br>"
          + "<b>Missing</b> — Expected from Swagger baseline, not yet observed"
          + "</html>";

  private JLabel makeCard(String title, String value) {
    JPanel card = new JPanel();
    card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
    card.setBackground(Color.WHITE);
    card.setBorder(
        BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CLR_BORDER),
            BorderFactory.createEmptyBorder(6, 12, 6, 12)));

    JLabel titleLabel = new JLabel(title);
    titleLabel.setFont(FONT_CARD_LBL);
    titleLabel.setForeground(CLR_TEXT_SEC);
    titleLabel.setAlignmentX(0.0f);
    card.add(titleLabel);
    card.add(Box.createVerticalStrut(1));

    JLabel valueLabel = new JLabel(value);
    valueLabel.setFont(FONT_CARD_VAL);
    valueLabel.setForeground(CLR_TEXT);
    valueLabel.setAlignmentX(0.0f);
    card.add(valueLabel);

    // Add depth legend tooltip to the Depth card
    if ("Depth".equals(title)) {
      card.setToolTipText(DEPTH_TOOLTIP);
      titleLabel.setToolTipText(DEPTH_TOOLTIP);
      valueLabel.setToolTipText(DEPTH_TOOLTIP);
    }

    summaryPanel.add(card);
    return valueLabel;
  }

  // --- Event handlers ---

  private void onRowSelected() {
    int sel = mainTable.getSelectedRow();
    if (sel < 0) {
      reqListModel.clear();
      reqListLabel.setText("Select an endpoint to view requests");
      requestEditor.setRequest(HttpRequest.httpRequest(""));
      responseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n"));
      return;
    }
    int modelRow = mainTable.convertRowIndexToModel(sel);
    EndpointRow rowData = tableModel.getRow(modelRow);
    if (rowData == null) return;

    String host = rowData.getHost();
    String endpoint = rowData.getEndpoint();

    String indexKey = host + "|" + endpoint;
    List<TrafficRecord> matching;
    synchronized (endpointLock) {
      matching = new ArrayList<>(recordIndex.getOrDefault(indexKey, Collections.emptyList()));
    }
    matching.sort(
        (a, b) -> {
          Long ta = a.getTimestamp();
          Long tb = b.getTimestamp();
          if (ta == null && tb == null) return 0;
          if (ta == null) return 1;
          if (tb == null) return -1;
          return Long.compare(tb, ta);
        });

    reqListModel.setRows(matching);
    reqListLabel.setText(
        String.format(
            "%d request%s for %s %s",
            matching.size(), matching.size() != 1 ? "s" : "", host, endpoint));

    if (!matching.isEmpty()) {
      reqListTable.setRowSelectionInterval(0, 0);
    }
  }

  private void onRequestListSelected() {
    int sel = reqListTable.getSelectedRow();
    if (sel < 0) return;
    int modelRow = reqListTable.convertRowIndexToModel(sel);
    TrafficRecord rec = reqListModel.getRow(modelRow);
    if (rec == null) return;

    // Step 1: Get raw bytes (always available)
    byte[] reqBytes = rec.getRequestBytes();
    byte[] respBytes = rec.getResponseBytes();

    if (reqBytes == null) {
      api.logging().logToError("ScopeProof: No request bytes for record");
      return;
    }

    // Step 2: Build HttpRequest/HttpResponse from stored bytes
    HttpRequest httpReq = null;
    HttpResponse httpResp = null;
    try {
      HttpService service = HttpService.httpService(rec.getHost(), rec.getPort(), rec.isSecure());
      httpReq = HttpRequest.httpRequest(service, ByteArray.byteArray(reqBytes));
    } catch (Exception e) {
      api.logging().logToError("ScopeProof: Failed to build HttpRequest: " + e.getMessage());
      return;
    }

    if (respBytes != null) {
      try {
        httpResp = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
      } catch (Exception e) {
        api.logging().logToError("ScopeProof: Failed to build HttpResponse: " + e.getMessage());
      }
    }

    // Step 3: Set editors — always show content, markers are optional
    try {
      requestEditor.setRequest(httpReq);
    } catch (Exception e) {
      api.logging().logToError("ScopeProof: setRequest failed: " + e.getMessage());
    }

    if (httpResp != null) {
      try {
        responseEditor.setResponse(httpResp);
      } catch (Exception e) {
        api.logging().logToError("ScopeProof: setResponse failed: " + e.getMessage());
      }
    } else {
      try {
        responseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n"));
      } catch (Exception ignored) {
      }
    }
  }

  private void onTagEdit(int viewRow) {
    int modelRow = mainTable.convertRowIndexToModel(viewRow);
    EndpointRow rowData = tableModel.getRow(modelRow);
    if (rowData == null) return;

    String current = rowData.getTag();
    Object result =
        JOptionPane.showInputDialog(
            mainPanel,
            "Tag for: " + rowData.getHost() + " " + rowData.getEndpoint(),
            "Set Tag",
            JOptionPane.PLAIN_MESSAGE,
            null,
            TAG_OPTIONS,
            current != null && Arrays.asList(TAG_OPTIONS).contains(current) ? current : "");

    if (result != null) {
      String tag = result.toString();
      if ("Custom...".equals(tag)) {
        tag =
            JOptionPane.showInputDialog(
                mainPanel, "Enter custom tag:", "Custom Tag", JOptionPane.PLAIN_MESSAGE);
        if (tag == null) return;
      }
      tag = tag.trim();
      if (tag.length() > 100) tag = tag.substring(0, 100);
      rowData.setTag(tag);
      String key = rowData.getHost() + "|" + rowData.getEndpoint();
      tagsStore.put(key, tag);
      tableModel.fireTableDataChanged();
    }
  }

  private void onRefresh() {
    persistNotesAndTags();
    statusLabel.setText("Scanning proxy history...");
    btnRefresh.setEnabled(false);

    new Thread(
            () -> {
              try {
                List<TrafficRecord> batch = parser.parseProxyHistory(api);
                Set<String> existing = new HashSet<>();
                for (TrafficRecord rec : allRecords) {
                  existing.add(rec.getMethod() + "|" + rec.getFullUrl() + "|" + rec.getToolName());
                }

                int newCount = 0;
                for (TrafficRecord rec : batch) {
                  String key = rec.getMethod() + "|" + rec.getFullUrl() + "|" + rec.getToolName();
                  if (!existing.contains(key)) {
                    allRecords.add(rec);
                    existing.add(key);
                    newCount++;
                  }
                }

                final int nc = newCount;
                SwingUtilities.invokeLater(
                    () -> {
                      reaggregateAndUpdate();
                      statusLabel.setText("Scan complete. " + nc + " new records.");
                      btnRefresh.setEnabled(true);
                    });
              } catch (Exception e) {
                api.logging().logToError("Refresh error: " + e.getMessage());
                SwingUtilities.invokeLater(
                    () -> {
                      statusLabel.setText("Refresh failed. Check Extensions > Errors.");
                      btnRefresh.setEnabled(true);
                    });
              }
            },
            "ScopeProof-Refresh")
        .start();
  }

  // --- Filter chips ---

  private void onChipClicked(String chipName) {
    // Toggle: clicking the active chip resets to "All"
    activeChip = activeChip.equals(chipName) && !"All".equals(chipName) ? "All" : chipName;
    styleChips();
    applyTableFilter();
  }

  private void styleChips() {
    for (Map.Entry<String, JButton> entry : chipButtons.entrySet()) {
      JButton btn = entry.getValue();
      boolean active = entry.getKey().equals(activeChip);
      if (active) {
        btn.setBackground(CLR_BRAND);
        btn.setForeground(Color.WHITE);
        btn.setOpaque(true);
        btn.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CLR_BRAND),
                BorderFactory.createEmptyBorder(3, 10, 3, 10)));
      } else {
        btn.setBackground(Color.WHITE);
        btn.setForeground(CLR_TEXT);
        btn.setOpaque(true);
        btn.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(CLR_BORDER),
                BorderFactory.createEmptyBorder(3, 10, 3, 10)));
      }
    }
  }

  private boolean matchesChip(EndpointRow row) {
    switch (activeChip) {
      case "Next Up":
        {
          if (FLAGGED_TAG.equals(row.getTag())) return true;
          String d = row.getTestingDepth();
          return row.getPriorityScore() > 20
              && !"Thoroughly Tested".equals(d)
              && !"Fuzz Tested".equals(d);
        }
      case "Untested":
        return "Untested".equals(row.getTestingDepth()) || "Observed".equals(row.getTestingDepth());
      case "Missing":
        return "Missing".equals(row.getBaselineStatus());
      case "High Priority":
        return "Critical".equals(row.getPriority()) || "High".equals(row.getPriority());
      case "Has Exploits":
        return row.getExploitsConfirmed() != null && !row.getExploitsConfirmed().isEmpty();
      case "Auth Only":
        return row.getAuthStates().contains("Auth") && !row.getAuthStates().contains("Unauth");
      case "Tested":
        String d = row.getTestingDepth();
        return "Thoroughly Tested".equals(d)
            || "Fuzz Tested".equals(d)
            || "Manually Tested".equals(d);
      default:
        return true; // "All"
    }
  }

  /** Update chip button labels with live counts. */
  private void updateChipCounts() {
    Map<String, Integer> counts = new LinkedHashMap<>();
    for (String name : chipButtons.keySet()) counts.put(name, 0);

    for (EndpointRow row : endpointRows) {
      counts.put("All", counts.get("All") + 1);
      String depth = row.getTestingDepth();
      if (FLAGGED_TAG.equals(row.getTag())
          || (row.getPriorityScore() > 20
              && !"Thoroughly Tested".equals(depth)
              && !"Fuzz Tested".equals(depth))) {
        counts.merge("Next Up", 1, Integer::sum);
      }
      if ("Untested".equals(depth) || "Observed".equals(depth)) {
        counts.merge("Untested", 1, Integer::sum);
      }
      if ("Missing".equals(row.getBaselineStatus())) {
        counts.merge("Missing", 1, Integer::sum);
      }
      if ("Critical".equals(row.getPriority()) || "High".equals(row.getPriority())) {
        counts.merge("High Priority", 1, Integer::sum);
      }
      if (row.getExploitsConfirmed() != null && !row.getExploitsConfirmed().isEmpty()) {
        counts.merge("Has Exploits", 1, Integer::sum);
      }
      if (row.getAuthStates().contains("Auth") && !row.getAuthStates().contains("Unauth")) {
        counts.merge("Auth Only", 1, Integer::sum);
      }
      if ("Thoroughly Tested".equals(depth)
          || "Fuzz Tested".equals(depth)
          || "Manually Tested".equals(depth)) {
        counts.merge("Tested", 1, Integer::sum);
      }
    }

    for (Map.Entry<String, JButton> entry : chipButtons.entrySet()) {
      int count = counts.getOrDefault(entry.getKey(), 0);
      entry.getValue().setText(entry.getKey() + " (" + count + ")");
    }
  }

  // --- Filter / scope ---

  private void applyScopeFilter() {
    if (!allRecords.isEmpty()) reaggregateAndUpdate();
  }

  private void applyTableFilter() {
    String query = filterField.getText().trim().toLowerCase();
    boolean hasQuery = !query.isEmpty();
    boolean hasChip = !"All".equals(activeChip);

    if (!hasQuery && !hasChip) {
      tableModel.setRows(endpointRows);
      return;
    }

    List<EndpointRow> filtered = new ArrayList<>();
    for (EndpointRow row : endpointRows) {
      // Apply chip filter first
      if (hasChip && !matchesChip(row)) continue;

      // Then apply text search
      if (hasQuery) {
        String searchable =
            String.join(
                    " ",
                    row.getHost(),
                    row.getEndpoint(),
                    String.join(", ", row.getMethods()),
                    row.getTestedBy(),
                    row.getTestingDepth(),
                    row.getPriority(),
                    row.getTag(),
                    row.getNotes(),
                    String.join(", ", row.getTestsDetected()))
                .toLowerCase();
        if (!searchable.contains(query)) continue;
      }

      filtered.add(row);
    }

    // "Next Up" sorts by priority score descending — highest priority first
    if ("Next Up".equals(activeChip)) {
      filtered.sort((a, b) -> Integer.compare(b.getPriorityScore(), a.getPriorityScore()));
    }

    tableModel.setRows(filtered);
  }

  private List<TrafficRecord> filterRecords(List<TrafficRecord> records) {
    String scopeText = scopeField.getText().trim().toLowerCase();
    Set<String> exactHosts = new HashSet<>();
    List<String> wildcards = new ArrayList<>();

    if (!scopeText.isEmpty()) {
      for (String h : scopeText.split(",")) {
        h = h.trim();
        if (h.isEmpty()) continue;
        if (h.startsWith("*.")) wildcards.add(h.substring(1));
        else exactHosts.add(h);
      }
    }
    boolean hasScope = !exactHosts.isEmpty() || !wildcards.isEmpty();

    List<TrafficRecord> filtered = new ArrayList<>();
    for (TrafficRecord r : records) {
      String host = r.getHost().toLowerCase();
      if (hasScope && !hostInScope(host, exactHosts, wildcards)) continue;
      if (excludeNoise && NOISE_DOMAINS.contains(host)) continue;
      if (excludeStatic && isStaticResource(r.getPath())) continue;
      filtered.add(r);
    }
    return filtered;
  }

  private boolean hostInScope(String host, Set<String> exact, List<String> wildcards) {
    if (exact.contains(host)) return true;
    for (String suffix : wildcards) {
      if (host.endsWith(suffix) || host.equals(suffix.substring(1))) return true;
    }
    return false;
  }

  private static boolean isStaticResource(String path) {
    int qi = path.indexOf('?');
    String lower = (qi >= 0 ? path.substring(0, qi) : path).toLowerCase();
    int dot = lower.lastIndexOf('.');
    if (dot < 0 || dot == lower.length() - 1) return false;
    return STATIC_EXTS.contains(lower.substring(dot));
  }

  // --- Summary ---

  private void updateSummary() {
    lblTotal.setText(String.valueOf(summary.getTotalRequests()));
    lblHosts.setText(String.valueOf(summary.getUniqueHosts()));
    lblEndpoints.setText(String.valueOf(summary.getUniqueEndpoints()));

    Map<String, Integer> depthCounts = new LinkedHashMap<>();
    for (String key : DEPTH_KEYS) depthCounts.put(key, 0);

    for (EndpointRow row : endpointRows) {
      depthCounts.merge(row.getTestingDepth(), 1, Integer::sum);
    }

    // Coverage card — shows baseline coverage when swagger baseline is loaded
    if (!swaggerBaseline.isEmpty()) {
      int baselineTotal = baselinePathKeys.size();
      int covered = 0;
      Set<String> observedPaths = new HashSet<>();
      synchronized (endpointLock) {
        for (EndpointRow row : endpointRows) {
          if (!"Missing".equals(row.getBaselineStatus())) {
            String pk = row.getHost() + "|" + row.getEndpoint();
            if (baselinePathKeys.contains(pk)) {
              observedPaths.add(pk);
            }
          }
        }
      }
      covered = observedPaths.size();
      int pct = baselineTotal > 0 ? (covered * 100 / baselineTotal) : 0;
      lblCoverage.setText(covered + "/" + baselineTotal + " (" + pct + "%)");
    } else {
      lblCoverage.setText("-");
    }
  }

  // --- Persistence ---

  private void persistNotesAndTags() {
    synchronized (endpointLock) {
      for (EndpointRow row : endpointRows) {
        String key = row.getHost() + "|" + row.getEndpoint();
        String note = row.getNotes();
        String tag = row.getTag();
        if (note != null && !note.isEmpty()) notesStore.put(key, note);
        else notesStore.remove(key);
        if (tag != null && !tag.isEmpty()) tagsStore.put(key, tag);
        else tagsStore.remove(key);
      }
    }
  }

  private void doSave() {
    // Take thread-safe snapshots — endpointRows is only safe to read on EDT
    final List<EndpointRow> rowsSnapshot;
    final List<TrafficRecord> recordsSnapshot = new ArrayList<>(allRecords);
    final Map<String, String> notesSnapshot;
    final Map<String, String> tagsSnapshot;
    synchronized (endpointLock) {
      rowsSnapshot = new ArrayList<>(endpointRows);
    }
    // Persist notes/tags from the snapshot
    for (EndpointRow row : rowsSnapshot) {
      String key = row.getHost() + "|" + row.getEndpoint();
      String note = row.getNotes();
      String tag = row.getTag();
      if (note != null && !note.isEmpty()) notesStore.put(key, note);
      else notesStore.remove(key);
      if (tag != null && !tag.isEmpty()) tagsStore.put(key, tag);
      else tagsStore.remove(key);
    }
    notesSnapshot = new HashMap<>(notesStore);
    tagsSnapshot = new HashMap<>(tagsStore);
    Map<String, String> exploitsSnapshot = new HashMap<>(exploitsStore);
    persistence.saveAll(recordsSnapshot, notesSnapshot, tagsSnapshot, exploitsSnapshot);
    // Also persist baseline if loaded
    if (!swaggerBaseline.isEmpty()) {
      persistence.saveBaseline(new ArrayList<>(swaggerBaseline));
    }
  }

  private void restoreData() {
    try {
      List<TrafficRecord> savedRecords = persistence.loadRecords();
      Persistence.Annotations annotations = persistence.loadAnnotations();

      if (!savedRecords.isEmpty()
          || !annotations.getNotes().isEmpty()
          || !annotations.getTags().isEmpty()) {
        allRecords.addAll(savedRecords);
        notesStore.putAll(annotations.getNotes());
        tagsStore.putAll(annotations.getTags());
        exploitsStore.putAll(annotations.getExploits());
        statusLabel.setText(
            String.format(
                "Restored %d records, %d notes from previous session.",
                savedRecords.size(), annotations.getNotes().size()));
      }

      // Restore swagger baseline
      List<com.mockedlabs.scopeproof.model.SwaggerEndpoint> savedBaseline =
          persistence.loadBaseline();
      if (!savedBaseline.isEmpty()) {
        loadBaselineIntoMemory(savedBaseline);
        api.logging()
            .logToOutput(
                "ScopeProof: Restored " + savedBaseline.size() + " swagger baseline endpoints.");
      }

      SwingUtilities.invokeLater(this::reaggregateAndUpdate);
    } catch (Exception e) {
      api.logging().logToError("ScopeProof: Failed to restore data: " + e.getMessage());
    }
  }

  /** Load a list of SwaggerEndpoints into the baseline data structures. */
  private void loadBaselineIntoMemory(
      List<com.mockedlabs.scopeproof.model.SwaggerEndpoint> endpoints) {
    swaggerBaseline.clear();
    baselinePathKeys.clear();
    baselineMethodKeys.clear();
    swaggerBaseline.addAll(endpoints);
    for (com.mockedlabs.scopeproof.model.SwaggerEndpoint ep : endpoints) {
      String pathKey = ep.getHost() + "|" + ep.getNormalizedPath();
      baselinePathKeys.add(pathKey);
      baselineMethodKeys.add(pathKey + "|" + ep.getMethod());
    }
  }

  // --- Exports ---

  private Map<String, String> getEngagementMeta() {
    Map<String, String> meta = new HashMap<>();
    meta.put("tester", fieldTester.getText().trim());
    meta.put("client", fieldClient.getText().trim());
    meta.put("engagement", fieldEngagement.getText().trim());
    return meta;
  }

  private void doExport(String label, String ext, boolean needsMeta) {
    if (endpointRows.isEmpty()) {
      statusLabel.setText("No data to export.");
      return;
    }
    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("Export " + label);
    chooser.setFileFilter(new FileNameExtensionFilter(label + " Files", ext));
    chooser.setSelectedFile(new File("coverage_report." + ext));

    if (chooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
      String filepath = chooser.getSelectedFile().getAbsolutePath();
      if (!filepath.endsWith("." + ext)) filepath += "." + ext;
      persistNotesAndTags();

      boolean ok;
      switch (ext) {
        case "json":
          ok =
              Exporters.exportJson(
                  filepath, summary, endpointRows, getEngagementMeta(), recordIndex);
          break;
        case "csv":
          ok = Exporters.exportCsv(filepath, endpointRows);
          break;
        default:
          ok = false;
      }
      statusLabel.setText(ok ? "Exported " + label + ": " + filepath : "Export failed.");
    }
  }

  // --- Upload ---

  private void onUpload() {
    if (endpointRows.isEmpty()) {
      statusLabel.setText("No data to upload.");
      return;
    }
    String apiKey = new String(fieldApiToken.getPassword()).trim();
    if (apiKey.isEmpty()) {
      JOptionPane.showMessageDialog(
          mainPanel,
          "No API Key set.\nGo to Settings > Connection to enter your API Key.",
          "API Key Required",
          JOptionPane.WARNING_MESSAGE);
      return;
    }

    try {
      File tmp = File.createTempFile("coverage_", ".json");
      persistNotesAndTags();
      boolean ok =
          Exporters.exportJson(
              tmp.getAbsolutePath(), summary, endpointRows, getEngagementMeta(), recordIndex);
      if (!ok) {
        statusLabel.setText("Export failed.");
        tmp.delete();
        return;
      }

      statusLabel.setText("Uploading to " + SAAS_NAME + "...");
      String uploadUrl = fieldUploadUrl.getText().trim();
      if (uploadUrl.isEmpty()) uploadUrl = DEFAULT_UPLOAD_URL;
      final String url = uploadUrl;

      new Thread(
              () -> {
                try {
                  HttpURLConnection conn =
                      (HttpURLConnection) new URI(url).toURL().openConnection();
                  conn.setRequestMethod("POST");
                  conn.setRequestProperty("Content-Type", "application/json");
                  conn.setRequestProperty("X-API-Key", apiKey);
                  conn.setDoOutput(true);
                  conn.setConnectTimeout(10000);
                  conn.setReadTimeout(15000);

                  // Stream file directly to connection — avoids loading entire export into memory
                  try (OutputStream out = conn.getOutputStream();
                      InputStream in = new FileInputStream(tmp)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                      out.write(buf, 0, n);
                    }
                  }
                  int code = conn.getResponseCode();
                  conn.disconnect();

                  SwingUtilities.invokeLater(
                      () -> {
                        if (code >= 200 && code < 300) {
                          statusLabel.setText("Uploaded to " + SAAS_NAME + " successfully.");
                        } else {
                          statusLabel.setText("Upload failed: HTTP " + code);
                        }
                      });
                } catch (Exception e) {
                  api.logging().logToError("Upload error: " + e.getMessage());
                  SwingUtilities.invokeLater(
                      () -> statusLabel.setText("Upload failed. Check Extensions > Errors."));
                } finally {
                  tmp.delete();
                }
              },
              "ScopeProof-Upload")
          .start();

    } catch (Exception e) {
      statusLabel.setText("Upload failed: " + e.getMessage());
    }
  }

  // --- Public methods for SettingsDialog ---

  public void clearAllData() {
    int result =
        JOptionPane.showConfirmDialog(
            mainPanel,
            "Clear all captured data, notes, and tags?",
            "Clear All",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
    if (result != JOptionPane.YES_OPTION) return;

    allRecords.clear();
    summary = new TrafficParser.Summary();
    synchronized (endpointLock) {
      endpointRows = new ArrayList<>();
    }
    recordIndex = new HashMap<>();
    notesStore.clear();
    tagsStore.clear();
    exploitsStore.clear();
    autoSaver.forceSave();
    tableModel.setRows(new ArrayList<>());
    emptyStateLabel.setVisible(true);
    lblTotal.setText("0");
    lblHosts.setText("0");
    lblEndpoints.setText("0");
    reqListModel.clear();
    reqListLabel.setText("Select an endpoint to view requests");
    requestEditor.setRequest(HttpRequest.httpRequest(""));
    responseEditor.setResponse(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n"));
    statusLabel.setText("All data cleared.");
  }

  public void useBurpScope() {
    if (allRecords.isEmpty()) {
      statusLabel.setText("No traffic captured yet.");
      return;
    }
    Set<String> inScope = new TreeSet<>();
    Set<String> seen = new HashSet<>();
    for (TrafficRecord rec : allRecords) {
      String host = rec.getHost();
      if (seen.contains(host)) continue;
      seen.add(host);
      try {
        if (api.scope().isInScope(rec.getFullUrl())) {
          inScope.add(host);
        }
      } catch (Exception ignored) {
      }
    }
    if (!inScope.isEmpty()) {
      scopeField.setText(String.join(", ", inScope));
      statusLabel.setText("Burp scope applied: " + inScope.size() + " host(s)");
    } else {
      statusLabel.setText("No hosts in Burp target scope.");
    }
  }

  public void loadScopeFile() {
    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("Load Scope Hosts");
    chooser.setFileFilter(new FileNameExtensionFilter("Text Files", "txt"));
    if (chooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
      try (BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(
                  new FileInputStream(chooser.getSelectedFile()), StandardCharsets.UTF_8))) {
        List<String> hosts = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
          line = line.trim();
          if (!line.isEmpty() && !line.startsWith("#")) hosts.add(line);
        }
        if (!hosts.isEmpty()) {
          scopeField.setText(String.join(", ", hosts));
          statusLabel.setText("Loaded " + hosts.size() + " hosts");
        }
      } catch (Exception e) {
        statusLabel.setText("Error: " + e.getMessage());
      }
    }
  }

  /** Mark a confirmed exploit for an endpoint. Called from the "Mark Exploited" context menu. */
  public void markExploitConfirmed(String host, String normalizedEndpoint, String category) {
    String key = host + "|" + normalizedEndpoint;
    String existing = exploitsStore.getOrDefault(key, "");
    Set<String> cats = new HashSet<>();
    if (!existing.isEmpty()) {
      for (String c : existing.split(",")) {
        c = c.trim();
        if (!c.isEmpty()) cats.add(c);
      }
    }
    if (cats.add(category)) {
      exploitsStore.put(key, String.join(",", cats));
      autoSaver.markDirty();
      SwingUtilities.invokeLater(
          () -> {
            reaggregateAndUpdate();
            statusLabel.setText(
                "Exploit confirmed: " + category + " on " + host + normalizedEndpoint);
          });
    }
  }

  /** Manually flag an endpoint for review. Appears in Next Up via the "Flagged" tag. */
  public void flagForReview(String host, String normalizedEndpoint) {
    String key = host + "|" + normalizedEndpoint;
    SwingUtilities.invokeLater(
        () -> {
          // Set tag directly on the row — avoids persistNotesAndTags() overwrite
          boolean found = false;
          synchronized (endpointLock) {
            for (EndpointRow row : endpointRows) {
              if (key.equals(row.getHost() + "|" + row.getEndpoint())) {
                row.setTag(FLAGGED_TAG);
                found = true;
                break;
              }
            }
            if (!found) {
              // Create synthetic row for endpoints not yet in traffic
              EndpointRow row = new EndpointRow();
              row.setHost(host);
              row.setEndpoint(normalizedEndpoint);
              row.setTag(FLAGGED_TAG);
              row.setRequestCount(0);
              row.setTestingDepth("Untested");
              row.setPriority("High");
              row.setPriorityScore(50);
              row.setPriorityReasons(
                  new ArrayList<>(Arrays.asList("Manually flagged for review", "Untested")));
              endpointRows.add(row);
            }
          }
          tagsStore.put(key, FLAGGED_TAG);
          autoSaver.markDirty();
          updateChipCounts();
          activeChip = "Next Up";
          styleChips();
          applyTableFilter();
          statusLabel.setText("\u2691 Flagged for review: " + host + normalizedEndpoint);
        });
  }

  // --- ScopeProof Pro integration ---

  /** Derive the v1 API base URL from the configured upload URL. */
  private String deriveV1BaseUrl() {
    String baseUrl = fieldUploadUrl.getText().trim();
    try {
      URI uploadUri = new URI(baseUrl);
      String scheme = uploadUri.getScheme();
      String host = uploadUri.getHost();
      int port = uploadUri.getPort();
      String portStr = (port > 0 && port != 443 && port != 80) ? ":" + port : "";
      return scheme + "://" + host + portStr + "/api/v1/";
    } catch (Exception e) {
      return null;
    }
  }

  /**
   * Pull Swagger/OpenAPI endpoints from ScopeProof Pro as a coverage baseline. Also optionally
   * pushes endpoints into Burp Suite's site map.
   */
  public void syncSwaggerBaseline() {
    String apiKey = new String(fieldApiToken.getPassword()).trim();
    if (apiKey.isEmpty()) {
      SwingUtilities.invokeLater(
          () ->
              JOptionPane.showMessageDialog(
                  mainPanel,
                  "No API Key set.\nGo to Settings > Connection to enter your API Key.",
                  "API Key Required",
                  JOptionPane.WARNING_MESSAGE));
      return;
    }

    String v1Base = deriveV1BaseUrl();
    if (v1Base == null) {
      SwingUtilities.invokeLater(
          () ->
              JOptionPane.showMessageDialog(
                  mainPanel,
                  "The Upload URL in Settings > Connection is invalid.",
                  "Invalid URL",
                  JOptionPane.WARNING_MESSAGE));
      return;
    }

    SwingUtilities.invokeLater(
        () -> statusLabel.setText("Syncing Swagger baseline from " + SAAS_NAME + "..."));

    final String url = v1Base + "swagger-endpoints/";
    new Thread(
            () -> {
              try {
                HttpURLConnection conn = (HttpURLConnection) new URI(url).toURL().openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("X-API-Key", apiKey);
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(15000);

                int code = conn.getResponseCode();
                if (code != 200) {
                  SwingUtilities.invokeLater(
                      () -> statusLabel.setText("Swagger sync failed (HTTP " + code + ")."));
                  return;
                }

                StringBuilder sb = new StringBuilder();
                try (BufferedReader reader =
                    new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                  String line;
                  while ((line = reader.readLine()) != null) sb.append(line);
                }

                com.google.gson.JsonObject resp =
                    com.google.gson.JsonParser.parseString(sb.toString()).getAsJsonObject();
                com.google.gson.JsonArray endpointsArr = resp.getAsJsonArray("endpoints");

                if (endpointsArr == null || endpointsArr.isEmpty()) {
                  SwingUtilities.invokeLater(
                      () ->
                          statusLabel.setText(
                              "No Swagger endpoints found in "
                                  + SAAS_NAME
                                  + ". Upload a spec first."));
                  return;
                }

                List<com.mockedlabs.scopeproof.model.SwaggerEndpoint> endpoints = new ArrayList<>();
                for (var elem : endpointsArr) {
                  com.google.gson.JsonObject obj = elem.getAsJsonObject();
                  com.mockedlabs.scopeproof.model.SwaggerEndpoint ep =
                      new com.mockedlabs.scopeproof.model.SwaggerEndpoint();
                  ep.setHost(obj.has("host") ? obj.get("host").getAsString() : "");
                  ep.setPath(obj.has("path") ? obj.get("path").getAsString() : "");
                  ep.setMethod(obj.has("method") ? obj.get("method").getAsString() : "");
                  ep.setNormalizedPath(PathNormalizer.normalizeSwaggerPath(ep.getPath()));
                  ep.setOperationId(
                      obj.has("operation_id") ? obj.get("operation_id").getAsString() : "");
                  ep.setSummary(obj.has("summary") ? obj.get("summary").getAsString() : "");
                  ep.setApplicationName(
                      obj.has("application_name") ? obj.get("application_name").getAsString() : "");
                  if (obj.has("tags") && obj.get("tags").isJsonArray()) {
                    List<String> tags = new ArrayList<>();
                    for (var t : obj.getAsJsonArray("tags")) tags.add(t.getAsString());
                    ep.setTags(tags);
                  }
                  endpoints.add(ep);
                }

                // Load into memory
                loadBaselineIntoMemory(endpoints);

                // Push to Burp Site Map (non-invasive — no actual requests sent)
                int siteMapCount = 0;
                for (com.mockedlabs.scopeproof.model.SwaggerEndpoint ep : endpoints) {
                  if (ep.getHost().isEmpty()) continue;
                  try {
                    HttpService svc = HttpService.httpService(ep.getHost(), 443, true);
                    HttpRequest req =
                        HttpRequest.httpRequest(
                            svc,
                            ep.getMethod()
                                + " "
                                + ep.getPath()
                                + " HTTP/2\r\n"
                                + "Host: "
                                + ep.getHost()
                                + "\r\n\r\n");
                    api.siteMap()
                        .add(
                            burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                                req, null));
                    siteMapCount++;
                  } catch (Exception e) {
                    api.logging()
                        .logToError(
                            "ScopeProof: Site map add failed for "
                                + ep.getMethod()
                                + " "
                                + ep.getPath()
                                + ": "
                                + e.getMessage());
                  }
                }

                // Persist baseline
                persistence.saveBaseline(endpoints);

                final int baselineSize = baselinePathKeys.size();
                final int smCount = siteMapCount;
                SwingUtilities.invokeLater(
                    () -> {
                      reaggregateAndUpdate();
                      statusLabel.setText(
                          "Swagger baseline loaded: "
                              + baselineSize
                              + " endpoint paths, "
                              + smCount
                              + " added to Burp Site Map.");
                    });

              } catch (Exception e) {
                SwingUtilities.invokeLater(
                    () -> statusLabel.setText("Swagger sync error: " + e.getMessage()));
              }
            },
            "ScopeProof-SyncSwagger")
        .start();
  }

  /**
   * Send a single request/response pair to ScopeProof Pro. Runs on a background thread to avoid
   * blocking the UI.
   */
  /**
   * Show the finding dialog, then POST the finding + evidence to ScopeProof Pro. Must be called on
   * the EDT (from a context menu action).
   */
  public void reportFindingToPro(burp.api.montoya.http.message.HttpRequestResponse msg) {
    if (msg == null || msg.request() == null) return;

    String apiKey = new String(fieldApiToken.getPassword()).trim();
    if (apiKey.isEmpty()) {
      JOptionPane.showMessageDialog(
          mainPanel,
          "No API Key set.\nGo to Settings > Connection to enter your API Key.",
          "API Key Required",
          JOptionPane.WARNING_MESSAGE);
      return;
    }

    String v1Base = deriveV1BaseUrl();
    if (v1Base == null) {
      JOptionPane.showMessageDialog(
          mainPanel,
          "The Upload URL in Settings > Connection is invalid.",
          "Invalid URL",
          JOptionPane.WARNING_MESSAGE);
      return;
    }

    // Show the dialog — blocks until user confirms or cancels
    Frame frame = (Frame) SwingUtilities.getWindowAncestor(mainPanel);
    FindingDialog dialog = new FindingDialog(frame);
    dialog.setVisible(true);

    if (!dialog.isConfirmed()) return;

    // Capture dialog values before they go out of scope
    String findingTitle = dialog.getTitle();
    String severity = dialog.getSeverity();
    String category = dialog.getCategoryCode();
    String description = dialog.getDescription();
    String steps = dialog.getStepsToReproduce();

    statusLabel.setText("Reporting finding to " + SAAS_NAME + "...");

    // Build the request/response data
    var req = msg.request();
    var resp = msg.response();

    Map<String, Object> data = new LinkedHashMap<>();
    data.put("title", findingTitle);
    data.put("severity", severity);
    data.put("category", category);
    data.put("description", description);
    data.put("steps_to_reproduce", steps);

    try {
      data.put("host", req.httpService().host());
      data.put("method", req.method());
      data.put("full_url", req.url());

      String rawUrl = req.url();
      String path = "/";
      try {
        URI parsed = new URI(rawUrl);
        path = parsed.getPath();
        if (path == null || path.isEmpty()) path = "/";
      } catch (Exception e) {
        int qi = rawUrl.indexOf('?');
        path = qi >= 0 ? rawUrl.substring(0, qi) : rawUrl;
      }
      String normalizedPath = PathNormalizer.normalizePath(path);
      data.put("normalized_endpoint", normalizedPath);
      data.put("request_size", req.toByteArray().length());
      data.put("timestamp", System.currentTimeMillis());
      data.put("tool_name", "Burp Extension");

      // Include confirmed exploits for this endpoint if any
      String exploitKey = req.httpService().host() + "|" + normalizedPath;
      String confirmedStr = exploitsStore.getOrDefault(exploitKey, "");
      if (!confirmedStr.isEmpty()) {
        List<String> confirmList = new ArrayList<>();
        for (String c : confirmedStr.split(",")) {
          c = c.trim();
          if (!c.isEmpty()) confirmList.add(c);
        }
        data.put("exploits_confirmed", confirmList);
      }

      if (resp != null) {
        data.put("status_code", resp.statusCode());
        data.put("response_size", resp.toByteArray().length());
        for (var header : resp.headers()) {
          if ("content-type".equalsIgnoreCase(header.name())) {
            String ct = header.value();
            int semi = ct.indexOf(';');
            data.put("content_type", semi >= 0 ? ct.substring(0, semi).trim() : ct.trim());
            break;
          }
        }
      }

      // Auth detection
      for (var header : req.headers()) {
        String hName = header.name().toLowerCase();
        if ("authorization".equals(hName) || "cookie".equals(hName)) {
          data.put("authenticated", true);
          break;
        }
      }

      // Base64 encode request/response
      data.put("request_bytes", Base64.getEncoder().encodeToString(req.toByteArray().getBytes()));
      if (resp != null) {
        data.put(
            "response_bytes", Base64.getEncoder().encodeToString(resp.toByteArray().getBytes()));
      }
    } catch (Exception e) {
      statusLabel.setText("Error building finding: " + e.getMessage());
      return;
    }

    com.google.gson.Gson gson = new com.google.gson.Gson();
    String json = gson.toJson(data);
    String findingsUrl = v1Base + "findings/";

    // POST on background thread
    new Thread(
            () -> {
              try {
                HttpURLConnection conn =
                    (HttpURLConnection) new URI(findingsUrl).toURL().openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("X-API-Key", apiKey);
                conn.setDoOutput(true);
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(15000);

                try (OutputStream os = conn.getOutputStream()) {
                  os.write(json.getBytes(StandardCharsets.UTF_8));
                }

                int code = conn.getResponseCode();
                SwingUtilities.invokeLater(
                    () -> {
                      if (code == 200 || code == 201) {
                        statusLabel.setText(
                            "["
                                + severity.toUpperCase()
                                + "] "
                                + findingTitle
                                + " — reported to "
                                + SAAS_NAME
                                + ".");
                      } else {
                        statusLabel.setText("Finding report failed (HTTP " + code + ").");
                      }
                    });
              } catch (Exception e) {
                SwingUtilities.invokeLater(
                    () -> statusLabel.setText("Finding report error: " + e.getMessage()));
              }
            },
            "ScopeProof-ReportFinding")
        .start();
  }

  /**
   * Pull scope configuration from ScopeProof Pro and configure Burp Suite's target scope. Runs on a
   * background thread.
   */
  public void syncScopeFromPro() {
    String apiKey = new String(fieldApiToken.getPassword()).trim();
    if (apiKey.isEmpty()) {
      SwingUtilities.invokeLater(
          () ->
              JOptionPane.showMessageDialog(
                  mainPanel,
                  "No API Key set.\nGo to Settings > Connection to enter your API Key.",
                  "API Key Required",
                  JOptionPane.WARNING_MESSAGE));
      return;
    }

    String v1Base = deriveV1BaseUrl();
    if (v1Base == null) {
      SwingUtilities.invokeLater(
          () ->
              JOptionPane.showMessageDialog(
                  mainPanel,
                  "The Upload URL in Settings > Connection is invalid.",
                  "Invalid URL",
                  JOptionPane.WARNING_MESSAGE));
      return;
    }
    String scopeUrl = v1Base + "scope/";

    SwingUtilities.invokeLater(
        () -> statusLabel.setText("Syncing scope from " + SAAS_NAME + "..."));

    final String url = scopeUrl;
    new Thread(
            () -> {
              try {
                HttpURLConnection conn = (HttpURLConnection) new URI(url).toURL().openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("X-API-Key", apiKey);
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(15000);

                int code = conn.getResponseCode();
                if (code != 200) {
                  SwingUtilities.invokeLater(
                      () -> statusLabel.setText("Scope sync failed (HTTP " + code + ")."));
                  return;
                }

                // Read response
                StringBuilder sb = new StringBuilder();
                try (BufferedReader reader =
                    new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                  String line;
                  while ((line = reader.readLine()) != null) sb.append(line);
                }

                com.google.gson.JsonObject resp =
                    com.google.gson.JsonParser.parseString(sb.toString()).getAsJsonObject();
                com.google.gson.JsonArray hostsArr = resp.getAsJsonArray("hosts");

                if (hostsArr == null || hostsArr.isEmpty()) {
                  SwingUtilities.invokeLater(
                      () -> statusLabel.setText("No scope hosts configured in " + SAAS_NAME + "."));
                  return;
                }

                // Collect hosts and add to Burp scope
                List<String> hosts = new ArrayList<>();
                int added = 0;
                for (var elem : hostsArr) {
                  String h = elem.getAsString().trim();
                  if (h.isEmpty()) continue;
                  hosts.add(h);
                  try {
                    // Add both http and https to Burp scope
                    String httpsUrl = "https://" + h + "/";
                    String httpUrl = "http://" + h + "/";
                    api.scope().includeInScope(httpsUrl);
                    api.scope().includeInScope(httpUrl);
                    added++;
                  } catch (Exception e) {
                    api.logging()
                        .logToError(
                            "ScopeProof: Failed to add " + h + " to Burp scope: " + e.getMessage());
                  }
                }

                // Also update the extension's scope filter
                final int count = added;
                final String hostsCsv = String.join(", ", hosts);
                SwingUtilities.invokeLater(
                    () -> {
                      scopeField.setText(hostsCsv);
                      statusLabel.setText(
                          "Scope synced: " + count + " host(s) added to Burp target scope.");
                    });

              } catch (Exception e) {
                SwingUtilities.invokeLater(
                    () -> statusLabel.setText("Scope sync error: " + e.getMessage()));
              }
            },
            "ScopeProof-SyncScope")
        .start();
  }

  // --- Simple DocumentListener helper ---

  private static class SimpleDocListener implements DocumentListener {
    private final java.util.function.Consumer<DocumentEvent> action;

    SimpleDocListener(java.util.function.Consumer<DocumentEvent> action) {
      this.action = action;
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
      action.accept(e);
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
      action.accept(e);
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
      action.accept(e);
    }
  }
}
