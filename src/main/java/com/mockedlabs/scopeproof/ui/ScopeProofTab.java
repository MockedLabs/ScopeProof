package com.mockedlabs.scopeproof.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.EditorOptions;

import com.mockedlabs.scopeproof.export.Exporters;
import com.mockedlabs.scopeproof.model.*;
import com.mockedlabs.scopeproof.parser.*;
import com.mockedlabs.scopeproof.persistence.Persistence;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.URI;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Main ScopeProof tab panel — equivalent to the Python CoverageUI class.
 */
public class ScopeProofTab {

    // Branding
    private static final String PRODUCT_NAME = "ScopeProof";
    private static final String BRAND_URL = "scopeproof.io";
    private static final String SAAS_NAME = "ScopeProof Pro";
    public static final String VERSION = "1.0.0";
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

    // Depth display constants
    private static final String[] DEPTH_KEYS = {
        "Thoroughly Tested", "Fuzz Tested", "Manually Tested", "Observed", "Untested"
    };
    private static final Map<String, String> DEPTH_SHORTS;
    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("Thoroughly Tested", "Full");
        m.put("Fuzz Tested", "Fuzz");
        m.put("Manually Tested", "Manual");
        m.put("Observed", "Obs");
        m.put("Untested", "None");
        DEPTH_SHORTS = Collections.unmodifiableMap(m);
    }

    // Static/noise filter sets
    private static final Set<String> STATIC_EXTS = new HashSet<>(Arrays.asList(
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".webp",
        ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz"
    ));
    private static final Set<String> NOISE_DOMAINS = new HashSet<>(Arrays.asList(
        "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
        "www.google-analytics.com", "www.googletagmanager.com",
        "connect.facebook.net", "platform.twitter.com",
        "www.gstatic.com", "apis.google.com", "maps.googleapis.com",
        "translate.googleapis.com", "accounts.google.com",
        "ssl.gstatic.com", "www.google.com",
        "cdn.segment.com", "api.segment.io",
        "browser.sentry-cdn.com", "sentry.io",
        "js.stripe.com", "m.stripe.network",
        "challenges.cloudflare.com", "static.cloudflareinsights.com"
    ));
    private static final String[] TAG_OPTIONS = {
        "", "Needs Retest", "Critical Area", "Out of Scope",
        "Auth Bypass Target", "IDOR Target", "Injection Target",
        "Business Logic", "File Upload", "Custom..."
    };

    // Burp API
    private final MontoyaApi api;
    private final TrafficParser parser;
    private final AttackDetector attackDetector;
    private final Persistence persistence;

    // Data
    private final List<TrafficRecord> allRecords = new CopyOnWriteArrayList<>();
    private TrafficParser.Summary summary = new TrafficParser.Summary();
    private final Object endpointLock = new Object();
    private List<EndpointRow> endpointRows = new ArrayList<>();
    private Map<String, String> notesStore = new java.util.concurrent.ConcurrentHashMap<>();
    private Map<String, String> tagsStore = new java.util.concurrent.ConcurrentHashMap<>();
    // Index: host|endpoint → list of matching records (rebuilt on reaggregate)
    private Map<String, List<TrafficRecord>> recordIndex = new HashMap<>();
    private boolean excludeStatic = false;
    private boolean excludeNoise = false;

    // Auto-save
    private final Persistence.AutoSaver autoSaver;

    // Debounce timer for live traffic updates (500ms coalesce window)
    private final javax.swing.Timer debounceTimer;

    // UI components
    private final JPanel mainPanel;
    private final CoverageTableModel tableModel;
    private JTable mainTable;
    private final RequestListTableModel reqListModel;
    private JTable reqListTable;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    // Summary labels
    private JLabel lblTotal, lblHosts, lblEndpoints, lblDepth;
    private JLabel statusLabel;
    private JLabel reqListLabel;
    private JLabel emptyStateLabel;
    private JButton btnRefresh;

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
        this.attackDetector = new AttackDetector(
            new File(System.getProperty("user.home"), ".scopeproof"));
        this.parser = new TrafficParser(attackDetector);
        this.persistence = new Persistence();

        // Table models
        tableModel = new CoverageTableModel();
        reqListModel = new RequestListTableModel();

        // Burp native editors
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // Debounce timer: fires on EDT after 500ms of no new records
        debounceTimer = new javax.swing.Timer(500, e -> reaggregateAndUpdate());
        debounceTimer.setRepeats(false);

        // Build UI
        mainPanel = buildMainPanel();

        // Restore persisted data
        restoreData();

        // Auto-save
        autoSaver = new Persistence.AutoSaver(this::doSave, 30);
        autoSaver.start();
    }

    public JComponent getComponent() { return mainPanel; }
    public TrafficParser getParser() { return parser; }
    public AttackDetector getAttackDetector() { return attackDetector; }

    // Expose fields for SettingsDialog
    public JTextField getFieldTester() { return fieldTester; }
    public JTextField getFieldClient() { return fieldClient; }
    public JTextField getFieldEngagement() { return fieldEngagement; }
    public JTextField getFieldUploadUrl() { return fieldUploadUrl; }
    public JPasswordField getFieldApiToken() { return fieldApiToken; }
    public JCheckBox getChkExcludeStatic() { return chkExcludeStatic; }
    public JCheckBox getChkExcludeNoise() { return chkExcludeNoise; }
    public String getScopeText() { return scopeField.getText(); }
    public void setScopeText(String text) { scopeField.setText(text); }

    // --- Public API ---

    public void addLiveRecord(TrafficRecord record) {
        allRecords.add(record);
        autoSaver.markDirty();
        // Debounce: restart the 500ms timer so rapid bursts coalesce into one update
        SwingUtilities.invokeLater(debounceTimer::restart);
    }

    public void shutdown() {
        debounceTimer.stop();
        autoSaver.stop();
        autoSaver.forceSave();
    }

    public void refreshFromMenu() { onRefresh(); }

    public void exportJsonFromMenu() { doExport("JSON", "json", true); }

    public void exportCsvFromMenu() { doExport("CSV", "csv", false); }

    public void openSettings() {
        Frame frame = (Frame) SwingUtilities.getWindowAncestor(mainPanel);
        new SettingsDialog(frame, this).setVisible(true);
    }

    public void reaggregateAndUpdate() {
        persistNotesAndTags();
        List<TrafficRecord> filtered = filterRecords(new ArrayList<>(allRecords));
        TrafficParser.AggregationResult result = TrafficParser.aggregate(
            filtered, notesStore, tagsStore);
        this.summary = result.getSummary();
        synchronized (endpointLock) {
            this.endpointRows = result.getEndpointRows();
        }
        // Rebuild record index for fast row selection lookups
        Map<String, List<TrafficRecord>> idx = new HashMap<>();
        for (TrafficRecord rec : filtered) {
            String key = rec.getHost() + "|" + rec.getNormalizedEndpoint();
            idx.computeIfAbsent(key, k -> new ArrayList<>()).add(rec);
        }
        this.recordIndex = idx;
        updateSummary();
        applyTableFilter();
        emptyStateLabel.setVisible(endpointRows.isEmpty());
        statusLabel.setText(String.format("%d requests | %d endpoints | %d hosts",
            summary.getTotalRequests(), summary.getUniqueEndpoints(),
            summary.getUniqueHosts()));
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
        scopeField.setBackground(new Color(240, 240, 244));
        scopeField.setToolTipText("Configure scope in Settings > Filters");
        scopeField.getDocument().addDocumentListener(new SimpleDocListener(e -> applyScopeFilter()));
        left.add(scopeField);

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

        JButton btnJson = new JButton("JSON");
        btnJson.setFont(FONT_SMALL);
        btnJson.addActionListener(e -> doExport("JSON", "json", true));
        right.add(btnJson);

        JButton btnCsv = new JButton("CSV");
        btnCsv.setFont(FONT_SMALL);
        btnCsv.addActionListener(e -> doExport("CSV", "csv", false));
        right.add(btnCsv);

        right.add(Box.createHorizontalStrut(4));

        JButton btnUpload = new JButton("Upload to Pro");
        btnUpload.setFont(new Font("SansSerif", Font.BOLD, 12));
        btnUpload.setForeground(CLR_BRAND);
        btnUpload.addActionListener(e -> onUpload());
        right.add(btnUpload);

        right.add(Box.createHorizontalStrut(4));

        JButton btnSettings = new JButton("Settings");
        btnSettings.setFont(FONT_BODY);
        btnSettings.addActionListener(e -> {
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
        lblDepth = makeCard("Depth", "-");
        centre.add(summaryPanel, BorderLayout.NORTH);

        // Filter checkboxes (used by SettingsDialog)
        chkExcludeStatic = new JCheckBox("Hide static resources", false);
        chkExcludeStatic.addActionListener(e -> {
            excludeStatic = chkExcludeStatic.isSelected();
            if (!allRecords.isEmpty()) reaggregateAndUpdate();
        });
        chkExcludeNoise = new JCheckBox("Hide noise domains", false);
        chkExcludeNoise.addActionListener(e -> {
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

        int[] widths = {130, 220, 70, 40, 60, 90, 130, 90, 100, 70, 120};
        for (int i = 0; i < widths.length; i++) {
            mainTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        mainTable.getColumnModel().getColumn(2).setCellRenderer(new CellRenderers.MethodCellRenderer());
        mainTable.getColumnModel().getColumn(4).setCellRenderer(new CellRenderers.PriorityCellRenderer());
        mainTable.getColumnModel().getColumn(5).setCellRenderer(new CellRenderers.DepthCellRenderer());
        mainTable.getColumnModel().getColumn(8).setCellRenderer(new CellRenderers.TestsCellRenderer());

        // Column header tooltips for interactive columns
        mainTable.getColumnModel().getColumn(9).setHeaderValue("Tag");
        mainTable.getColumnModel().getColumn(10).setHeaderValue("Notes");
        mainTable.getTableHeader().setToolTipText("Double-click Tag or Notes columns to edit");

        // Tag double-click
        mainTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = mainTable.rowAtPoint(e.getPoint());
                    int col = mainTable.columnAtPoint(e.getPoint());
                    if (col == 9 && row >= 0) onTagEdit(row);
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
        reqListTable.getColumnModel().getColumn(5).setCellRenderer(new CellRenderers.TestsCellRenderer());

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
        JSplitPane reqRespSplit = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            requestEditor.uiComponent(),
            responseEditor.uiComponent()
        );
        reqRespSplit.setResizeWeight(0.5);

        // Detail pane
        JPanel detailPanel = new JPanel(new BorderLayout(0, 2));
        detailPanel.setBackground(CLR_BG);
        reqListPanel.setPreferredSize(new Dimension(0, 130));
        reqListPanel.setMinimumSize(new Dimension(0, 80));
        detailPanel.add(reqListPanel, BorderLayout.NORTH);
        detailPanel.add(reqRespSplit, BorderLayout.CENTER);

        // Selection listeners
        reqListTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onRequestListSelected();
        });
        mainTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onRowSelected();
        });

        // Table scroll pane with empty-state message
        JScrollPane tableScroll = new JScrollPane(mainTable);
        emptyStateLabel = new JLabel(
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
        JSplitPane mainSplit = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            tableWrapper,
            detailPanel
        );
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

    private JLabel makeCard(String title, String value) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(Color.WHITE);
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(CLR_BORDER),
            BorderFactory.createEmptyBorder(6, 12, 6, 12)
        ));

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
        List<TrafficRecord> matching = new ArrayList<>(
            recordIndex.getOrDefault(indexKey, Collections.emptyList()));
        matching.sort((a, b) -> {
            Long ta = a.getTimestamp();
            Long tb = b.getTimestamp();
            if (ta == null && tb == null) return 0;
            if (ta == null) return 1;
            if (tb == null) return -1;
            return Long.compare(tb, ta);
        });

        reqListModel.setRows(matching);
        reqListLabel.setText(String.format("%d request%s for %s %s",
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
            HttpService service = HttpService.httpService(
                rec.getHost(), rec.getPort(), rec.isSecure());
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
            } catch (Exception ignored) {}
        }
    }

    private void onTagEdit(int viewRow) {
        int modelRow = mainTable.convertRowIndexToModel(viewRow);
        EndpointRow rowData = tableModel.getRow(modelRow);
        if (rowData == null) return;

        String current = rowData.getTag();
        Object result = JOptionPane.showInputDialog(
            mainPanel,
            "Tag for: " + rowData.getHost() + " " + rowData.getEndpoint(),
            "Set Tag", JOptionPane.PLAIN_MESSAGE, null,
            TAG_OPTIONS, current != null && Arrays.asList(TAG_OPTIONS).contains(current) ? current : ""
        );

        if (result != null) {
            String tag = result.toString();
            if ("Custom...".equals(tag)) {
                tag = JOptionPane.showInputDialog(mainPanel, "Enter custom tag:",
                    "Custom Tag", JOptionPane.PLAIN_MESSAGE);
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

        new Thread(() -> {
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
                SwingUtilities.invokeLater(() -> {
                    reaggregateAndUpdate();
                    statusLabel.setText("Scan complete. " + nc + " new records.");
                    btnRefresh.setEnabled(true);
                });
            } catch (Exception e) {
                api.logging().logToError("Refresh error: " + e.getMessage());
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Refresh failed. Check Extensions > Errors.");
                    btnRefresh.setEnabled(true);
                });
            }
        }, "ScopeProof-Refresh").start();
    }

    // --- Filter / scope ---

    private void applyScopeFilter() {
        if (!allRecords.isEmpty()) reaggregateAndUpdate();
    }

    private void applyTableFilter() {
        String query = filterField.getText().trim().toLowerCase();
        if (query.isEmpty()) {
            tableModel.setRows(endpointRows);
            return;
        }
        List<EndpointRow> filtered = new ArrayList<>();
        for (EndpointRow row : endpointRows) {
            String searchable = String.join(" ",
                row.getHost(), row.getEndpoint(),
                String.join(", ", row.getMethods()),
                row.getTestedBy(), row.getTestingDepth(),
                row.getPriority(), row.getTag(), row.getNotes(),
                String.join(", ", row.getTestsDetected())
            ).toLowerCase();
            if (searchable.contains(query)) filtered.add(row);
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
        for (String ext : STATIC_EXTS) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
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

        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, Integer> e : depthCounts.entrySet()) {
            if (e.getValue() > 0) {
                parts.add(DEPTH_SHORTS.getOrDefault(e.getKey(), e.getKey()) + ":" + e.getValue());
            }
        }
        lblDepth.setText(parts.isEmpty() ? "-" : String.join(" ", parts));
    }

    // --- Persistence ---

    private void persistNotesAndTags() {
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
        persistence.saveAll(recordsSnapshot, notesSnapshot, tagsSnapshot);
    }

    private void restoreData() {
        try {
            List<TrafficRecord> savedRecords = persistence.loadRecords();
            Persistence.Annotations annotations = persistence.loadAnnotations();

            if (!savedRecords.isEmpty() || !annotations.getNotes().isEmpty()
                    || !annotations.getTags().isEmpty()) {
                allRecords.addAll(savedRecords);
                notesStore.putAll(annotations.getNotes());
                tagsStore.putAll(annotations.getTags());
                statusLabel.setText(String.format(
                    "Restored %d records, %d notes from previous session.",
                    savedRecords.size(), annotations.getNotes().size()));
                SwingUtilities.invokeLater(this::reaggregateAndUpdate);
            }
        } catch (Exception e) {
            api.logging().logToError("ScopeProof: Failed to restore data: " + e.getMessage());
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
                    ok = Exporters.exportJson(filepath, summary, endpointRows, getEngagementMeta());
                    break;
                case "csv":
                    ok = Exporters.exportCsv(filepath, endpointRows);
                    break;
                default:
                    ok = false;
            }
            statusLabel.setText(ok
                ? "Exported " + label + ": " + filepath
                : "Export failed.");
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
            JOptionPane.showMessageDialog(mainPanel,
                "No API Key set.\nGo to Settings > Connection to enter your API Key.",
                "API Key Required", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            File tmp = File.createTempFile("coverage_", ".json");
            persistNotesAndTags();
            boolean ok = Exporters.exportJson(tmp.getAbsolutePath(), summary,
                endpointRows, getEngagementMeta());
            if (!ok) {
                statusLabel.setText("Export failed.");
                tmp.delete();
                return;
            }

            statusLabel.setText("Uploading to " + SAAS_NAME + "...");
            String uploadUrl = fieldUploadUrl.getText().trim();
            if (uploadUrl.isEmpty()) uploadUrl = DEFAULT_UPLOAD_URL;
            final String url = uploadUrl;

            new Thread(() -> {
                try {
                    String json = new String(java.nio.file.Files.readAllBytes(tmp.toPath()),
                        StandardCharsets.UTF_8);
                    HttpURLConnection conn = (HttpURLConnection) new URI(url).toURL().openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setRequestProperty("X-API-Key", apiKey);
                    conn.setDoOutput(true);
                    conn.setConnectTimeout(10000);
                    conn.setReadTimeout(15000);

                    try (OutputStream out = conn.getOutputStream()) {
                        out.write(json.getBytes(StandardCharsets.UTF_8));
                    }
                    int code = conn.getResponseCode();
                    conn.disconnect();

                    SwingUtilities.invokeLater(() -> {
                        if (code >= 200 && code < 300) {
                            statusLabel.setText("Uploaded to " + SAAS_NAME + " successfully.");
                        } else {
                            statusLabel.setText("Upload failed: HTTP " + code);
                        }
                    });
                } catch (Exception e) {
                    api.logging().logToError("Upload error: " + e.getMessage());
                    SwingUtilities.invokeLater(() ->
                        statusLabel.setText("Upload failed. Check Extensions > Errors."));
                } finally {
                    tmp.delete();
                }
            }, "ScopeProof-Upload").start();

        } catch (Exception e) {
            statusLabel.setText("Upload failed: " + e.getMessage());
        }
    }

    // --- Public methods for SettingsDialog ---

    public void clearAllData() {
        int result = JOptionPane.showConfirmDialog(mainPanel,
            "Clear all captured data, notes, and tags?",
            "Clear All", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (result != JOptionPane.YES_OPTION) return;

        allRecords.clear();
        summary = new TrafficParser.Summary();
        synchronized (endpointLock) {
            endpointRows = new ArrayList<>();
        }
        recordIndex = new HashMap<>();
        notesStore.clear();
        tagsStore.clear();
        autoSaver.forceSave();
        tableModel.setRows(new ArrayList<>());
        emptyStateLabel.setVisible(true);
        lblTotal.setText("0");
        lblHosts.setText("0");
        lblEndpoints.setText("0");
        lblDepth.setText("-");
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
            } catch (Exception ignored) {}
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
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(new FileInputStream(chooser.getSelectedFile()),
                        StandardCharsets.UTF_8))) {
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

    // --- Simple DocumentListener helper ---

    private static class SimpleDocListener implements DocumentListener {
        private final java.util.function.Consumer<DocumentEvent> action;
        SimpleDocListener(java.util.function.Consumer<DocumentEvent> action) {
            this.action = action;
        }
        @Override public void insertUpdate(DocumentEvent e) { action.accept(e); }
        @Override public void removeUpdate(DocumentEvent e) { action.accept(e); }
        @Override public void changedUpdate(DocumentEvent e) { action.accept(e); }
    }
}
