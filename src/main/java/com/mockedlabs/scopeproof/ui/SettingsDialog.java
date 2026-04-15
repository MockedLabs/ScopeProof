package com.mockedlabs.scopeproof.ui;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.io.*;
import java.util.*;
import java.util.List;
import javax.swing.*;

/** Modal settings dialog with tabbed sections. */
public class SettingsDialog extends JDialog {

  private final ScopeProofTab tab;

  // Payloads tab state
  private JComboBox<String> categoryCombo;
  private DefaultListModel<String> payloadListModel;
  private JList<String> payloadList;
  private JLabel payloadCountLabel;

  public SettingsDialog(Frame parent, ScopeProofTab tab) {
    super(parent, "ScopeProof Settings", true);
    this.tab = tab;
    setSize(560, 520);
    setLocationRelativeTo(parent);
    setResizable(false);
    buildUI();
  }

  private void buildUI() {
    JPanel root = new JPanel(new BorderLayout());
    root.setBackground(Color.WHITE);

    JTabbedPane tabs = new JTabbedPane();
    tabs.setFont(new Font("SansSerif", Font.PLAIN, 12));

    tabs.addTab("Engagement", buildEngagementTab());
    tabs.addTab("Connection", buildConnectionTab());
    tabs.addTab("Filters", buildFiltersTab());
    tabs.addTab("Payloads", buildPayloadsTab());
    tabs.addTab("Data", buildDataTab());

    root.add(tabs, BorderLayout.CENTER);

    JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
    bottom.setBackground(new Color(245, 245, 248));
    JButton btnClose = new JButton("Done");
    btnClose.addActionListener(e -> dispose());
    bottom.add(btnClose);
    root.add(bottom, BorderLayout.SOUTH);

    setContentPane(root);
  }

  private JPanel makeFormPanel() {
    JPanel p = new JPanel(new GridBagLayout());
    p.setBackground(Color.WHITE);
    p.setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));
    return p;
  }

  private void addField(JPanel panel, int row, String labelText, JComponent field) {
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.insets = new Insets(6, 0, 6, 10);
    gbc.anchor = GridBagConstraints.WEST;

    JLabel lbl = new JLabel(labelText);
    gbc.gridx = 0;
    gbc.gridy = row;
    gbc.weightx = 0.0;
    gbc.fill = GridBagConstraints.NONE;
    panel.add(lbl, gbc);

    gbc.gridx = 1;
    gbc.weightx = 1.0;
    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.insets = new Insets(6, 0, 6, 0);
    panel.add(field, gbc);
  }

  private JPanel buildEngagementTab() {
    JPanel panel = makeFormPanel();
    addField(panel, 0, "Tester:", tab.getFieldTester());
    addField(panel, 1, "Client:", tab.getFieldClient());
    addField(panel, 2, "Engagement:", tab.getFieldEngagement());
    addSpacer(panel, 3);
    return panel;
  }

  private JPanel buildConnectionTab() {
    JPanel panel = makeFormPanel();
    addField(panel, 0, "Upload URL:", tab.getFieldUploadUrl());
    addField(panel, 1, "API Key:", tab.getFieldApiToken());

    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 2;
    gbc.gridwidth = 2;
    gbc.insets = new Insets(12, 0, 0, 0);
    gbc.anchor = GridBagConstraints.WEST;
    JLabel help =
        new JLabel(
            "<html><span style='color:#6e7382;font-size:10px;'>"
                + "Get your API Key from the Team Settings page in ScopeProof Pro.<br>"
                + "The key authenticates uploads from this extension."
                + "</span></html>");
    panel.add(help, gbc);

    // Pro sync buttons
    JPanel syncRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    syncRow.setBackground(Color.WHITE);
    JButton btnSyncSwagger = new JButton("Sync Swagger Baseline");
    btnSyncSwagger.setToolTipText(
        "Pull Swagger/OpenAPI endpoints as coverage baseline and populate Burp Site Map");
    btnSyncSwagger.addActionListener(e -> tab.syncSwaggerBaseline());
    syncRow.add(btnSyncSwagger);
    JButton btnSyncScope = new JButton("Sync Scope");
    btnSyncScope.setToolTipText("Pull scope hosts and configure Burp target scope");
    btnSyncScope.addActionListener(e -> tab.syncScopeFromPro());
    syncRow.add(btnSyncScope);

    gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 3;
    gbc.gridwidth = 2;
    gbc.anchor = GridBagConstraints.WEST;
    gbc.insets = new Insets(12, 0, 0, 0);
    panel.add(syncRow, gbc);

    addSpacer(panel, 4);
    return panel;
  }

  private JPanel buildFiltersTab() {
    JPanel panel = makeFormPanel();

    JCheckBox chkStatic = tab.getChkExcludeStatic();
    chkStatic.setBackground(Color.WHITE);
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 0;
    gbc.gridwidth = 2;
    gbc.anchor = GridBagConstraints.WEST;
    gbc.insets = new Insets(4, 0, 4, 0);
    panel.add(chkStatic, gbc);

    JCheckBox chkNoise = tab.getChkExcludeNoise();
    chkNoise.setBackground(Color.WHITE);
    gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 1;
    gbc.gridwidth = 2;
    gbc.anchor = GridBagConstraints.WEST;
    gbc.insets = new Insets(4, 0, 4, 0);
    panel.add(chkNoise, gbc);

    // Editable scope field
    JTextField scopeEdit = new JTextField(tab.getScopeText(), 28);
    scopeEdit.setFont(new Font("SansSerif", Font.PLAIN, 12));
    scopeEdit.setToolTipText("Comma-separated hosts. Supports wildcards: *.example.com");
    addField(panel, 2, "Scope hosts:", scopeEdit);

    // Apply button + import buttons
    JPanel scopeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
    scopeRow.setBackground(Color.WHITE);
    JButton btnApply = new JButton("Apply");
    btnApply.addActionListener(e -> tab.setScopeText(scopeEdit.getText().trim()));
    scopeRow.add(btnApply);
    JButton btnBurpScope = new JButton("Use Burp Scope");
    btnBurpScope.addActionListener(
        e -> {
          tab.useBurpScope();
          scopeEdit.setText(tab.getScopeText());
        });
    scopeRow.add(btnBurpScope);
    JButton btnLoadScope = new JButton("Load from File");
    btnLoadScope.addActionListener(
        e -> {
          tab.loadScopeFile();
          scopeEdit.setText(tab.getScopeText());
        });
    scopeRow.add(btnLoadScope);
    JButton btnClearScope = new JButton("Clear");
    btnClearScope.addActionListener(
        e -> {
          scopeEdit.setText("");
          tab.setScopeText("");
        });
    scopeRow.add(btnClearScope);

    gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 3;
    gbc.gridwidth = 2;
    gbc.anchor = GridBagConstraints.WEST;
    gbc.insets = new Insets(6, 0, 4, 0);
    panel.add(scopeRow, gbc);

    addSpacer(panel, 4);
    return panel;
  }

  // --- Payloads tab (Intruder-style) ---

  private JPanel buildPayloadsTab() {
    JPanel panel = new JPanel(new BorderLayout(0, 6));
    panel.setBackground(Color.WHITE);
    panel.setBorder(BorderFactory.createEmptyBorder(10, 12, 8, 12));

    // Top: category selector + count
    JPanel topBar = new JPanel(new BorderLayout(8, 0));
    topBar.setBackground(Color.WHITE);

    JPanel catPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
    catPanel.setBackground(Color.WHITE);
    catPanel.add(new JLabel("Category:"));
    categoryCombo = new JComboBox<>(tab.getAttackDetector().getCategories().toArray(new String[0]));
    categoryCombo.setFont(new Font("SansSerif", Font.PLAIN, 12));
    categoryCombo.addActionListener(e -> refreshPayloadList());
    catPanel.add(categoryCombo);

    JButton btnAddCat = new JButton("+");
    btnAddCat.setFont(new Font("SansSerif", Font.BOLD, 12));
    btnAddCat.setMargin(new Insets(1, 6, 1, 6));
    btnAddCat.setToolTipText("Add a custom category");
    btnAddCat.addActionListener(e -> addCategory());
    catPanel.add(btnAddCat);

    JButton btnRemoveCat = new JButton("\u2212");
    btnRemoveCat.setFont(new Font("SansSerif", Font.BOLD, 12));
    btnRemoveCat.setMargin(new Insets(1, 6, 1, 6));
    btnRemoveCat.setToolTipText("Remove selected custom category");
    btnRemoveCat.addActionListener(e -> removeCategory());
    catPanel.add(btnRemoveCat);

    topBar.add(catPanel, BorderLayout.WEST);

    payloadCountLabel = new JLabel("");
    payloadCountLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
    payloadCountLabel.setForeground(new Color(110, 115, 130));
    topBar.add(payloadCountLabel, BorderLayout.EAST);

    panel.add(topBar, BorderLayout.NORTH);

    // Center: payload list
    payloadListModel = new DefaultListModel<>();
    payloadList = new JList<>(payloadListModel);
    payloadList.setFont(new Font("Monospaced", Font.PLAIN, 12));
    payloadList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
    JScrollPane listScroll = new JScrollPane(payloadList);
    panel.add(listScroll, BorderLayout.CENTER);

    // Right: action buttons (Intruder-style vertical stack)
    JPanel btnPanel = new JPanel();
    btnPanel.setLayout(new BoxLayout(btnPanel, BoxLayout.Y_AXIS));
    btnPanel.setBackground(Color.WHITE);
    btnPanel.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));

    JTextField addField = new JTextField(16);
    addField.setFont(new Font("Monospaced", Font.PLAIN, 12));
    addField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
    btnPanel.add(addField);
    btnPanel.add(Box.createVerticalStrut(4));

    JButton btnAdd = makeButton("Add");
    btnAdd.addActionListener(
        e -> {
          String text = addField.getText().trim();
          if (!text.isEmpty()) {
            String cat = (String) categoryCombo.getSelectedItem();
            if (tab.getAttackDetector().addPayload(cat, text)) {
              addField.setText("");
              refreshPayloadList();
              tab.reaggregateAndUpdate();
            }
          }
        });
    // Enter key in field triggers Add
    addField.addActionListener(e -> btnAdd.doClick());
    btnPanel.add(btnAdd);
    btnPanel.add(Box.createVerticalStrut(8));

    JButton btnPaste = makeButton("Paste");
    btnPaste.setToolTipText("Paste payloads from clipboard (one per line)");
    btnPaste.addActionListener(e -> pasteFromClipboard());
    btnPanel.add(btnPaste);
    btnPanel.add(Box.createVerticalStrut(4));

    JButton btnLoad = makeButton("Load ...");
    btnLoad.setToolTipText("Load payloads from a text file (one per line)");
    btnLoad.addActionListener(e -> loadFromFile());
    btnPanel.add(btnLoad);
    btnPanel.add(Box.createVerticalStrut(16));

    // --- Export ---
    JLabel exportLabel = new JLabel("Export:");
    exportLabel.setFont(new Font("SansSerif", Font.PLAIN, 10));
    exportLabel.setForeground(new Color(110, 115, 130));
    exportLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
    btnPanel.add(exportLabel);
    btnPanel.add(Box.createVerticalStrut(4));

    JButton btnCopy = makeButton("Copy");
    btnCopy.setToolTipText("Copy payloads to clipboard — paste into Intruder's payload list");
    btnCopy.addActionListener(e -> copyToClipboard());
    btnPanel.add(btnCopy);
    btnPanel.add(Box.createVerticalStrut(4));

    JButton btnSave = makeButton("Save ...");
    btnSave.setToolTipText("Save payloads to file — load into Intruder via Load...");
    btnSave.addActionListener(e -> saveToFile());
    btnPanel.add(btnSave);
    btnPanel.add(Box.createVerticalStrut(16));

    JButton btnRemove = makeButton("Remove");
    btnRemove.addActionListener(e -> removeSelected());
    btnPanel.add(btnRemove);
    btnPanel.add(Box.createVerticalStrut(4));

    JButton btnClear = makeButton("Clear");
    btnClear.setForeground(new Color(220, 38, 38));
    btnClear.addActionListener(e -> clearCategory());
    btnPanel.add(btnClear);

    btnPanel.add(Box.createVerticalGlue());
    panel.add(btnPanel, BorderLayout.EAST);

    refreshPayloadList();
    return panel;
  }

  private JButton makeButton(String text) {
    JButton btn = new JButton(text);
    btn.setFont(new Font("SansSerif", Font.PLAIN, 11));
    btn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
    btn.setAlignmentX(Component.LEFT_ALIGNMENT);
    return btn;
  }

  private void refreshCategoryCombo() {
    String selected = (String) categoryCombo.getSelectedItem();
    categoryCombo.removeAllItems();
    for (String cat : tab.getAttackDetector().getCategories()) {
      categoryCombo.addItem(cat);
    }
    if (selected != null) {
      categoryCombo.setSelectedItem(selected);
    }
  }

  private void addCategory() {
    String name =
        JOptionPane.showInputDialog(
            this, "New category name:", "Add Category", JOptionPane.PLAIN_MESSAGE);
    if (name == null || name.trim().isEmpty()) return;
    name = name.trim();
    if (name.length() > 40) name = name.substring(0, 40);
    if (tab.getAttackDetector().addCategory(name)) {
      refreshCategoryCombo();
      categoryCombo.setSelectedItem(name);
    } else {
      JOptionPane.showMessageDialog(
          this, "Category already exists.", "Duplicate", JOptionPane.WARNING_MESSAGE);
    }
  }

  private void removeCategory() {
    String cat = selectedCategory();
    if (cat == null) return;
    if (!tab.getAttackDetector().removeCategory(cat)) {
      JOptionPane.showMessageDialog(
          this,
          "Default categories cannot be removed.",
          "Cannot Remove",
          JOptionPane.WARNING_MESSAGE);
      return;
    }
    refreshCategoryCombo();
    refreshPayloadList();
    tab.reaggregateAndUpdate();
  }

  private String selectedCategory() {
    return (String) categoryCombo.getSelectedItem();
  }

  private void refreshPayloadList() {
    payloadListModel.clear();
    String cat = selectedCategory();
    Map<String, List<String>> all = tab.getAttackDetector().getPayloads();
    List<String> items = all.getOrDefault(cat, Collections.emptyList());
    for (String item : items) {
      payloadListModel.addElement(item);
    }

    // Count across all categories
    int total = 0;
    for (List<String> v : all.values()) total += v.size();
    payloadCountLabel.setText(items.size() + " in " + cat + " | " + total + " total");
  }

  private void pasteFromClipboard() {
    try {
      String clip =
          (String)
              Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
      if (clip == null || clip.trim().isEmpty()) return;

      String[] lines = clip.split("\\r?\\n");
      List<String> payloads = new ArrayList<>();
      for (String line : lines) {
        line = line.trim();
        if (!line.isEmpty()) payloads.add(line);
      }

      if (!payloads.isEmpty()) {
        String cat = selectedCategory();
        int added = tab.getAttackDetector().addPayloads(cat, payloads);
        refreshPayloadList();
        if (added > 0) tab.reaggregateAndUpdate();
      }
    } catch (Exception e) {
      System.err.println("ScopeProof: Paste failed: " + e.getMessage());
    }
  }

  private void loadFromFile() {
    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("Load Payloads");
    chooser.setFileFilter(
        new javax.swing.filechooser.FileNameExtensionFilter("Text Files", "txt", "lst", "csv"));
    if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
      try (BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(
                  new FileInputStream(chooser.getSelectedFile()),
                  java.nio.charset.StandardCharsets.UTF_8))) {
        List<String> payloads = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
          line = line.trim();
          if (!line.isEmpty() && !line.startsWith("#")) payloads.add(line);
        }
        if (!payloads.isEmpty()) {
          String cat = selectedCategory();
          int added = tab.getAttackDetector().addPayloads(cat, payloads);
          refreshPayloadList();
          if (added > 0) tab.reaggregateAndUpdate();
        }
      } catch (Exception e) {
        System.err.println("ScopeProof: Load payloads failed: " + e.getMessage());
      }
    }
  }

  private void removeSelected() {
    List<String> selected = payloadList.getSelectedValuesList();
    if (selected.isEmpty()) return;
    String cat = selectedCategory();
    for (String s : selected) {
      tab.getAttackDetector().removePayload(cat, s);
    }
    refreshPayloadList();
    tab.reaggregateAndUpdate();
  }

  private void clearCategory() {
    String cat = selectedCategory();
    tab.getAttackDetector().clearPayloads(cat);
    refreshPayloadList();
    tab.reaggregateAndUpdate();
  }

  private void copyToClipboard() {
    String cat = selectedCategory();
    List<String> items =
        tab.getAttackDetector().getPayloads().getOrDefault(cat, Collections.emptyList());
    if (items.isEmpty()) return;

    String text = String.join("\n", items);
    java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(text);
    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
    payloadCountLabel.setText(
        "Copied "
            + items.size()
            + " "
            + cat
            + " payload"
            + (items.size() != 1 ? "s" : "")
            + " to clipboard");
  }

  private void saveToFile() {
    String cat = selectedCategory();
    List<String> items =
        tab.getAttackDetector().getPayloads().getOrDefault(cat, Collections.emptyList());
    if (items.isEmpty()) return;

    JFileChooser chooser = new JFileChooser();
    chooser.setDialogTitle("Save " + cat + " Payloads");
    chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Text Files", "txt"));
    chooser.setSelectedFile(
        new java.io.File(cat.toLowerCase().replace(" ", "_") + "_payloads.txt"));
    if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
      try {
        String path = chooser.getSelectedFile().getAbsolutePath();
        if (!path.endsWith(".txt")) path += ".txt";
        try (java.io.PrintWriter w =
            new java.io.PrintWriter(
                new java.io.OutputStreamWriter(
                    new java.io.FileOutputStream(path), java.nio.charset.StandardCharsets.UTF_8))) {
          for (String item : items) {
            w.println(item);
          }
        }
        payloadCountLabel.setText("Saved " + items.size() + " payloads to file");
      } catch (Exception e) {
        System.err.println("ScopeProof: Save payloads failed: " + e.getMessage());
      }
    }
  }

  // --- Other tabs ---

  private JPanel buildDataTab() {
    JPanel panel = makeFormPanel();

    JButton btnClearAll = new JButton("Clear All Data");
    btnClearAll.setForeground(new Color(220, 38, 38));
    btnClearAll.setPreferredSize(new Dimension(200, 30));
    btnClearAll.addActionListener(e -> tab.clearAllData());

    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 0;
    gbc.anchor = GridBagConstraints.WEST;
    gbc.insets = new Insets(4, 0, 4, 10);
    panel.add(btnClearAll, gbc);

    JLabel lbl = new JLabel("Reset all captured data, notes, and tags");
    lbl.setFont(new Font("SansSerif", Font.PLAIN, 11));
    lbl.setForeground(new Color(110, 115, 130));
    gbc.gridx = 1;
    gbc.insets = new Insets(4, 0, 4, 0);
    panel.add(lbl, gbc);

    addSpacer(panel, 1);
    return panel;
  }

  private void addSpacer(JPanel panel, int row) {
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridy = row;
    gbc.weighty = 1.0;
    gbc.fill = GridBagConstraints.VERTICAL;
    panel.add(new JLabel(""), gbc);
  }
}
