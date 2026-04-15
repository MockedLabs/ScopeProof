package com.mockedlabs.scopeproof.ui;

import java.awt.*;
import javax.swing.*;

/**
 * Modal dialog for reporting a vulnerability finding to ScopeProof Pro. Collects: title, severity,
 * OWASP category, description.
 */
public class FindingDialog extends JDialog {

  private static final String[] SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"};

  // OWASP Testing Guide v4.2 categories (matches Django model)
  private static final String[][] CATEGORIES = {
    {"", "(None)"},
    {"INFO", "Information Gathering"},
    {"CONF", "Configuration and Deployment Management"},
    {"IDEN", "Identity Management"},
    {"AUTHN", "Authentication"},
    {"AUTHZ", "Authorization"},
    {"SESS", "Session Management"},
    {"INPV", "Input Validation"},
    {"ERRH", "Error Handling"},
    {"CRYP", "Cryptography"},
    {"BUSL", "Business Logic"},
    {"CLNT", "Client-side"},
    {"APIS", "API Testing"},
  };

  private JTextField titleField;
  private JComboBox<String> severityCombo;
  private JComboBox<String> categoryCombo;
  private JTextArea descriptionArea;
  private JTextArea stepsArea;
  private boolean confirmed = false;

  public FindingDialog(Frame parent) {
    super(parent, "Report Finding to ScopeProof Pro", true);
    setSize(520, 480);
    setLocationRelativeTo(parent);
    setResizable(false);
    buildUI();
  }

  private void buildUI() {
    JPanel root = new JPanel(new BorderLayout(0, 0));
    root.setBackground(Color.WHITE);

    // Header
    JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 8));
    header.setBackground(new Color(26, 86, 219));
    JLabel headerLabel = new JLabel("Report a Vulnerability Finding");
    headerLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
    headerLabel.setForeground(Color.WHITE);
    header.add(headerLabel);
    root.add(header, BorderLayout.NORTH);

    // Form
    JPanel form = new JPanel(new GridBagLayout());
    form.setBackground(Color.WHITE);
    form.setBorder(BorderFactory.createEmptyBorder(12, 16, 8, 16));

    GridBagConstraints lbl = new GridBagConstraints();
    lbl.anchor = GridBagConstraints.NORTHWEST;
    lbl.insets = new Insets(6, 0, 4, 8);
    lbl.gridx = 0;

    GridBagConstraints fld = new GridBagConstraints();
    fld.anchor = GridBagConstraints.WEST;
    fld.fill = GridBagConstraints.HORIZONTAL;
    fld.weightx = 1.0;
    fld.insets = new Insets(6, 0, 4, 0);
    fld.gridx = 1;

    int row = 0;

    // Title
    lbl.gridy = row;
    fld.gridy = row;
    form.add(label("Title *"), lbl);
    titleField = new JTextField(30);
    titleField.setFont(new Font("SansSerif", Font.PLAIN, 12));
    form.add(titleField, fld);
    row++;

    // Severity
    lbl.gridy = row;
    fld.gridy = row;
    form.add(label("Severity"), lbl);
    severityCombo = new JComboBox<>(SEVERITIES);
    severityCombo.setSelectedIndex(2); // Default: Medium
    severityCombo.setFont(new Font("SansSerif", Font.PLAIN, 12));
    form.add(severityCombo, fld);
    row++;

    // Category
    lbl.gridy = row;
    fld.gridy = row;
    form.add(label("Category"), lbl);
    String[] categoryLabels = new String[CATEGORIES.length];
    for (int i = 0; i < CATEGORIES.length; i++) {
      categoryLabels[i] =
          CATEGORIES[i][0].isEmpty()
              ? CATEGORIES[i][1]
              : CATEGORIES[i][0] + " - " + CATEGORIES[i][1];
    }
    categoryCombo = new JComboBox<>(categoryLabels);
    categoryCombo.setFont(new Font("SansSerif", Font.PLAIN, 12));
    form.add(categoryCombo, fld);
    row++;

    // Description
    lbl.gridy = row;
    fld.gridy = row;
    fld.fill = GridBagConstraints.BOTH;
    fld.weighty = 1.0;
    form.add(label("Description"), lbl);
    descriptionArea = new JTextArea(3, 30);
    descriptionArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
    descriptionArea.setLineWrap(true);
    descriptionArea.setWrapStyleWord(true);
    form.add(new JScrollPane(descriptionArea), fld);
    row++;

    // Steps to Reproduce
    lbl.gridy = row;
    fld.gridy = row;
    form.add(label("Steps"), lbl);
    stepsArea = new JTextArea(3, 30);
    stepsArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
    stepsArea.setLineWrap(true);
    stepsArea.setWrapStyleWord(true);
    form.add(new JScrollPane(stepsArea), fld);
    fld.weighty = 0;
    fld.fill = GridBagConstraints.HORIZONTAL;
    row++;

    // Help text
    lbl.gridy = row;
    fld.gridy = row;
    form.add(new JLabel(""), lbl);
    JLabel help =
        new JLabel(
            "<html><span style='color:#6e7382;font-size:10px;'>"
                + "The request/response will be attached as evidence automatically.<br>"
                + "You can assign this finding to an engagement later in ScopeProof Pro."
                + "</span></html>");
    form.add(help, fld);

    root.add(form, BorderLayout.CENTER);

    // Buttons
    JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
    buttons.setBackground(new Color(245, 245, 248));
    JButton btnCancel = new JButton("Cancel");
    btnCancel.addActionListener(e -> dispose());
    buttons.add(btnCancel);

    JButton btnSubmit = new JButton("Report Finding");
    btnSubmit.setFont(new Font("SansSerif", Font.BOLD, 12));
    btnSubmit.setForeground(Color.WHITE);
    btnSubmit.setBackground(new Color(26, 86, 219));
    btnSubmit.setOpaque(true);
    btnSubmit.setBorderPainted(false);
    btnSubmit.addActionListener(
        e -> {
          if (titleField.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(
                this, "Title is required.", "Validation", JOptionPane.WARNING_MESSAGE);
            titleField.requestFocus();
            return;
          }
          confirmed = true;
          dispose();
        });
    buttons.add(btnSubmit);

    // Enter key in title field triggers submit
    titleField.addActionListener(e -> btnSubmit.doClick());

    root.add(buttons, BorderLayout.SOUTH);
    setContentPane(root);

    // Focus title on open
    addWindowListener(
        new java.awt.event.WindowAdapter() {
          @Override
          public void windowOpened(java.awt.event.WindowEvent e) {
            titleField.requestFocusInWindow();
          }
        });
  }

  private JLabel label(String text) {
    JLabel l = new JLabel(text);
    l.setFont(new Font("SansSerif", Font.PLAIN, 12));
    return l;
  }

  public boolean isConfirmed() {
    return confirmed;
  }

  public String getTitle() {
    return titleField.getText().trim();
  }

  public String getSeverity() {
    return ((String) severityCombo.getSelectedItem()).toLowerCase();
  }

  public String getCategoryCode() {
    int idx = categoryCombo.getSelectedIndex();
    return CATEGORIES[idx][0];
  }

  public String getDescription() {
    return descriptionArea.getText().trim();
  }

  public String getStepsToReproduce() {
    return stepsArea.getText().trim();
  }
}
