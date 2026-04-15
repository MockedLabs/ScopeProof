package com.mockedlabs.scopeproof.ui;

import java.awt.*;
import java.util.HashMap;
import java.util.Map;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;

/** Custom cell renderers for coverage table columns. */
public class CellRenderers {

  // Depth colors
  private static final Color DEPTH_THOROUGH_BG = new Color(22, 120, 60);
  private static final Color DEPTH_FUZZ_BG = new Color(230, 244, 234);
  private static final Color DEPTH_FUZZ_FG = new Color(30, 100, 30);
  private static final Color DEPTH_MANUAL_BG = new Color(200, 235, 255);
  private static final Color DEPTH_MANUAL_FG = new Color(0, 80, 160);
  private static final Color DEPTH_OBSERVED_BG = new Color(254, 247, 224);
  private static final Color DEPTH_OBSERVED_FG = new Color(120, 100, 0);
  private static final Color DEPTH_UNTESTED_BG = new Color(252, 220, 215);
  private static final Color DEPTH_UNTESTED_FG = new Color(160, 30, 30);
  private static final Color DEPTH_MISSING_BG = new Color(200, 200, 210);
  private static final Color DEPTH_MISSING_FG = new Color(80, 80, 100);

  // Priority colors
  private static final Color PRIO_CRITICAL_BG = new Color(180, 30, 30);
  private static final Color PRIO_HIGH_BG = new Color(252, 220, 215);
  private static final Color PRIO_HIGH_FG = new Color(160, 30, 30);
  private static final Color PRIO_MEDIUM_BG = new Color(254, 247, 224);
  private static final Color PRIO_MEDIUM_FG = new Color(120, 100, 0);
  private static final Color PRIO_LOW_BG = new Color(230, 244, 234);
  private static final Color PRIO_LOW_FG = new Color(30, 100, 30);

  // Method colors
  private static final Color METHOD_MANY_BG = new Color(230, 244, 234);
  private static final Color METHOD_TWO_BG = new Color(254, 247, 224);
  private static final Color METHOD_ONE_BG = new Color(252, 232, 230);

  // Tests colors
  private static final Color TESTS_BG = new Color(230, 230, 250);
  private static final Color TESTS_FG = new Color(80, 60, 140);
  private static final Color EXPLOITED_BG = new Color(220, 38, 38);
  private static final Color EXPLOITED_FG = Color.WHITE;

  // Shared
  private static final Color DEFAULT_FG = new Color(110, 115, 130);

  public static class DepthCellRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean selected, boolean focused, int row, int col) {
      Component comp =
          super.getTableCellRendererComponent(table, value, selected, focused, row, col);
      if (!selected) {
        String v = value != null ? value.toString().trim() : "";
        switch (v) {
          case "Thoroughly Tested":
            comp.setBackground(DEPTH_THOROUGH_BG);
            comp.setForeground(Color.WHITE);
            break;
          case "Fuzz Tested":
            comp.setBackground(DEPTH_FUZZ_BG);
            comp.setForeground(DEPTH_FUZZ_FG);
            break;
          case "Manually Tested":
            comp.setBackground(DEPTH_MANUAL_BG);
            comp.setForeground(DEPTH_MANUAL_FG);
            break;
          case "Observed":
            comp.setBackground(DEPTH_OBSERVED_BG);
            comp.setForeground(DEPTH_OBSERVED_FG);
            break;
          case "Untested":
            comp.setBackground(DEPTH_UNTESTED_BG);
            comp.setForeground(DEPTH_UNTESTED_FG);
            break;
          case "Missing":
            comp.setBackground(DEPTH_MISSING_BG);
            comp.setForeground(DEPTH_MISSING_FG);
            break;
          default:
            comp.setBackground(Color.WHITE);
            comp.setForeground(DEFAULT_FG);
        }
      }
      return comp;
    }
  }

  public static class PriorityCellRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean selected, boolean focused, int row, int col) {
      Component comp =
          super.getTableCellRendererComponent(table, value, selected, focused, row, col);
      if (!selected) {
        String v = value != null ? value.toString().trim() : "";
        switch (v) {
          case "Critical":
            comp.setBackground(PRIO_CRITICAL_BG);
            comp.setForeground(Color.WHITE);
            break;
          case "High":
            comp.setBackground(PRIO_HIGH_BG);
            comp.setForeground(PRIO_HIGH_FG);
            break;
          case "Medium":
            comp.setBackground(PRIO_MEDIUM_BG);
            comp.setForeground(PRIO_MEDIUM_FG);
            break;
          case "Low":
            comp.setBackground(PRIO_LOW_BG);
            comp.setForeground(PRIO_LOW_FG);
            break;
          default:
            comp.setBackground(Color.WHITE);
            comp.setForeground(DEFAULT_FG);
        }
      }

      // Show priority reasons as tooltip
      if (comp instanceof JComponent) {
        String tip = null;
        try {
          int modelRow = table.convertRowIndexToModel(row);
          javax.swing.table.TableModel model = table.getModel();
          if (model instanceof CoverageTableModel) {
            com.mockedlabs.scopeproof.model.EndpointRow epRow =
                ((CoverageTableModel) model).getRow(modelRow);
            if (epRow != null && !epRow.getPriorityReasons().isEmpty()) {
              StringBuilder sb = new StringBuilder("Score: ");
              sb.append(epRow.getPriorityScore());
              for (String reason : epRow.getPriorityReasons()) {
                sb.append("  \u2022 ").append(reason);
              }
              tip = sb.toString();
            }
          }
        } catch (Exception ignored) {
        }
        ((JComponent) comp).setToolTipText(tip);
      }

      return comp;
    }
  }

  public static class MethodCellRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean selected, boolean focused, int row, int col) {
      Component comp =
          super.getTableCellRendererComponent(table, value, selected, focused, row, col);
      if (!selected) {
        // Count methods by counting commas + 1, avoiding split/array allocation
        String s = value != null ? value.toString() : "";
        int count = s.isEmpty() ? 0 : 1;
        for (int i = 0; i < s.length(); i++) {
          if (s.charAt(i) == ',') count++;
        }
        if (count >= 3) comp.setBackground(METHOD_MANY_BG);
        else if (count == 2) comp.setBackground(METHOD_TWO_BG);
        else comp.setBackground(METHOD_ONE_BG);
      }
      return comp;
    }
  }

  /**
   * Row-level renderer that applies a subtle background tint to synthetic baseline rows (where the
   * value in the Depth column is "Missing").
   */
  public static class BaselineRowRenderer extends DefaultTableCellRenderer {
    private final TableCellRenderer delegate;

    public BaselineRowRenderer(TableCellRenderer delegate) {
      this.delegate = delegate;
    }

    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean selected, boolean focused, int row, int col) {
      Component comp =
          delegate != null
              ? delegate.getTableCellRendererComponent(table, value, selected, focused, row, col)
              : super.getTableCellRendererComponent(table, value, selected, focused, row, col);
      if (!selected) {
        // Check the Depth column (model col 5) for "Missing"
        int modelRow = table.convertRowIndexToModel(row);
        Object depthVal = table.getModel().getValueAt(modelRow, 5);
        if ("Missing".equals(depthVal != null ? depthVal.toString().trim() : "")) {
          // Subtle dashed-border effect via background tint
          comp.setBackground(BASELINE_ROW_BG);
          if (comp instanceof JComponent) {
            ((JComponent) comp)
                .setToolTipText("Expected from Swagger baseline — not yet observed in traffic");
          }
        }
      }
      return comp;
    }
  }

  private static final Color BASELINE_ROW_BG = new Color(245, 245, 252);

  // Auth state colors
  private static final Color AUTH_BOTH_BG = new Color(230, 244, 234);
  private static final Color AUTH_BOTH_FG = new Color(30, 100, 30);
  private static final Color AUTH_ONLY_BG = new Color(254, 247, 224);
  private static final Color AUTH_ONLY_FG = new Color(120, 100, 0);
  private static final Color UNAUTH_ONLY_BG = new Color(252, 232, 230);
  private static final Color UNAUTH_ONLY_FG = new Color(160, 30, 30);

  public static class AuthCellRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean selected, boolean focused, int row, int col) {
      Component comp =
          super.getTableCellRendererComponent(table, value, selected, focused, row, col);
      if (!selected) {
        String v = value != null ? value.toString().trim() : "";
        switch (v) {
          case "Both":
            comp.setBackground(AUTH_BOTH_BG);
            comp.setForeground(AUTH_BOTH_FG);
            break;
          case "Auth Only":
            comp.setBackground(AUTH_ONLY_BG);
            comp.setForeground(AUTH_ONLY_FG);
            break;
          case "Unauth Only":
            comp.setBackground(UNAUTH_ONLY_BG);
            comp.setForeground(UNAUTH_ONLY_FG);
            break;
          default:
            comp.setBackground(Color.WHITE);
            comp.setForeground(DEFAULT_FG);
        }
      }
      return comp;
    }
  }

  public static class TestsCellRenderer extends DefaultTableCellRenderer {
    private static final Font SMALL_FONT = new Font("SansSerif", Font.PLAIN, 11);
    private static final Font SMALL_BOLD = new Font("SansSerif", Font.BOLD, 11);

    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean selected, boolean focused, int row, int col) {
      Component comp =
          super.getTableCellRendererComponent(table, value, selected, focused, row, col);
      if (!selected) {
        String v = value != null ? value.toString().trim() : "";
        if (v.contains("\u2713")) {
          // Has confirmed exploits — red background
          comp.setBackground(EXPLOITED_BG);
          comp.setForeground(EXPLOITED_FG);
          comp.setFont(SMALL_BOLD);
          return comp;
        } else if (!v.isEmpty()) {
          comp.setBackground(TESTS_BG);
          comp.setForeground(TESTS_FG);
        } else {
          comp.setBackground(Color.WHITE);
          comp.setForeground(DEFAULT_FG);
        }
      }
      comp.setFont(SMALL_FONT);
      return comp;
    }
  }

  /**
   * Header renderer that delegates to the default header renderer but adds per-column tooltips.
   * Columns 5 (Depth) gets the depth legend, 7 (Auth) explains states, 10/11 (Tag/Notes) get edit
   * hints.
   */
  public static class HeaderTooltipRenderer implements TableCellRenderer {
    private final TableCellRenderer delegate;
    private final Map<Integer, String> tooltips = new HashMap<>();

    public HeaderTooltipRenderer(JTableHeader header) {
      this.delegate = header.getDefaultRenderer();
      tooltips.put(
          5,
          "<html>"
              + "<b>Testing Depth Legend</b><br><br>"
              + "<b>Thoroughly Tested</b> — Repeater + Intruder + attack payloads<br>"
              + "<b>Fuzz Tested</b> — Intruder or Scanner used<br>"
              + "<b>Manually Tested</b> — Repeater or edited in Proxy<br>"
              + "<b>Observed</b> — Traffic seen, no manual testing<br>"
              + "<b>Untested</b> — In scope, no traffic<br>"
              + "<b>Missing</b> — Swagger baseline, not yet observed"
              + "</html>");
      tooltips.put(
          7,
          "<html>"
              + "<b>Auth</b> — Both: tested authenticated &amp; unauthenticated<br>"
              + "<b>Auth Only</b> — only authenticated requests seen<br>"
              + "<b>Unauth Only</b> — only unauthenticated requests seen"
              + "</html>");
      tooltips.put(10, "Double-click to set a tag");
      tooltips.put(11, "Double-click to edit notes");
    }

    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean selected, boolean focused, int row, int col) {
      Component comp =
          delegate.getTableCellRendererComponent(table, value, selected, focused, row, col);
      if (comp instanceof JComponent) {
        String tip = tooltips.get(col);
        ((JComponent) comp).setToolTipText(tip);
      }
      return comp;
    }
  }
}
