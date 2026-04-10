package com.mockedlabs.scopeproof.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Custom cell renderers for coverage table columns.
 */
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

    // Shared
    private static final Color DEFAULT_FG = new Color(110, 115, 130);

    public static class DepthCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focused, int row, int col) {
            Component comp = super.getTableCellRendererComponent(
                table, value, selected, focused, row, col);
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
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focused, int row, int col) {
            Component comp = super.getTableCellRendererComponent(
                table, value, selected, focused, row, col);
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
            return comp;
        }
    }

    public static class MethodCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focused, int row, int col) {
            Component comp = super.getTableCellRendererComponent(
                table, value, selected, focused, row, col);
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

    public static class TestsCellRenderer extends DefaultTableCellRenderer {
        private static final Font SMALL_FONT = new Font("SansSerif", Font.PLAIN, 11);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focused, int row, int col) {
            Component comp = super.getTableCellRendererComponent(
                table, value, selected, focused, row, col);
            if (!selected) {
                String v = value != null ? value.toString().trim() : "";
                if (!v.isEmpty()) {
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
}
