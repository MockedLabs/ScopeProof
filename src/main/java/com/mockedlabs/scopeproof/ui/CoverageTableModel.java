package com.mockedlabs.scopeproof.ui;

import com.mockedlabs.scopeproof.model.EndpointRow;

import javax.swing.table.AbstractTableModel;
import java.util.*;

/**
 * Table model for the main endpoint coverage table.
 */
public class CoverageTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "Host", "Endpoint", "Methods", "Reqs", "Priority",
        "Depth", "Tested By", "Status Codes", "Tests", "Tag", "Notes"
    };

    private List<EndpointRow> rows = new ArrayList<>();

    public void setRows(List<EndpointRow> rows) {
        this.rows = rows != null ? new ArrayList<>(rows) : new ArrayList<>();
        fireTableDataChanged();
    }

    public List<EndpointRow> getRows() { return new ArrayList<>(rows); }

    public EndpointRow getRow(int idx) {
        return (idx >= 0 && idx < rows.size()) ? rows.get(idx) : null;
    }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int col) { return COLUMNS[col]; }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 10; // Notes column
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        if (col == 10 && row >= 0 && row < rows.size()) {
            rows.get(row).setNotes(String.valueOf(value));
            fireTableCellUpdated(row, col);
        }
    }

    @Override
    public Object getValueAt(int row, int col) {
        EndpointRow r = rows.get(row);
        switch (col) {
            case 0: return r.getHost();
            case 1: {
                String ep = r.getEndpoint();
                List<String> params = r.getQueryParams();
                if (params != null && !params.isEmpty()) {
                    return ep + "?" + String.join("&", params);
                }
                return ep;
            }
            case 2: return String.join(", ", r.getMethods());
            case 3: return r.getRequestCount();
            case 4: return r.getPriority();
            case 5: return r.getTestingDepth();
            case 6: return r.getTestedBy();
            case 7: return formatStatusCodes(r.getStatusCodes());
            case 8: return String.join(", ", r.getTestsDetected());
            case 9: return r.getTag();
            case 10: return r.getNotes();
            default: return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int col) {
        if (col == 3) return Integer.class;
        return String.class;
    }

    private static String formatStatusCodes(Map<String, Integer> codes) {
        if (codes == null || codes.isEmpty()) return "";
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, Integer> e : new TreeMap<>(codes).entrySet()) {
            parts.add(e.getKey() + "(" + e.getValue() + ")");
        }
        return String.join(", ", parts);
    }
}
