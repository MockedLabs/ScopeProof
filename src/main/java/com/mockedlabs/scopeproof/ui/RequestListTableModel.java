package com.mockedlabs.scopeproof.ui;

import com.mockedlabs.scopeproof.model.AttackPattern;
import com.mockedlabs.scopeproof.model.TrafficRecord;
import com.mockedlabs.scopeproof.parser.TrafficParser;
import java.util.*;
import javax.swing.table.AbstractTableModel;

/** Table model for the request list (individual requests for a selected endpoint). */
public class RequestListTableModel extends AbstractTableModel {

  private static final String[] COLUMNS = {
    "#", "Tool", "Method", "Status", "Size", "Payloads", "Timestamp"
  };

  private List<TrafficRecord> rows = new ArrayList<>();

  public void setRows(List<TrafficRecord> rows) {
    this.rows = rows != null ? new ArrayList<>(rows) : new ArrayList<>();
    fireTableDataChanged();
  }

  public void clear() {
    this.rows = new ArrayList<>();
    fireTableDataChanged();
  }

  public TrafficRecord getRow(int idx) {
    return (idx >= 0 && idx < rows.size()) ? rows.get(idx) : null;
  }

  @Override
  public int getRowCount() {
    return rows.size();
  }

  @Override
  public int getColumnCount() {
    return COLUMNS.length;
  }

  @Override
  public String getColumnName(int col) {
    return COLUMNS[col];
  }

  @Override
  public boolean isCellEditable(int row, int col) {
    return false;
  }

  @Override
  public Object getValueAt(int row, int col) {
    TrafficRecord r = rows.get(row);
    switch (col) {
      case 0:
        return row + 1;
      case 1:
        return r.getToolName();
      case 2:
        return r.getMethod();
      case 3:
        return r.getStatusCode();
      case 4:
        {
          int resp = r.getResponseSize();
          if (resp >= 1024) return String.format("%.1fK", resp / 1024.0);
          return String.valueOf(resp);
        }
      case 5:
        {
          Map<String, AttackPattern> patterns = r.getAttackPatterns();
          if (patterns != null && !patterns.isEmpty()) {
            List<String> parts = new ArrayList<>();
            for (String cat : new TreeSet<>(patterns.keySet())) {
              AttackPattern info = patterns.get(cat);
              if (info != null && info.getMatch() != null) {
                parts.add(info.getMatch());
              } else {
                parts.add(cat);
              }
            }
            return String.join(", ", parts);
          }
          return "";
        }
      case 6:
        return TrafficParser.formatTimestamp(r.getTimestamp());
      default:
        return "";
    }
  }

  @Override
  public Class<?> getColumnClass(int col) {
    if (col == 0 || col == 3) return Integer.class;
    return String.class;
  }
}
