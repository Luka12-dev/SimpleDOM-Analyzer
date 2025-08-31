import sys
import json
import re
import traceback
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

import requests
from PyQt6.QtGui import QIcon
from bs4 import BeautifulSoup

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, QFileDialog,
    QMessageBox, QProgressBar, QHeaderView, QGroupBox, QRadioButton
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# -------------------------
# Patterns & helpers
# -------------------------

EVENT_ATTR_RE = re.compile(r"^on[a-zA-Z]+$", re.IGNORECASE)

# Patterns for suspicious JS usage commonly associated with DOM XSS
JS_SUSPICIOUS_PATTERNS = [
    r"\.innerHTML\b",
    r"\.outerHTML\b",
    r"document\.write\b",
    r"\beval\s*\(",
    r"new\s+Function\s*\(",
    r"location\.hash\b",
    r"location\.search\b",
    r"location\.href\b",
    r"document\.location\b",
    r"window\.location\b",
    r"location\.replace\b",
    r"location\.assign\b",
    r"document\.cookie\b",
    r"decodeURI\s*\(",
    r"decodeURIComponent\s*\(",
    r"\.insertAdjacentHTML\b",
    r"setAttribute\s*\(\s*['\"]?on",
]

COMPILED_JS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in JS_SUSPICIOUS_PATTERNS]

# Shorten snippet for display
def short_snippet(s: str, n: int = 180) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + " ..."

@dataclass
class Finding:
    kind: str           # e.g. "inline-script", "event-attribute", "suspicious-js"
    location: str       # e.g. "URL /path#fragment" or "line X in pasted HTML" or element selector
    snippet: str
    details: Dict[str, Any]

# Worker (thread) for scanning

class ScannerWorker(QThread):
    started_signal = pyqtSignal()
    finished_signal = pyqtSignal(list)  # list of Finding (dicts)
    progress_signal = pyqtSignal(int, str)  # percent, message
    error_signal = pyqtSignal(str)

    def __init__(self, source_type: str, source_value: str, parent=None):
        super().__init__(parent)
        self.source_type = source_type  # "url" or "html"
        self.source_value = source_value

    def run(self):
        try:
            self.started_signal.emit()
            self.progress_signal.emit(5, "Preparing scan...")

            html = ""
            if self.source_type == "url":
                self.progress_signal.emit(10, f"Fetching URL {self.source_value} ...")
                try:
                    resp = requests.get(self.source_value, timeout=12)
                    resp.raise_for_status()
                    html = resp.text
                except Exception as e:
                    raise RuntimeError(f"Failed to fetch URL: {e}")
            else:
                html = self.source_value

            self.progress_signal.emit(30, "Parsing HTML...")
            soup = BeautifulSoup(html, "lxml")

            findings: List[Finding] = []

            # 1) Inline <script> tags
            scripts = soup.find_all("script")
            total_scripts = len(scripts)
            for idx, script in enumerate(scripts, start=1):
                self.progress_signal.emit(30 + int(40 * idx / max(1, total_scripts)),
                                          f"Scanning script {idx}/{total_scripts}...")
                content = script.string or ""
                src = script.get("src")
                if src:
                    # external script reference — note it but we don't fetch external resources by default
                    findings.append(Finding(
                        kind="external-script",
                        location=f"script[src={src}]",
                        snippet="External script reference (not fetched).",
                        details={"src": src}
                    ))
                else:
                    # inline script — analyze for suspicious patterns
                    hits = []
                    for pat in COMPILED_JS_PATTERNS:
                        for m in pat.finditer(content):
                            hits.append({"pattern": pat.pattern, "match": short_snippet(content[m.start():m.end()+80])})
                    if hits:
                        findings.append(Finding(
                            kind="inline-script",
                            location=f"inline <script> (position #{idx})",
                            snippet=short_snippet(content),
                            details={"matches": hits}
                        ))

            # 2) Event handler attributes (onclick, onload, onmouseover...)
            self.progress_signal.emit(75, "Scanning event attributes...")
            all_elements = soup.find_all(True)
            for el in all_elements:
                attrs = el.attrs
                on_attrs = {k: v for k, v in attrs.items() if EVENT_ATTR_RE.match(k)}
                if on_attrs:
                    # if attribute value contains "javascript:" or suspicious patterns, flag
                    suspicious_hits = []
                    for name, val in on_attrs.items():
                        vstr = val if isinstance(val, str) else " ".join(val)
                        for pat in COMPILED_JS_PATTERNS:
                            if pat.search(vstr):
                                suspicious_hits.append({"attr": name, "value": short_snippet(vstr), "pattern": pat.pattern})
                        # also if value contains "javascript:" prefix
                        if re.search(r"^\s*javascript:", vstr, re.IGNORECASE):
                            suspicious_hits.append({"attr": name, "value": short_snippet(vstr), "pattern": "javascript:"})

                    findings.append(Finding(
                        kind="event-attribute",
                        location=self._describe_element(el),
                        snippet=short_snippet(str({k: v for k, v in on_attrs.items()})),
                        details={"attrs": on_attrs, "suspicious": suspicious_hits}
                    ))

            # 3) Search entire inline JS + on* attributes for other suspicious references to location/cookie etc.
            self.progress_signal.emit(90, "Global heuristic scan...")
            # join script texts and attribute values
            collected_js = []
            for script in scripts:
                txt = script.string or ""
                if txt.strip():
                    collected_js.append(txt)
            # also collect event attribute contents
            for el in all_elements:
                for k, v in el.attrs.items():
                    if EVENT_ATTR_RE.match(k):
                        vstr = v if isinstance(v, str) else " ".join(v)
                        collected_js.append(vstr)

            global_text = "\n".join(collected_js)
            global_hits = []
            for pat in COMPILED_JS_PATTERNS:
                for m in pat.finditer(global_text):
                    context = global_text[max(0, m.start()-60):m.end()+60]
                    global_hits.append({"pattern": pat.pattern, "context": short_snippet(context, 200)})

            if global_hits:
                findings.append(Finding(
                    kind="suspicious-js-global",
                    location="inline scripts & event attributes combined",
                    snippet=f"Found {len(global_hits)} suspicious matches across inline JS/event attributes.",
                    details={"matches": global_hits}
                ))

            # Done
            self.progress_signal.emit(100, "Scan complete.")
            # Convert dataclass objects to dicts for transport
            findings_dicts = [asdict(f) for f in findings]
            self.finished_signal.emit(findings_dicts)
        except Exception as e:
            tb = traceback.format_exc()
            self.error_signal.emit(f"{str(e)}\n{tb}")

    @staticmethod
    def _describe_element(el) -> str:
        # Build simple CSS-like selector: tag#id.class1.class2
        parts = [el.name]
        eid = el.get("id")
        if eid:
            parts.append(f"#{eid}")
        classes = el.get("class") or []
        if classes:
            parts.append("." + ".".join(classes))
        # include name attribute or other distinguishing attributes
        if el.get("name") and "id" not in (el.attrs or {}):
            parts.append(f'[name="{el.get("name")}"]')
        return "".join(parts)

# GUI

class SimpleDomAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Simple DOM Analyzer — DOM-based XSS Finder")
        self.setWindowIcon(QIcon("webico.ico"))
        self.resize(900, 600)
        self._setup_ui()
        self.scanner_thread = None

    def _setup_ui(self):
        layout = QVBoxLayout()
        top_row = QHBoxLayout()

        self.url_radio = QRadioButton("Scan URL")
        self.html_radio = QRadioButton("Paste HTML")
        self.url_radio.setChecked(True)
        radio_box = QGroupBox("Source")
        rb_layout = QHBoxLayout()
        rb_layout.addWidget(self.url_radio)
        rb_layout.addWidget(self.html_radio)
        radio_box.setLayout(rb_layout)

        top_row.addWidget(radio_box)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/page.html")
        top_row.addWidget(QLabel("URL / HTML:"))
        top_row.addWidget(self.url_input)

        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.on_scan)
        top_row.addWidget(self.scan_button)

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.on_clear)
        top_row.addWidget(self.clear_button)

        layout.addLayout(top_row)

        # Large HTML paste area
        self.html_text = QTextEdit()
        self.html_text.setPlaceholderText("Paste HTML here if 'Paste HTML' selected. For 'Scan URL', this area can remain empty.")
        self.html_text.setMinimumHeight(140)
        layout.addWidget(self.html_text)

        # Progress and status
        status_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.status_label = QLabel("Ready.")
        status_row.addWidget(self.progress, stretch=3)
        status_row.addWidget(self.status_label, stretch=7)
        layout.addLayout(status_row)

        # Results table
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Type", "Location", "Snippet / Summary"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, stretch=1)

        # Save report button
        bottom_row = QHBoxLayout()
        self.save_button = QPushButton("Save Report")
        self.save_button.clicked.connect(self.on_save)
        self.save_button.setEnabled(False)
        bottom_row.addStretch()
        bottom_row.addWidget(self.save_button)
        layout.addLayout(bottom_row)

        self.setLayout(layout)

    # GUI slots
    def on_scan(self):
        src_type = "url" if self.url_radio.isChecked() else "html"
        src_value = self.url_input.text().strip() if src_type == "url" else self.html_text.toPlainText()
        if src_type == "url":
            if not src_value:
                QMessageBox.warning(self, "Missing URL", "Please enter a URL to scan.")
                return
            if not (src_value.startswith("http://") or src_value.startswith("https://")):
                QMessageBox.warning(self, "Invalid URL", "Please enter a full URL starting with http:// or https://")
                return
        else:
            if not src_value.strip():
                QMessageBox.warning(self, "Missing HTML", "Please paste HTML to scan.")
                return

        # disable controls
        self.scan_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.status_label.setText("Starting scan...")

        # start worker thread
        self.scanner_thread = ScannerWorker(src_type, src_value)
        self.scanner_thread.progress_signal.connect(self._on_progress)
        self.scanner_thread.finished_signal.connect(self._on_finished)
        self.scanner_thread.error_signal.connect(self._on_error)
        self.scanner_thread.started_signal.connect(lambda: self.status_label.setText("Scan running..."))
        self.scanner_thread.start()

    def on_clear(self):
        self.table.setRowCount(0)
        self.status_label.setText("Cleared.")
        self.progress.setValue(0)
        self.save_button.setEnabled(False)

    def _on_progress(self, percent: int, message: str):
        self.progress.setValue(max(0, min(100, percent)))
        self.status_label.setText(message)

    def _on_finished(self, findings_list: List[Dict[str, Any]]):
        self.progress.setValue(100)
        self.status_label.setText(f"Scan finished. {len(findings_list)} findings.")
        self.scan_button.setEnabled(True)
        self.save_button.setEnabled(bool(findings_list))
        # populate table
        self.table.setRowCount(0)
        for f in findings_list:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(f.get("kind", "")))
            self.table.setItem(row, 1, QTableWidgetItem(f.get("location", "")))
            snippet = f.get("snippet", "")
            # if details exist, add small summary
            details = f.get("details")
            if isinstance(details, dict) and details:
                extra = []
                if "matches" in details:
                    extra.append(f"{len(details['matches'])} match(es)")
                if "suspicious" in details:
                    extra.append(f"{len(details['suspicious'])} suspicious attr(s)")
                if extra:
                    snippet = snippet + " [" + ", ".join(extra) + "]"
            self.table.setItem(row, 2, QTableWidgetItem(snippet))
        # store last findings for saving
        self._last_findings = findings_list

    def _on_error(self, message: str):
        self.scan_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.status_label.setText("Error during scan.")
        QMessageBox.critical(self, "Scan Error", f"An error occurred:\n\n{message}")

    def on_save(self):
        try:
            initial = "dom_scan_report.json"
            path, _ = QFileDialog.getSaveFileName(self, "Save Report", initial, "JSON files (*.json);;All Files (*)")
            if not path:
                return
            # save stored findings
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._last_findings, f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Saved", f"Report saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))

# Main

def main():
    app = QApplication(sys.argv)
    win = SimpleDomAnalyzer()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()