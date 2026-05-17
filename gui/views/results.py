import os
from gi.repository import Gtk, Pango
from backend.exporters import export_report

class ResultsView(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.set_margin_top(24)
        self.set_margin_bottom(24)
        self.set_margin_start(24)
        self.set_margin_end(24)
        
        # Header
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        title = Gtk.Label(label="Scan Results")
        title.add_css_class("title-1")
        header_box.append(title)
        
        self.file_label = Gtk.Label(label="")
        self.file_label.add_css_class("dim-label")
        self.file_label.set_halign(Gtk.Align.END)
        self.file_label.set_hexpand(True)
        header_box.append(self.file_label)

        self.export_button = Gtk.Button(label="Export")
        self.export_button.add_css_class("suggested-action")
        self.export_button.set_sensitive(False)
        self.export_button.connect("clicked", self._on_export_clicked)
        header_box.append(self.export_button)
        
        self.append(header_box)
        
        # Summary Card (Score)
        self.score_card = Gtk.Frame()
        self.score_card.add_css_class("card")
        score_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        score_box.set_margin_start(16)
        score_box.set_margin_end(16)
        score_box.set_margin_top(12)
        score_box.set_margin_bottom(12)
        self.score_card.set_child(score_box)
        
        self.score_label = Gtk.Label(label="Score: —")
        self.score_label.add_css_class("title-2")
        score_box.append(self.score_label)
        
        self.score_bar = Gtk.ProgressBar()
        self.score_bar.set_hexpand(True)
        self.score_bar.set_valign(Gtk.Align.CENTER)
        score_box.append(self.score_bar)
        
        self.append(self.score_card)
        
        # Results List
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.add_css_class("view") # Optional
        self.append(scrolled)
        
        self.results_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.results_box.set_margin_top(12)
        self.results_box.set_margin_bottom(12)
        scrolled.set_child(self.results_box)
        
        # Placeholder
        self.placeholder = Gtk.Label(label="No results to display.")
        self.placeholder.add_css_class("dim-label")
        self.results_box.append(self.placeholder)
        self.current_report = None
        self.current_file_path = None

    def display_report(self, report, file_path):
        self.current_report = report
        self.current_file_path = file_path
        self.export_button.set_sensitive(isinstance(report, dict) and "error" not in report)

        # Clear previous
        child = self.results_box.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.results_box.remove(child)
            child = next_child

        if isinstance(report, dict) and "error" in report:
            error_text = str(report.get("error") or "").strip()
            if not error_text:
                error_text = "Scan failed. The scanner could not complete the analysis."
            else:
                error_text = f"Scan failed: {error_text}"

            self.file_label.set_label("Scan Error")
            self.score_label.set_label("Score: —")
            self.score_bar.set_fraction(0.0)

            error_lbl = Gtk.Label(label=error_text)
            error_lbl.add_css_class("error")
            error_lbl.set_wrap(True)
            error_lbl.set_halign(Gtk.Align.CENTER)
            error_lbl.set_justify(Gtk.Justification.CENTER)
            error_lbl.set_margin_top(40)
            self.results_box.append(error_lbl)
            return
            
        # File Info
        fname = os.path.basename(file_path)
        self.file_label.set_label(f"File: {fname}")
        
        # Score
        score = report.get("security_score", 0)
        self.score_label.set_label(f"Score: {score}")
        self.score_bar.set_fraction(score / 100.0)
        
        # Findings
        findings = report.get("findings", [])
        if not findings:
            lbl = Gtk.Label(label="No threats detected! 🎉")
            lbl.add_css_class("success-label")
            lbl.set_halign(Gtk.Align.CENTER)
            lbl.set_margin_top(40)
            self.results_box.append(lbl)
            return

        for idx, f in enumerate(findings, start=1):
            row = self._create_finding_row(idx, f)
            self.results_box.append(row)

    def _on_export_clicked(self, widget):
        if not self.current_report or not self.current_file_path:
            return

        suggested_name = f"{os.path.basename(self.current_file_path)}.report.json"
        dialog = Gtk.FileDialog()
        dialog.set_title("Export Scan Report")
        dialog.set_initial_name(suggested_name)
        parent = self.get_root()
        dialog.save(parent, None, self._on_export_path_selected)

    def _on_export_path_selected(self, dialog, result):
        try:
            file = dialog.save_finish(result)
            if not file:
                return
            output_path = file.get_path()
            if not output_path:
                return
            # Why: exporters.py was dead code — this gives it a real entry point
            export_report(self.current_report, format='json', output_path=output_path)
        except Exception:
            pass

    def _create_finding_row(self, idx, finding):
        frame = Gtk.Frame()
        frame.add_css_class("card")
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_margin_start(16)
        box.set_margin_end(16)
        box.set_margin_top(16)
        box.set_margin_bottom(16)
        frame.set_child(box)
        
        # Title Row
        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        sev = finding.get("severity", "Medium")
        sev_lbl = Gtk.Label(label=sev)
        sev_lbl.add_css_class("badge")
        if sev == "Critical":
            sev_lbl.add_css_class("badge-critical")
        elif sev == "High":
            sev_lbl.add_css_class("badge-high")
        elif sev == "Medium":
            sev_lbl.add_css_class("badge-medium")
        else:
            sev_lbl.add_css_class("badge-low")
            
        desc = finding.get("description", "Finding")
        desc_lbl = Gtk.Label(label=f"{desc}")
        desc_lbl.add_css_class("heading")
        
        title_box.append(sev_lbl)
        title_box.append(desc_lbl)
        box.append(title_box)
        
        # Details
        line = finding.get("line", "?")
        source = finding.get("source", "Unknown")
        meta_lbl = Gtk.Label(label=f"Line: {line} | Source: {source}")
        meta_lbl.add_css_class("dim-label")
        meta_lbl.set_halign(Gtk.Align.START)
        box.append(meta_lbl)

        # Why: metadata from scanner is shown here — users need CWE/OWASP refs and remediation to act on findings
        cwe = str(finding.get("cwe", "")).strip()
        if cwe:
            cwe_lbl = Gtk.Label(label=f"CWE: {cwe}")
            cwe_lbl.add_css_class("dim-label")
            cwe_lbl.set_halign(Gtk.Align.START)
            cwe_lbl.set_xalign(0)
            box.append(cwe_lbl)

        owasp = str(finding.get("owasp", "")).strip()
        if owasp:
            owasp_lbl = Gtk.Label(label=f"OWASP: {owasp}")
            owasp_lbl.add_css_class("dim-label")
            owasp_lbl.set_halign(Gtk.Align.START)
            owasp_lbl.set_xalign(0)
            box.append(owasp_lbl)

        remediation = str(finding.get("remediation", "")).strip()
        if remediation:
            remediation_lbl = Gtk.Label(label=f"Remediation: {remediation}")
            remediation_lbl.add_css_class("dim-label")
            remediation_lbl.set_halign(Gtk.Align.START)
            remediation_lbl.set_xalign(0)
            remediation_lbl.set_wrap(True)
            remediation_lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            box.append(remediation_lbl)

        confidence = str(finding.get("confidence", "")).strip()
        if confidence:
            confidence_lbl = Gtk.Label(label=f"Confidence: {confidence}")
            confidence_lbl.add_css_class("dim-label")
            confidence_lbl.set_halign(Gtk.Align.START)
            confidence_lbl.set_xalign(0)
            box.append(confidence_lbl)
        
        # Code Snippet
        snippet = finding.get("code_snippet", "").strip()
        if snippet:
            code_frame = Gtk.Frame()
            code_frame.add_css_class("code-block")
            code_lbl = Gtk.Label(label=snippet)
            code_lbl.set_wrap(True)
            code_lbl.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            code_lbl.set_selectable(True)
            code_lbl.set_xalign(0)
            code_frame.set_child(code_lbl)
            box.append(code_frame)
        
        # Explanation
        expl = finding.get("explanation", "").strip()
        if expl:
            expl_lbl = Gtk.Label(label=expl)
            expl_lbl.set_wrap(True)
            expl_lbl.set_xalign(0)
            expl_lbl.set_max_width_chars(80)
            box.append(expl_lbl)
            
        return frame
