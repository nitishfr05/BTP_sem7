"""Convert Mid_Term_Report.md into a formatted Word (.docx) document with embedded figures."""

import os
import re
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn


def set_cell_background(cell, fill_hex):
    """Set background color of a table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set inner padding for table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)


def build_docx_report():
    doc = Document()

    # Page Margins: 1 inch all around
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Base Normal Style: Georgia or Calibri, 11pt, 1.15 line spacing
    style = doc.styles['Normal']
    font = style.font
    font.name = 'Calibri'
    font.size = Pt(11)
    font.color.rgb = RGBColor(0x22, 0x22, 0x22)
    style.paragraph_format.line_spacing = 1.15
    style.paragraph_format.space_after = Pt(6)

    with open("Mid_Term_Report.md", "r", encoding="utf-8") as f:
        md_text = f.read()

    lines = md_text.split("\n")
    i = 0
    in_code_block = False
    code_lines = []
    in_table = False
    table_lines = []

    def flush_code():
        nonlocal code_lines
        if code_lines:
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(8)
            p.paragraph_format.left_indent = Inches(0.2)
            run = p.add_run("\n".join(code_lines))
            run.font.name = "Consolas"
            run.font.size = Pt(9.5)
            run.font.color.rgb = RGBColor(0x1a, 0x36, 0x5d)
            code_lines = []

    def flush_table():
        nonlocal table_lines
        if table_lines:
            # Parse table rows
            rows = []
            for tline in table_lines:
                tline = tline.strip()
                if tline.startswith("|") and tline.endswith("|"):
                    parts = [c.strip() for c in tline[1:-1].split("|")]
                    if not all(re.match(r"^:?-+:?$", p) for p in parts):
                        rows.append(parts)
            if rows:
                num_cols = max(len(r) for r in rows)
                t = doc.add_table(rows=len(rows), cols=num_cols)
                t.alignment = WD_TABLE_ALIGNMENT.CENTER
                for r_idx, row_data in enumerate(rows):
                    row = t.rows[r_idx]
                    is_header = (r_idx == 0)
                    for c_idx, val in enumerate(row_data):
                        if c_idx < len(row.cells):
                            cell = row.cells[c_idx]
                            cell.text = val
                            p = cell.paragraphs[0]
                            p.paragraph_format.space_after = Pt(2)
                            p.paragraph_format.space_before = Pt(2)
                            if is_header:
                                set_cell_background(cell, "2B4C7E")
                                for r in p.runs:
                                    r.font.bold = True
                                    r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                            else:
                                if r_idx % 2 == 1:
                                    set_cell_background(cell, "F4F6F9")
                                else:
                                    set_cell_background(cell, "FFFFFF")
                                for r in p.runs:
                                    r.font.size = Pt(10)
                            set_cell_margins(cell, top=120, bottom=120, left=140, right=140)
            doc.add_paragraph()  # spacing after table
            table_lines = []

    while i < len(lines):
        line = lines[i]

        # Code block fence
        if line.strip().startswith("```"):
            if in_code_block:
                in_code_block = False
                flush_code()
            else:
                if in_table:
                    in_table = False
                    flush_table()
                in_code_block = True
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        # Table detection
        if line.strip().startswith("|") and line.strip().endswith("|"):
            in_table = True
            table_lines.append(line)
            i += 1
            continue
        elif in_table:
            in_table = False
            flush_table()

        # Headers
        if line.startswith("# "):
            p = doc.add_heading(level=0)
            p.paragraph_format.space_before = Pt(16)
            p.paragraph_format.space_after = Pt(8)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(line[2:].strip())
            run.font.name = 'Calibri'
            run.font.size = Pt(22)
            run.font.bold = True
            run.font.color.rgb = RGBColor(0x1B, 0x36, 0x5D)
        elif line.startswith("## "):
            p = doc.add_heading(level=1)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(6)
            run = p.add_run(line[3:].strip())
            run.font.name = 'Calibri'
            run.font.size = Pt(15)
            run.font.bold = True
            run.font.color.rgb = RGBColor(0x2B, 0x4C, 0x7E)
        elif line.startswith("### "):
            p = doc.add_heading(level=2)
            p.paragraph_format.space_before = Pt(10)
            p.paragraph_format.space_after = Pt(4)
            run = p.add_run(line[4:].strip())
            run.font.name = 'Calibri'
            run.font.size = Pt(13)
            run.font.bold = True
            run.font.color.rgb = RGBColor(0x3B, 0x5C, 0x8E)
        elif line.startswith("#### "):
            p = doc.add_heading(level=3)
            p.paragraph_format.space_before = Pt(8)
            p.paragraph_format.space_after = Pt(2)
            run = p.add_run(line[5:].strip())
            run.font.name = 'Calibri'
            run.font.size = Pt(11.5)
            run.font.bold = True
            run.font.color.rgb = RGBColor(0x44, 0x44, 0x44)
        elif line.strip() == "---":
            # Horizontal divider
            pass
        elif line.startswith("> "):
            # Callout box / blockquote
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.3)
            p.paragraph_format.right_indent = Inches(0.3)
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(6)
            run = p.add_run(line[2:].strip())
            run.font.italic = True
            run.font.color.rgb = RGBColor(0x33, 0x4E, 0x68)
        elif line.strip().startswith("* ") or line.strip().startswith("- "):
            p = doc.add_paragraph(style='List Bullet')
            p.paragraph_format.space_after = Pt(3)
            # Basic bold parsing inside bullets
            content = line.strip()[2:]
            parts = re.split(r"(\*\*.*?\*\*)", content)
            for part in parts:
                if part.startswith("**") and part.endswith("**"):
                    r = p.add_run(part[2:-2])
                    r.bold = True
                else:
                    p.add_run(part)
        elif re.match(r"^\d+\.\s", line.strip()):
            p = doc.add_paragraph(style='List Number')
            p.paragraph_format.space_after = Pt(3)
            content = re.sub(r"^\d+\.\s", "", line.strip())
            parts = re.split(r"(\*\*.*?\*\*)", content)
            for part in parts:
                if part.startswith("**") and part.endswith("**"):
                    r = p.add_run(part[2:-2])
                    r.bold = True
                else:
                    p.add_run(part)
        else:
            if line.strip():
                p = doc.add_paragraph()
                p.paragraph_format.space_after = Pt(5)
                parts = re.split(r"(\*\*.*?\*\*)", line)
                for part in parts:
                    if part.startswith("**") and part.endswith("**"):
                        r = p.add_run(part[2:-2])
                        r.bold = True
                    else:
                        p.add_run(part)

        # Check if we should insert figures after section 5.2 and 5.3
        if "5.2 Breakdown by Attack Category" in line:
            fig1_path = os.path.abspath("results/figures/isr_by_category_comparison.png")
            if os.path.exists(fig1_path):
                fp = doc.add_paragraph()
                fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
                fp.paragraph_format.space_before = Pt(8)
                fp.paragraph_format.space_after = Pt(4)
                fp.add_run().add_picture(fig1_path, width=Inches(5.8))
                cap = doc.add_paragraph()
                cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                cap_run = cap.add_run("Figure 1: Prompt Injection Success Rate (ISR) Across Attack Categories (Baseline vs. Defended)")
                cap_run.font.italic = True
                cap_run.font.size = Pt(9.5)
                cap_run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

        if "5.3 Breakdown by Network Telemetry Channel" in line:
            fig2_path = os.path.abspath("results/figures/isr_by_channel_comparison.png")
            if os.path.exists(fig2_path):
                fp = doc.add_paragraph()
                fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
                fp.paragraph_format.space_before = Pt(8)
                fp.paragraph_format.space_after = Pt(4)
                fp.add_run().add_picture(fig2_path, width=Inches(5.8))
                cap = doc.add_paragraph()
                cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                cap_run = cap.add_run("Figure 2: Vulnerability Distribution Across Network Telemetry Channels (Baseline vs. Defended)")
                cap_run.font.italic = True
                cap_run.font.size = Pt(9.5)
                cap_run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

        if "5.4 Cross-Architecture Comparison" in line:
            fig3_path = os.path.abspath("results/figures/cross_architecture_comparison.png")
            if os.path.exists(fig3_path):
                fp = doc.add_paragraph()
                fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
                fp.paragraph_format.space_before = Pt(8)
                fp.paragraph_format.space_after = Pt(4)
                fp.add_run().add_picture(fig3_path, width=Inches(5.8))
                cap = doc.add_paragraph()
                cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                cap_run = cap.add_run("Figure 3: Cross-Architecture Vulnerability Comparison Across Attack Categories (GPT-OSS-20B vs. Qwen-27B)")
                cap_run.font.italic = True
                cap_run.font.size = Pt(9.5)
                cap_run.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

        i += 1

    if in_table:
        flush_table()
    if in_code_block:
        flush_code()

    output_path = "Mid_Term_Report.docx"
    doc.save(output_path)
    print(f"[+] Successfully generated Word document: {output_path}")


if __name__ == "__main__":
    build_docx_report()
