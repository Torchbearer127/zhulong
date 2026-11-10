#!/usr/bin/env python3
"""Offline DOCX presentation regressions using anonymous source-bound fixtures."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

if os.environ.get("ZHULONG_TEST_CORE"):
    sys.path.insert(0, str(Path(os.environ["ZHULONG_TEST_CORE"]) / "scripts"))

from docx import Document
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
import render_confirmed_vuln_docx as renderer
import selftest_plugin as fixtures

CORE = Path(renderer.__file__).resolve().parent.parent
FONTS = {"ascii": "Times New Roman", "hAnsi": "Times New Roman",
         "eastAsia": "SimSun", "cs": "Times New Roman"}


def invoke(command, env=None, cwd=CORE):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    receipt = os.environ.get("ZHULONG_TYPOGRAPHY_RECEIPTS")
    if receipt:
        with Path(receipt).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"argv": command, "returncode": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr}, ensure_ascii=False) + "\n")
    return result


def package_bytes(bundle):
    return {str(path.relative_to(bundle)): path.read_bytes() for path in bundle.rglob("*")
            if path.is_file() and path.suffix != ".docx"}


class TypographyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="zhulong-typography-")
        cls.root = Path(cls.temp.name)
        fakebin = cls.root / "bin"
        fakebin.mkdir()
        docker = fakebin / "docker"
        docker.write_text('#!/bin/sh\ncase "$*" in "compose version"|*" config") exit 0;; *) exit 99;; esac\n')
        docker.chmod(0o755)
        cls.env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ["PATH"])
        cls.bundles = {}
        cls.inputs = {}
        for language in ("zh-CN", "en-US"):
            repo, workspace = fixtures.new_build_wrapper_workspace(cls.root, language)
            slug = fixtures.build_wrapper_source_finding(
                CORE, repo, workspace,
                slug="demo-app_Path_Traversal_高危漏洞报告" if language == "zh-CN" else "demo-app_Path_Traversal_High_report",
            )
            contract = fixtures.build_wrapper_contract(workspace, slug)
            payload = json.loads(contract.read_text())
            payload["bundle"]["language"] = language
            source = repo / "src/importer.py"
            raw = source.read_bytes()
            payload["source_binding"]["source_references"].append({
                **payload["source_binding"]["source_references"][0], "id": "quote",
                "start_line": 1, "end_line": 3, "sha256": hashlib.sha256(raw).hexdigest(),
            })
            contract.write_text(json.dumps(payload))
            finding_path = workspace / "confirmed/findings.json"
            findings = json.loads(finding_path.read_text())
            finding = findings["findings"][0]
            finding["attachments"].append({"path": "src/importer.py", "purpose": "源代码原文"})
            item = dict(finding["code_context"][0])
            item.update(location="src/importer.py:1-3", snippet=raw.decode().rstrip("\n"))
            finding["code_context"].append(item)
            if language == "en-US":
                for key in list(finding):
                    if key.startswith(("vulnerability_name", "vuln_type")):
                        del finding[key]
                finding.update(report_language=language, vulnerability_name="Path Traversal", vuln_type="Path Traversal")
            finding_path.write_text(json.dumps(findings))
            result = invoke([sys.executable, str(CORE / "scripts/build_confirmed_bundle.py"),
                             "--repo-root", str(repo), "--workspace-dir", str(workspace),
                             "--contract", str(contract), "--language", language], cls.env)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            cls.bundles[language] = workspace / "confirmed" / slug
            cls.inputs[language] = (repo, finding_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def validate(self, bundle, language, *flags):
        return invoke([sys.executable, str(CORE / "scripts/validate_report_bundle.py"),
                       "--bundle-dir", str(bundle), "--language", language, *flags], self.env)

    def copy_bundle(self, pristine, name):
        workspace = self.root / name / pristine.parent.parent.name
        bundle = workspace / "confirmed" / pristine.name
        shutil.copytree(pristine, bundle)
        shutil.copyfile(pristine.parent.parent / "asr-config.json", workspace / "asr-config.json")
        return bundle

    def assertFonts(self, root):
        for fonts in root.iter(qn("w:rFonts")):
            self.assertEqual({key: fonts.get(qn("w:" + key)) for key in FONTS}, FONTS)
            self.assertFalse(any(qn("w:" + key + "Theme") in fonts.attrib for key in FONTS))
            self.assertNotIn(qn("w:cstheme"), fonts.attrib)
        for run in root.iter(qn("w:r")):
            if any(text.text for text in run.iter(qn("w:t"))):
                self.assertIsNotNone(run.find("./" + qn("w:rPr") + "/" + qn("w:rFonts")))

    def test_generated_default_template_fonts(self):
        for language, bundle in self.bundles.items():
            with self.subTest(language=language):
                doc = Document(next(bundle.glob("*.docx")))
                self.assertFonts(doc._element)
                self.assertFonts(doc.styles.element)
                defaults = doc.styles.element.find("./" + qn("w:docDefaults") + "/" + qn("w:rPrDefault"))
                self.assertIsNotNone(defaults.find("./" + qn("w:rPr") + "/" + qn("w:rFonts")))

    def test_font_only_helper_preserves_other_ooxml(self):
        doc = Document()
        paragraph = doc.add_paragraph("中文 Latin 123")
        paragraph.paragraph_format.space_after = Pt(9)
        run = paragraph.runs[0]
        run.bold = True
        run.italic = True
        run.font.size = Pt(13)
        run.font.name = "Arial"
        run._element.rPr.rFonts.set(qn("w:asciiTheme"), "majorHAnsi")
        doc.add_table(rows=1, cols=1).cell(0, 0).text = "表格 Table 456"
        doc.sections[0].header.paragraphs[0].text = "页眉 Header 789"
        doc.sections[0].footer.paragraphs[0].text = "页脚 Footer 012"
        before = deepcopy(doc._element)
        style_before = deepcopy(doc.styles.element)
        renderer.apply_report_fonts(doc)
        self.assertFonts(doc._element)
        self.assertFonts(doc.styles.element)
        for part in doc.part.related_parts.values():
            if part.content_type in {"application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml",
                                     "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"}:
                self.assertFonts(part.element)

        def without_fonts(element):
            value = deepcopy(element)
            for node in list(value.iter(qn("w:rFonts"))):
                node.getparent().remove(node)
            for node in list(value.iter(qn("w:rPr"))):
                if not len(node) and not node.attrib:
                    node.getparent().remove(node)
            return value

        from lxml import etree
        self.assertEqual(etree.tostring(without_fonts(before)), etree.tostring(without_fonts(doc._element)))
        self.assertEqual(etree.tostring(without_fonts(style_before)), etree.tostring(without_fonts(doc.styles.element)))
        self.assertTrue(run.bold)
        self.assertTrue(run.italic)
        self.assertEqual(run.font.size.pt, 13)
        # Font normalization must not create unused header/footer parts.
        empty = Document()
        before_parts = set(empty.part.related_parts)
        renderer.apply_report_fonts(empty)
        self.assertEqual(set(empty.part.related_parts), before_parts)

    def test_actual_renderer_with_active_theme_and_header_footer_tables(self):
        template = Document()
        template.styles["Normal"].font.name = "Arial"
        for style in ("Normal", "Title", "Heading 1"):
            fonts = template.styles[style].element.get_or_add_rPr().get_or_add_rFonts()
            for slot in FONTS:
                fonts.set(qn("w:" + ("cstheme" if slot == "cs" else slot + "Theme")), "majorHAnsi")
        header = template.sections[0].header
        header.paragraphs[0].text = "中文 Header 123"
        header.paragraphs[0].runs[0].font.name = "Calibri"
        header.add_table(rows=1, cols=1, width=Inches(3)).cell(0, 0).text = "页眉表格 Table 456"
        template.sections[0].footer.paragraphs[0].text = "页脚 Footer 789"
        path = self.root / "custom-template.docx"
        template.save(path)
        for language, (repo, findings) in self.inputs.items():
            with self.subTest(language=language):
                result = invoke([sys.executable, str(CORE / "scripts/render_confirmed_vuln_docx.py"),
                                 "--input", str(findings), "--output-dir", str(repo / "rendered/confirmed"),
                                 "--template-docx", str(path), "--language", language], self.env, cwd=repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                doc = Document(next((repo / "rendered/confirmed").rglob("*.docx")))
                self.assertFonts(doc._element)
                self.assertFonts(doc.styles.element)
                self.assertFonts(doc.sections[0].header._element)
                self.assertFonts(doc.sections[0].footer._element)
                self.assertEqual(doc.sections[0].header.tables[0].cell(0, 0).text, "页眉表格 Table 456")
                self.assertEqual(doc.sections[0].footer.paragraphs[0].text, "页脚 Footer 789")

    def test_presentation_is_not_a_bundle_gate_and_bytes_stay_identical(self):
        for language, pristine in self.bundles.items():
            for name, family, size, color, style in (
                ("ordinary", "Arial", 8.5, "000000", "Normal"),
                ("large", "Courier New", 14, "000000", "Normal"),
                ("blue", "Courier New", 8.5, "0000FF", "Normal"),
                ("quote", "Courier New", 8.5, "000000", "Intense Quote"),
                ("combined", "Times New Roman", 14, "0070C0", "Intense Quote"),
            ):
                with self.subTest(language=language, presentation=name):
                    bundle = self.copy_bundle(pristine, language + "-" + name)
                    before = package_bytes(bundle)
                    path = next(bundle.glob("*.docx"))
                    doc = Document(path)
                    texts = [p.text for p in doc.paragraphs]
                    for paragraph in doc.paragraphs:
                        if any(token in paragraph.text for token in ("const secret", "app.use(jwt", "ENTRYPOINT =", "http_fetch(url)", "OUTBOUND_REQUESTS_ENABLED =")):
                            paragraph.style = style
                            for run in paragraph.runs:
                                run.font.name = family
                                run.font.size = Pt(size)
                                run.font.color.rgb = RGBColor.from_string(color)
                    doc.save(path)
                    self.assertEqual(texts, [p.text for p in Document(path).paragraphs])
                    self.assertEqual(before, package_bytes(bundle))
                    for flags in ((), ("--all-errors", "--json")):
                        result = self.validate(bundle, language, *flags)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        if flags:
                            self.assertTrue(json.loads(result.stdout)["valid"])
                    batch = invoke([sys.executable, str(CORE / "scripts/validate_all_report_bundles.py"),
                                    "--confirmed-dir", str(bundle.parent), "--language", language], self.env)
                    self.assertEqual(batch.returncode, 0, batch.stdout + batch.stderr)

    def test_content_evidence_and_runtime_gates_remain(self):
        for language, pristine in self.bundles.items():
            for defect, diagnostic in (("quote", "source quote does not match"),
                                       ("missing", "replay"), ("digest", "sha256"),
                                       ("runtime", "status.target_startup"), ("placeholder", "placeholder")):
                with self.subTest(language=language, defect=defect):
                    bundle = self.copy_bundle(pristine, language + "-bad-" + defect)
                    if defect == "quote":
                        path = bundle / "findings.json"
                        value = json.loads(path.read_text())
                        value["findings"][0]["code_context"][-1]["snippet"] += "\n# invented"
                        path.write_text(json.dumps(value))
                    elif defect in {"missing", "digest"}:
                        path = bundle / "attachments/evidence/replay-output.log"
                        if defect == "missing":
                            path.unlink()
                        else:
                            path.write_bytes(path.read_bytes() + b"digest drift\n")
                    elif defect == "runtime":
                        path = bundle / "bundle-build-manifest.json"
                        value = json.loads(path.read_text())
                        value["status"]["target_startup"] = "passed"
                        path.write_text(json.dumps(value))
                    else:
                        path = next(bundle.glob("*.docx"))
                        doc = Document(path)
                        doc.add_paragraph("最终判定待补充" if language == "zh-CN" else "Final verdict pending")
                        doc.save(path)
                    for flags in ((), ("--all-errors", "--json")):
                        result = self.validate(bundle, language, *flags)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(diagnostic.lower(), (result.stdout + result.stderr).lower())
                        if flags:
                            payload = json.loads(result.stdout)
                            self.assertFalse(payload["valid"])
                            if defect == "quote":
                                self.assertIn("SOURCE_QUOTE_MISMATCH", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
