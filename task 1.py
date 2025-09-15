#!/usr/bin/env python3
"""
secure_review.py — Lightweight Secure Coding Review tool for Python projects.

Features:
- Walks a project directory and scans .py files using AST + regex checks
- Flags risky APIs (eval/exec, subprocess with shell=True, yaml.load, pickle, md5/sha1, verify=False, debug=True, etc.)
- Detects common secret patterns (AWS keys, private keys, tokens, passwords)
- Notes use of 'random' where 'secrets' is recommended
- Flags http:// URLs in code (potential mixed-content/insecure transport)
- Optionally runs Bandit, Semgrep, and pip-audit (if installed) and merges results
- Outputs both Markdown and JSON reports with remediation steps and references

Usage:
    python secure_review.py --path /path/to/project \
                            --out md:report.md json:report.json \
                            --include-tests
"""
import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ----------------------- Utilities -----------------------

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", f"{e}"

def read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None

def get_snippet(text: str, lineno: int, context: int = 2) -> str:
    if not text or lineno <= 0:
        return ""
    lines = text.splitlines()
    i = max(0, lineno - 1 - context)
    j = min(len(lines), lineno - 1 + context + 1)
    numbered = []
    for idx in range(i, j):
        mark = ">>" if (idx + 1) == lineno else "  "
        numbered.append(f"{mark} {idx+1:4d}: {lines[idx]}")
    return "\n".join(numbered)

def add_finding(findings: List[Dict], *, rule_id: str, severity: str, title: str,
                message: str, file: str, line: int, snippet: str, recommendation: str,
                references: Optional[List[str]] = None):
    findings.append({
        "rule_id": rule_id,
        "severity": severity.upper(),
        "title": title,
        "message": message,
        "file": file,
        "line": line,
        "snippet": snippet,
        "recommendation": recommendation,
        "references": references or []
    })

# ----------------------- AST Checks -----------------------

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, code: str, findings: List[Dict]):
        self.filename = filename
        self.code = code
        self.findings = findings
        self.imports: Dict[str, str] = {}  # alias -> module
        super().__init__()

    # Track imports to resolve calls like yaml.load, hashlib.md5
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            fq = f"{module}.{alias.name}" if module else alias.name
            self.imports[alias.asname or alias.name] = fq
        self.generic_visit(node)

    def _name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self._name(node.func)
        return ""

    def visit_Call(self, node: ast.Call):
        fname = self._name(node.func)

        # eval / exec
        if fname in ("eval", "builtins.eval", "exec", "builtins.exec"):
            add_finding(
                self.findings,
                rule_id="PY-EVAL-EXEC",
                severity="HIGH",
                title="Use of eval/exec",
                message=f"Detected call to {fname}.",
                file=self.filename,
                line=node.lineno,
                snippet=get_snippet(self.code, node.lineno),
                recommendation="Avoid eval/exec; use safe parsers or explicit mappings. If needed, restrict inputs and sandbox."
            )

        # compile(..., mode='exec')
        if fname in ("compile", "builtins.compile"):
            for kw in node.keywords or []:
                if getattr(kw, "arg", None) == "mode":
                    if isinstance(kw.value, ast.Str) and kw.value.s in ("exec", "eval"):
                        add_finding(
                            self.findings,
                            rule_id="PY-COMPILE-EXEC",
                            severity="HIGH",
                            title="Dynamic code compilation",
                            message="compile() used with mode that executes code.",
                            file=self.filename,
                            line=node.lineno,
                            snippet=get_snippet(self.code, node.lineno),
                            recommendation="Avoid dynamic code execution; pre-compile trusted code or remove feature."
                        )

        # subprocess with shell=True
        if fname.startswith("subprocess.") and fname.split(".")[-1] in ("Popen", "call", "run", "check_output"):
            shell_true = any((isinstance(k.value, ast.NameConstant) and k.value.value is True)_
