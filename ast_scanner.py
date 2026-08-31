# ast_scanner.py
# Qryptis — Python AST (Abstract Syntax Tree) Cryptographic Discovery Engine
# Performs structural static analysis of Python source code to detect cryptographic primitives

import ast
from typing import List, Dict, Any, Optional


class PythonCryptoASTVisitor(ast.NodeVisitor):
    """AST Node Visitor for discovering cryptographic API usage in Python code."""

    def __init__(self, file_path: str = "source.py", lines: Optional[List[str]] = None):
        self.file_path = file_path
        self.lines = lines or []
        self.findings: List[Dict[str, Any]] = []
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None
        self.imported_modules: Dict[str, str] = {}  # alias -> full_name

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.imported_modules[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            name = f"{module}.{alias.name}" if module else alias.name
            asname = alias.asname or alias.name
            self.imported_modules[asname] = name
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        prev_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = prev_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        prev_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev_function

    def visit_Call(self, node: ast.Call):
        call_name = self._resolve_call_name(node.func)
        if call_name:
            self._inspect_crypto_call(node, call_name)
        self.generic_visit(node)

    def _resolve_call_name(self, func_node: ast.AST) -> str:
        """Resolve dotted or simple call expression (e.g. 'RSA.generate', 'AES.new')."""
        if isinstance(func_node, ast.Name):
            return self.imported_modules.get(func_node.id, func_node.id)
        elif isinstance(func_node, ast.Attribute):
            value_name = self._resolve_call_name(func_node.value)
            if value_name:
                return f"{value_name}.{func_node.attr}"
            return func_node.attr
        return ""

    def _get_code_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _inspect_crypto_call(self, node: ast.Call, call_name: str):
        lineno = getattr(node, "lineno", 1)
        code_line = self._get_code_line(lineno)

        # 1. PyCryptodome RSA.generate(bits)
        if "RSA.generate" in call_name or call_name.endswith(".RSA.generate"):
            key_size = 2048
            if node.args:
                val = self._extract_int_literal(node.args[0])
                if val:
                    key_size = val
            for kw in node.keywords:
                if kw.arg in ("bits", "key_size"):
                    val = self._extract_int_literal(kw.value)
                    if val:
                        key_size = val

            self.findings.append({
                "algorithm": "RSA",
                "full_name": f"RSA-{key_size}",
                "key_size": key_size,
                "file": self.file_path,
                "line_number": lineno,
                "usage": "Asymmetric Key Pair Generation / PKI",
                "detection_method": "AST",
                "confidence": "High",
                "ast_node": "Call: RSA.generate",
                "enclosing_function": self.current_function or "global",
                "enclosing_class": self.current_class or "None",
                "code_line": code_line,
                "matched_text": code_line
            })

        # 2. PyCryptodome AES.new(key, mode)
        elif "AES.new" in call_name or call_name.endswith(".AES.new"):
            mode = "MODE_CBC"
            if len(node.args) >= 2:
                mode = self._extract_name_or_attr(node.args[1]) or mode
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode = self._extract_name_or_attr(kw.value) or mode

            self.findings.append({
                "algorithm": "AES",
                "full_name": "AES-256" if "GCM" in mode else "AES-128",
                "key_size": 256 if "GCM" in mode else 128,
                "file": self.file_path,
                "line_number": lineno,
                "usage": f"Symmetric Encryption ({mode})",
                "detection_method": "AST",
                "confidence": "High",
                "ast_node": f"Call: AES.new ({mode})",
                "enclosing_function": self.current_function or "global",
                "enclosing_class": self.current_class or "None",
                "code_line": code_line,
                "matched_text": code_line
            })

        # 3. PyCryptodome DES3.new(key, mode) / DES.new(key)
        elif "DES3.new" in call_name or call_name.endswith(".DES3.new") or "DES.new" in call_name:
            self.findings.append({
                "algorithm": "3DES",
                "full_name": "3DES",
                "key_size": 168,
                "file": self.file_path,
                "line_number": lineno,
                "usage": "Legacy Block Cipher (Sweet32 Disallowance)",
                "detection_method": "AST",
                "confidence": "High",
                "ast_node": "Call: DES3.new",
                "enclosing_function": self.current_function or "global",
                "enclosing_class": self.current_class or "None",
                "code_line": code_line,
                "matched_text": code_line
            })

        # 4. PyCryptodome ECC.generate(curve='P-256') / ECDSA
        elif "ECC.generate" in call_name or "ec.generate_private_key" in call_name:
            curve = "P-256"
            if node.args:
                c_val = self._extract_str_literal(node.args[0])
                if c_val:
                    curve = c_val
            for kw in node.keywords:
                if kw.arg in ("curve", "curve_name"):
                    c_val = self._extract_str_literal(kw.value)
                    if c_val:
                        curve = c_val

            self.findings.append({
                "algorithm": "ECC",
                "full_name": f"ECDSA {curve}",
                "key_size": 256 if "256" in curve else 384,
                "file": self.file_path,
                "line_number": lineno,
                "usage": "Elliptic Curve Key Pair Generation",
                "detection_method": "AST",
                "confidence": "High",
                "ast_node": f"Call: ECC.generate ({curve})",
                "enclosing_function": self.current_function or "global",
                "enclosing_class": self.current_class or "None",
                "code_line": code_line,
                "matched_text": code_line
            })

        # 5. PyCryptodome DSA.generate(bits)
        elif "DSA.generate" in call_name or call_name.endswith(".DSA.generate"):
            key_size = 2048
            if node.args:
                val = self._extract_int_literal(node.args[0])
                if val:
                    key_size = val

            self.findings.append({
                "algorithm": "DSA",
                "full_name": f"DSA-{key_size}",
                "key_size": key_size,
                "file": self.file_path,
                "line_number": lineno,
                "usage": "Legacy Digital Signature Algorithm",
                "detection_method": "AST",
                "confidence": "High",
                "ast_node": "Call: DSA.generate",
                "enclosing_function": self.current_function or "global",
                "enclosing_class": self.current_class or "None",
                "code_line": code_line,
                "matched_text": code_line
            })

        # 6. hashlib / Crypto Hash algorithms (MD5, SHA1, SHA256)
        elif "hashlib.md5" in call_name or "MD5.new" in call_name:
            self.findings.append({
                "algorithm": "MD5",
                "full_name": "MD5",
                "key_size": 128,
                "file": self.file_path,
                "line_number": lineno,
                "usage": "Cryptographic Hash (Collision Vulnerable)",
                "detection_method": "AST",
                "confidence": "High",
                "ast_node": "Call: hashlib.md5",
                "enclosing_function": self.current_function or "global",
                "enclosing_class": self.current_class or "None",
                "code_line": code_line,
                "matched_text": code_line
            })

        # 7. Post-Quantum Native oqs.KeyEncapsulation / oqs.Signature
        elif "KeyEncapsulation" in call_name or "Signature" in call_name or "oqs." in call_name:
            algo_name = "ML-KEM-768"
            if node.args:
                s_val = self._extract_str_literal(node.args[0])
                if s_val:
                    algo_name = s_val

            self.findings.append({
                "algorithm": algo_name,
                "full_name": algo_name,
                "key_size": 256,
                "file": self.file_path,
                "line_number": lineno,
                "usage": "NIST Post-Quantum Cryptographic Primitive",
                "detection_method": "AST",
                "confidence": "High",
                "ast_node": f"Call: oqs ({algo_name})",
                "enclosing_function": self.current_function or "global",
                "enclosing_class": self.current_class or "None",
                "code_line": code_line,
                "matched_text": code_line
            })

        # 8. Cryptography hazmat rsa.generate_private_key
        elif "rsa.generate_private_key" in call_name or "generate_private_key" in call_name:
            key_size = 2048
            for kw in node.keywords:
                if kw.arg == "key_size":
                    val = self._extract_int_literal(kw.value)
                    if val:
                        key_size = val

            self.findings.append({
                "algorithm": "RSA",
                "full_name": f"RSA-{key_size}",
                "key_size": key_size,
                "file": self.file_path,
                "line_number": lineno,
                "usage": "Hazmat RSA Private Key Generation",
                "detection_method": "AST",
                "confidence": "High",
                "ast_node": "Call: rsa.generate_private_key",
                "enclosing_function": self.current_function or "global",
                "enclosing_class": self.current_class or "None",
                "code_line": code_line,
                "matched_text": code_line
            })

    def _extract_int_literal(self, node: ast.AST) -> Optional[int]:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        elif isinstance(node, ast.Num):  # Python 3.7 compatibility
            return int(node.n)
        return None

    def _extract_str_literal(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):
            return node.s
        return None

    def _extract_name_or_attr(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return None


def scan_python_code_ast(code_text: str, file_path: str = "source.py") -> List[Dict[str, Any]]:
    """Parse Python code into AST and run the visitor to produce structured cryptographic findings."""
    lines = code_text.splitlines()
    try:
        tree = ast.parse(code_text, filename=file_path)
        visitor = PythonCryptoASTVisitor(file_path=file_path, lines=lines)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        # If AST parsing fails due to syntax errors, return empty to let regex fallback take over
        return []
