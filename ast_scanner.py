# ast_scanner.py
# Qryptis — Python AST (Abstract Syntax Tree) Cryptographic Discovery Engine
# Performs structural static analysis of Python source code to detect cryptographic primitives

import ast
from typing import List, Dict, Any, Optional, Tuple


class PythonCryptoASTVisitor(ast.NodeVisitor):
    """
    AST Node Visitor for discovering cryptographic API usage in Python source code.
    Inspects standard libraries (hashlib, ssl), cryptography.hazmat, PyCryptodome, and liboqs.
    """

    def __init__(self, file_path: str = "source.py", lines: Optional[List[str]] = None):
        self.file_path = file_path
        self.lines = lines or []
        self.findings: List[Dict[str, Any]] = []
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None
        self.imported_modules: Dict[str, str] = {}  # alias -> full_name
        self.variable_assignments: Dict[str, Any] = {}

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

    def visit_Assign(self, node: ast.Assign):
        # Track literal variable assignments for key_size and curve names
        val = None
        if isinstance(node.value, ast.Constant):
            val = node.value.value
        elif isinstance(node.value, ast.Num):
            val = node.value.n
        elif isinstance(node.value, ast.Str):
            val = node.value.s

        if val is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.variable_assignments[target.id] = val

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
        """Resolve dotted or simple call expression (e.g. 'rsa.generate_private_key', 'RSA.generate')."""
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

    def _add_finding(
        self,
        algorithm: str,
        key_size: Optional[int],
        purpose: str,
        lineno: int,
        ast_node_desc: str,
        confidence: str = "high",
        usage_desc: Optional[str] = None
    ):
        code_line = self._get_code_line(lineno)
        full_name = f"{algorithm}-{key_size}" if key_size and str(key_size) not in algorithm else algorithm

        finding = {
            "algorithm": algorithm,
            "key_size": key_size,
            "purpose": purpose,
            "file": self.file_path,
            "line": lineno,
            "line_number": lineno,
            "file_path": self.file_path,
            "detection_method": "AST",
            "confidence": confidence,
            "full_name": full_name,
            "usage": usage_desc or purpose.replace("_", " ").title(),
            "ast_node": ast_node_desc,
            "enclosing_function": self.current_function or "global",
            "enclosing_class": self.current_class or "None",
            "code_line": code_line,
            "matched_text": code_line
        }
        self.findings.append(finding)

    def _inspect_crypto_call(self, node: ast.Call, call_name: str):
        lineno = getattr(node, "lineno", 1)
        lower_call = call_name.lower()

        # =====================================================================
        # 1. RSA (cryptography.hazmat, PyCryptodome, PKCS1 signatures)
        # =====================================================================
        if (
            "rsa.generate_private_key" in lower_call
            or "generate_private_key" in lower_call and "rsa" in lower_call
            or "rsa.generate" in lower_call
            or call_name.endswith(".RSA.generate")
            or call_name == "RSA.generate"
        ):
            key_size = 2048
            # Extract from positional or keyword args
            if node.args:
                val = self._extract_int_literal(node.args[0])
                if val:
                    key_size = val
                elif len(node.args) >= 2:
                    val2 = self._extract_int_literal(node.args[1])
                    if val2:
                        key_size = val2

            for kw in node.keywords:
                if kw.arg in ("key_size", "bits"):
                    val = self._extract_int_literal(kw.value)
                    if val:
                        key_size = val

            self._add_finding(
                algorithm="RSA",
                key_size=key_size,
                purpose="digital_signature",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc=f"Asymmetric Key Pair Generation ({key_size}-bit)"
            )
            return

        if "pkcs1_15.new" in lower_call or "pkcs1_v1_5.new" in lower_call or "pss.new" in lower_call:
            self._add_finding(
                algorithm="RSA",
                key_size=2048,
                purpose="digital_signature",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc="RSA Digital Signature Scheme (PKCS#1 / PSS)"
            )
            return

        if "pkcs1_oaep.new" in lower_call or "oaep.new" in lower_call:
            self._add_finding(
                algorithm="RSA",
                key_size=2048,
                purpose="asymmetric_encryption",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc="RSA OAEP Asymmetric Encryption"
            )
            return

        # =====================================================================
        # 2. ECC / ECDSA (cryptography.hazmat ec, PyCryptodome ECC)
        # =====================================================================
        if (
            "ec.generate_private_key" in lower_call
            or "ecc.generate" in lower_call
            or call_name.endswith(".ECC.generate")
            or call_name == "ECC.generate"
        ):
            curve = "P-256"
            if node.args:
                c_val = self._extract_str_or_call_name(node.args[0])
                if c_val:
                    curve = c_val
            for kw in node.keywords:
                if kw.arg in ("curve", "curve_name"):
                    c_val = self._extract_str_or_call_name(kw.value)
                    if c_val:
                        curve = c_val

            key_size = 256
            if "384" in curve:
                key_size = 384
            elif "521" in curve:
                key_size = 521

            self._add_finding(
                algorithm="ECC",
                key_size=key_size,
                purpose="digital_signature",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name} ({curve})",
                confidence="high",
                usage_desc=f"Elliptic Curve Key Pair Generation ({curve})"
            )
            return

        # =====================================================================
        # 3. 3DES / DES / Sweet32 Legacy Ciphers
        # =====================================================================
        if (
            "des3.new" in lower_call
            or "tripledes" in lower_call
            or "des.new" in lower_call and "des3" not in lower_call
            or "algorithms.des" in lower_call
            or "algorithms.tripledes" in lower_call
        ):
            self._add_finding(
                algorithm="3DES",
                key_size=168,
                purpose="symmetric_encryption",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc="Legacy Block Cipher (Sweet32 Disallowance)"
            )
            return

        # =====================================================================
        # 4. AES (cryptography.hazmat, PyCryptodome)
        # =====================================================================
        if (
            "aes.new" in lower_call
            or "algorithms.aes" in lower_call
            or "aes128" in lower_call
            or "aes256" in lower_call
        ):
            mode = "MODE_CBC"
            key_size = 256
            if "aes128" in lower_call:
                key_size = 128
            elif "aes256" in lower_call:
                key_size = 256

            if len(node.args) >= 2:
                m_val = self._extract_name_or_attr(node.args[1])
                if m_val:
                    mode = m_val
            for kw in node.keywords:
                if kw.arg == "mode":
                    m_val = self._extract_name_or_attr(kw.value)
                    if m_val:
                        mode = m_val

            if "gcm" in mode.lower():
                key_size = 256
            elif "128" in mode.lower():
                key_size = 128

            self._add_finding(
                algorithm="AES",
                key_size=key_size,
                purpose="symmetric_encryption",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name} ({mode})",
                confidence="high",
                usage_desc=f"Symmetric Encryption ({mode})"
            )
            return

        # =====================================================================
        # 5. DSA (cryptography.hazmat, PyCryptodome)
        # =====================================================================
        if (
            "dsa.generate_private_key" in lower_call
            or "dsa.generate" in lower_call
            or call_name.endswith(".DSA.generate")
            or call_name == "DSA.generate"
        ):
            key_size = 2048
            if node.args:
                val = self._extract_int_literal(node.args[0])
                if val:
                    key_size = val
            for kw in node.keywords:
                if kw.arg in ("key_size", "bits"):
                    val = self._extract_int_literal(kw.value)
                    if val:
                        key_size = val

            self._add_finding(
                algorithm="DSA",
                key_size=key_size,
                purpose="digital_signature",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc=f"Legacy Digital Signature Algorithm ({key_size}-bit)"
            )
            return

        # =====================================================================
        # 6. Diffie-Hellman / X25519 Key Exchange
        # =====================================================================
        if "dh.generate_parameters" in lower_call or "dh.generate_private_key" in lower_call:
            key_size = 2048
            for kw in node.keywords:
                if kw.arg == "key_size":
                    val = self._extract_int_literal(kw.value)
                    if val:
                        key_size = val

            self._add_finding(
                algorithm="Diffie-Hellman",
                key_size=key_size,
                purpose="key_exchange",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc=f"Classical Diffie-Hellman Key Exchange ({key_size}-bit)"
            )
            return

        if "x25519" in lower_call and "generate" in lower_call:
            self._add_finding(
                algorithm="X25519",
                key_size=256,
                purpose="key_exchange",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc="Elliptic Curve Diffie-Hellman (X25519)"
            )
            return

        if "ed25519" in lower_call and "generate" in lower_call:
            self._add_finding(
                algorithm="Ed25519",
                key_size=256,
                purpose="digital_signature",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc="Edwards-curve Digital Signature (Ed25519)"
            )
            return

        # =====================================================================
        # 7. Hash Functions (hashlib, cryptography.hazmat, PyCryptodome)
        # =====================================================================
        if "hashlib.md5" in lower_call or "md5.new" in lower_call or "hashes.md5" in lower_call:
            self._add_finding(
                algorithm="MD5",
                key_size=128,
                purpose="hash",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc="Cryptographic Hash (Collision Broken)"
            )
            return

        if "hashlib.sha1" in lower_call or "sha1.new" in lower_call or "hashes.sha1" in lower_call:
            self._add_finding(
                algorithm="SHA1",
                key_size=160,
                purpose="hash",
                lineno=lineno,
                ast_node_desc=f"Call: {call_name}",
                confidence="high",
                usage_desc="Cryptographic Hash (SHA-1 Collision Deprecated)"
            )
            return

        if "hashlib.new" in lower_call:
            hash_name = ""
            if node.args:
                h_val = self._extract_str_literal(node.args[0])
                if h_val:
                    hash_name = h_val.upper()
            for kw in node.keywords:
                if kw.arg in ("name", "digestmod"):
                    h_val = self._extract_str_literal(kw.value)
                    if h_val:
                        hash_name = h_val.upper()

            if "MD5" in hash_name:
                self._add_finding(
                    algorithm="MD5",
                    key_size=128,
                    purpose="hash",
                    lineno=lineno,
                    ast_node_desc=f"Call: hashlib.new('{hash_name}')",
                    confidence="high",
                    usage_desc="Cryptographic Hash (MD5 Broken)"
                )
            elif "SHA1" in hash_name:
                self._add_finding(
                    algorithm="SHA1",
                    key_size=160,
                    purpose="hash",
                    lineno=lineno,
                    ast_node_desc=f"Call: hashlib.new('{hash_name}')",
                    confidence="high",
                    usage_desc="Cryptographic Hash (SHA-1 Deprecated)"
                )
            return

        # =====================================================================
        # 8. Post-Quantum Native (oqs / liboqs / pqcrypto)
        # =====================================================================
        if (
            "keyencapsulation" in lower_call
            or "signature" in lower_call and ("oqs" in lower_call or "kem" in lower_call)
            or "oqs." in lower_call
        ):
            pqc_algo = "ML-KEM-768"
            if node.args:
                s_val = self._extract_str_literal(node.args[0])
                if s_val:
                    pqc_algo = s_val

            is_sig = "sig" in lower_call or "dsa" in pqc_algo.lower()
            purpose = "digital_signature" if is_sig else "key_exchange"

            self._add_finding(
                algorithm=pqc_algo,
                key_size=256,
                purpose=purpose,
                lineno=lineno,
                ast_node_desc=f"Call: {call_name} ('{pqc_algo}')",
                confidence="high",
                usage_desc=f"NIST Post-Quantum Primitive ({pqc_algo})"
            )
            return

    def _extract_int_literal(self, node: ast.AST) -> Optional[int]:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        elif isinstance(node, ast.Num):
            return int(node.n)
        elif isinstance(node, ast.Name) and node.id in self.variable_assignments:
            val = self.variable_assignments[node.id]
            if isinstance(val, int):
                return val
        return None

    def _extract_str_literal(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Name) and node.id in self.variable_assignments:
            val = self.variable_assignments[node.id]
            if isinstance(val, str):
                return val
        return None

    def _extract_str_or_call_name(self, node: ast.AST) -> Optional[str]:
        s = self._extract_str_literal(node)
        if s:
            return s
        if isinstance(node, ast.Call):
            resolved = self._resolve_call_name(node.func)
            if resolved:
                return resolved.split(".")[-1]
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Name):
            return self.variable_assignments.get(node.id, node.id)
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
        # On syntax errors in pasted snippet, return empty so graceful fallback occurs
        return []
