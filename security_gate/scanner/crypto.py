import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# CRYPTO-01: Math.random() — not a CSPRNG; must not appear in crypto-adjacent code
_MATH_RANDOM = re.compile(r'Math\.random\s*\(\s*\)')

# CRYPTO-02: createCipheriv / createDecipheriv (GCM) without a setAAD call within the
# function body — outer envelope fields are unauthenticated, enabling recipient-identity
# spoofing and timestamp tampering to bypass replay protection
_CREATE_CIPHERIV = re.compile(r'\bcreate(?:De)?Cipheriv\s*\(')
_SET_AAD = re.compile(r'\.setAAD\s*\(')
_AAD_WINDOW = 15

# CRYPTO-03: hkdf with undefined third argument (salt) — weakens key derivation entropy;
# RFC 5869 permits it but uses a zero-filled salt, reducing security margin
_HKDF_UNDEFINED_SALT = re.compile(r'\bhkdf\s*\([^,]+,[^,]+,\s*undefined\s*,')

# CRYPTO-04: catch block that silently returns null/undefined with no logging —
# authentication failures and tampered-message errors are indistinguishable from
# benign decode errors; log the error class before discarding
_CATCH_START = re.compile(r'\}\s*catch\s*(\([^)]*\)\s*)?\{')
_RETURN_NULL = re.compile(r'\breturn\s+(null|undefined)\s*;?\s*$')
_LOG_CALL = re.compile(r'(console\.(log|error|warn|debug|info)|agent\.log\s*\(|logger\.)')
_SILENT_CATCH_WINDOW = 4

# CRYPTO-05: non-constant-time equality comparison of sensitive values — timing attack
# risk; use timingSafeEqual() for all key and signature material
_TIMING_UNSAFE_CMP = re.compile(
    r'\b(key|secret|token|signature|hash|hmac|mac|password)\w*\s*[!=]==\s*'
    r'(?!null\b|undefined\b|true\b|false\b|\d)',
    re.IGNORECASE,
)

# CRYPTO-06: sensitive key material passed to a log function — private key exposure risk
_LOG_SENSITIVE = re.compile(
    r'console\.(log|error|warn|debug|info)\s*\([^)]*'
    r'\b(privateKey|secretKey|secret_key|private_key|mnemonic|seed|password|passwd)\b',
    re.IGNORECASE,
)


class CryptoScanner(BaseScanner):
    name = "crypto"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for ts_file in self._ts_files(root):
            lines = self._read_lines(ts_file)
            if lines is None:
                continue

            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("//") or self._suppressed(line):
                    continue

                if _MATH_RANDOM.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        file=self._rel(root, ts_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail="Math.random() is not a CSPRNG — use crypto.getRandomValues() or randomBytes()",
                        checklist_item="CRYPTO-01: All randomness uses a cryptographically secure source",
                    ))

                if _CREATE_CIPHERIV.search(line):
                    window = lines[i:i + _AAD_WINDOW + 1]
                    if not any(_SET_AAD.search(wl) for wl in window):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.HIGH,
                            file=self._rel(root, ts_file),
                            line=i + 1,
                            match=stripped[:120],
                            detail=(
                                "GCM cipher created without setAAD — outer envelope fields "
                                "(sender, recipient, timestamp) are unauthenticated and can be "
                                "tampered without triggering the auth tag check"
                            ),
                            checklist_item="CRYPTO-02: AES-GCM AAD covers all unauthenticated envelope fields",
                        ))

                if _HKDF_UNDEFINED_SALT.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.LOW,
                        file=self._rel(root, ts_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail=(
                            "hkdf called with undefined salt — RFC 5869 permits this but uses a "
                            "zero-filled salt, reducing entropy contribution; pass an explicit salt"
                        ),
                        checklist_item="CRYPTO-03: HKDF salt is explicit and non-empty",
                    ))

                if _CATCH_START.search(line):
                    window = lines[i:i + _SILENT_CATCH_WINDOW + 1]
                    has_return_null = any(_RETURN_NULL.search(wl) for wl in window)
                    has_logging = any(_LOG_CALL.search(wl) for wl in window)
                    if has_return_null and not has_logging:
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            file=self._rel(root, ts_file),
                            line=i + 1,
                            match=stripped[:120],
                            detail=(
                                "catch block silently returns null with no logging — authentication "
                                "failures and tampered-message errors are indistinguishable from "
                                "benign decode misses; log the error class before discarding"
                            ),
                            checklist_item="CRYPTO-04: Cryptographic errors are logged before being discarded",
                        ))

                if _TIMING_UNSAFE_CMP.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        file=self._rel(root, ts_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail=(
                            "Sensitive value compared with === or !== — JavaScript equality is not "
                            "constant-time; use timingSafeEqual() for all key and signature comparisons"
                        ),
                        checklist_item="CRYPTO-05: Sensitive value comparisons use constant-time equality",
                    ))

                if _LOG_SENSITIVE.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        file=self._rel(root, ts_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail="Private key or secret material passed to a log function — remove or redact",
                        checklist_item="CRYPTO-06: Key material is never passed to log functions",
                    ))

        return findings
