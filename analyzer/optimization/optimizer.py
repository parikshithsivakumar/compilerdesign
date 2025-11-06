#!/usr/bin/env python3
import clang.cindex
from clang.cindex import CursorKind, TokenKind, TranslationUnitLoadError
import os
import re
import sys
import tempfile

# ---------- Set up libclang ----------
try:
    clang.cindex.Config.set_library_path("/usr/lib/llvm-14/lib")
except Exception:
    pass


# ---------- Basic CFG block (for display only) ----------
class BasicBlock:
    def __init__(self, block_id, function_name):
        self.id = block_id
        self.function_name = function_name
        self.statements = []

    def add_statement(self, stmt):
        self.statements.append(stmt)

    def __repr__(self):
        return f"Block {self.function_name}_B{self.id}: {len(self.statements)} statements"


class CFGBuilder:
    def __init__(self):
        self.blocks = []
        self.current_block = None

    def build(self, func_cursor):
        self.blocks = []
        self.current_block = BasicBlock(0, func_cursor.spelling)
        self.blocks.append(self.current_block)
        self._traverse(func_cursor)
        return self.blocks

    def _traverse(self, cursor):
        for c in cursor.get_children():
            if c.kind == CursorKind.COMPOUND_STMT:
                self._traverse(c)
            elif c.kind.is_expression() or c.kind.is_statement():
                self.current_block.add_statement(c)


# ---------- Optimizer ----------
class Optimizer:
    NOISE_TOKENS = {
        "__bswap_16", "__bswap_32", "__bswap_64",
        "__builtin_bswap32", "__builtin_bswap64",
        "__builtin_expect", "__inline", "__extension__"
    }

    def __init__(self, filename):
        self.filename = filename
        self.index = clang.cindex.Index.create()
        self.translation_unit = None
        self.suggestions = []
        self._parse_file(filename)

    # --- Static helper for Streamlit use ---
    @staticmethod
    def from_code(code: str):
        """Create an Optimizer instance directly from a string of C code."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_file = os.path.join(tmpdir, "temp.c")
            with open(temp_file, "w") as f:
                f.write(code)
            opt = Optimizer(temp_file)
            opt._analyze()
            return opt.suggestions

    def _parse_file(self, filename):
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Test file not found: {filename}")

        base_args = ["-x", "c", "-std=c11", "-I.", "-nostdinc"]
        for args in (base_args, ["-x", "c", "-std=c11", "-I."], ["-x", "c"]):
            try:
                self.translation_unit = self.index.parse(filename, args=args)
                return
            except TranslationUnitLoadError:
                continue

        raise RuntimeError("❌ Unable to parse translation unit. Check libclang path or file validity.")

    # --- Core pipeline ---
    def run(self):
        print("🔍 Running optimizer test...")
        self._analyze()
        print("\n=== Optimization Suggestions ===")
        if not self.suggestions:
            print("⚠️ No optimization opportunities detected.")
        else:
            for s in sorted(self.suggestions, key=lambda x: (x["file"], x["line"])):
                print(f"[{s['opt_type']}] {s['file']}:{s['line']}: {s['suggestion']}")

    def _analyze(self):
        cursor = self.translation_unit.cursor
        for func_cursor in cursor.walk_preorder():
            if func_cursor.kind == CursorKind.FUNCTION_DECL and func_cursor.is_definition():
                self._dataflow_analysis(func_cursor)

    def _dataflow_analysis(self, func_cursor):
        tokens = [
            t for t in func_cursor.get_tokens()
            if not (t.spelling in self.NOISE_TOKENS)
        ]

        exprs = []
        cur_tokens = []
        start_line = None
        for t in tokens:
            if start_line is None and t.location and t.location.file and t.location.file.name == os.path.abspath(self.filename):
                start_line = t.location.line
            cur_tokens.append(t)
            if t.kind == TokenKind.PUNCTUATION and t.spelling == ";":
                lines = [tok.spelling for tok in cur_tokens if not (tok.kind == TokenKind.COMMENT)]
                if lines:
                    first_line, last_line = None, None
                    for tok in cur_tokens:
                        if tok.location and tok.location.file and os.path.abspath(tok.location.file.name) == os.path.abspath(self.filename):
                            if first_line is None:
                                first_line = tok.location.line
                            last_line = tok.location.line
                    exprs.append({
                        "text": " ".join(lines).strip(),
                        "start_line": first_line or func_cursor.location.line,
                        "end_line": last_line or func_cursor.location.line
                    })
                cur_tokens, start_line = [], None

        self._find_optimizations(exprs)

    def _find_optimizations(self, exprs):
        seen_exprs = set()
        suggestions = []
        for i, e in enumerate(exprs):
            text = e["text"]
            line = e["start_line"] or e["end_line"] or 0
            norm = re.sub(r'\s+', ' ', text).strip()

            # --- Dead Code Elimination ---
            m_decl = re.search(r'(?:int\s+)?([A-Za-z_]\w*)\s*=\s*([^;]+)', norm)
            if m_decl:
                var = m_decl.group(1)
                if var not in ("i",):
                    used_later = any(re.search(rf'\b{re.escape(var)}\b', o["text"]) for o in exprs[i+1:])
                    if not used_later:
                        suggestions.append({
                            "opt_type": "DEAD_CODE_ELIMINATION",
                            "file": os.path.abspath(self.filename),
                            "line": line,
                            "suggestion": f"The assignment to '{var}' appears never to be used later."
                        })

            # --- Redundant Expression ---
            if re.search(r'=\s*[A-Za-z_]\w*\s*\+\s*0', norm) or re.search(r'=\s*[A-Za-z_]\w*\s*\*\s*1', norm):
                suggestions.append({
                    "opt_type": "REDUNDANT_EXPRESSION",
                    "file": os.path.abspath(self.filename),
                    "line": line,
                    "suggestion": f"The expression '{text.strip()}' is redundant and has no effect."
                })

            # --- Common Subexpression ---
            binary_ops = re.findall(r'([A-Za-z_]\w*\s*[\+\-\*/]\s*[A-Za-z_0-9\(\)]+)', norm)
            for op in binary_ops:
                key = re.sub(r'\s+', '', op)
                if re.search(r'(\+0|0\+|^\s*1\*|\*1\b)', op):
                    continue
                if key in seen_exprs:
                    suggestions.append({
                        "opt_type": "COMMON_SUBEXPRESSION_ELIMINATION",
                        "file": os.path.abspath(self.filename),
                        "line": line,
                        "suggestion": f"The expression '{op.strip()}' has already been computed earlier."
                    })
                else:
                    seen_exprs.add(key)

        # Deduplicate
        unique = {(s["opt_type"], s["file"], s["line"], s["suggestion"]): s for s in suggestions}
        self.suggestions.extend(unique.values())


# ---------- CLI Mode ----------
if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        optimizer = Optimizer(test_file)
        optimizer.run()
    else:
        # Default demo file
        sample = r'''
int compute(int a, int b) {
    int x = a + b;
    int y = x * 2;
    int z = x + 0;
    int total = 0;
    int limit = 5;
    int unused_var = 42;
    for (int i = 0; i < limit; i++) {
        total = total + (a + b);
    }
    return total + y + z;
}
'''
        print("⚙️ Running demo on internal sample code...")
        results = Optimizer.from_code(sample)
        for s in results:
            print(f"[{s['opt_type']}] line {s['line']}: {s['suggestion']}")
