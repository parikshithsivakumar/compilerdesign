import clang.cindex
import sys
import json
import traceback
import re
import subprocess
from pathlib import Path

# --- Adjust for your system ---
clang.cindex.Config.set_library_path("/usr/lib/llvm-14/lib")

# --- Global lists of known patterns ---
DANGEROUS_FUNCTIONS = ["gets", "strcpy", "strcat", "sprintf"]
SECRET_KEYWORDS = ["pass", "secret", "token", "key", "api_key", "password"]
ALLOC_FUNCTIONS = ["malloc", "calloc", "realloc"]
FILE_OPEN_FUNCTIONS = ["open", "creat", "fopen"]

def find_child_kind(node, kind):
    """Recursively find first child of given kind."""
    if not node:
        return None
    if node.kind == kind:
        return node
    for c in node.get_children():
        found = find_child_kind(c, kind)
        if found:
            return found
    return None

# Escape unsafe characters for Graphviz
def sanitize_label(text):
    text = re.sub(r'["\\{}<>]', '', text)
    text = text.replace("\n", "\\n").replace("\t", " ")
    return text

class AstToDot:
    def __init__(self):
        self.node_counter = 0
        self.dot_nodes = []
        self.dot_edges = []
        self.bugs_found = []
        self.consequence_nodes = set()
        self.freed_vars_by_func = {}
        self.current_function = None
        self.c_code = ""
        self._bug_signatures = set()

    # ----------------- Utilities -----------------
    def get_unique_id(self):
        self.node_counter += 1
        return f"node{self.node_counter}"

    def safe_get_source(self, node):
        try:
            if not node or not node.extent:
                return ""
            start = node.extent.start.offset
            end = node.extent.end.offset
            if start is None or end is None or end <= start:
                return ""
            return self.c_code[start:end]
        except Exception:
            return ""

    # ----------------- Bug detectors -----------------
    def is_unused_return_bug(self, node, parent_node):
        """Detect calls that return a value but result is ignored."""
        if node.kind != clang.cindex.CursorKind.CALL_EXPR:
            return False
        try:
            if node.result_type.kind == clang.cindex.TypeKind.VOID:
                return False
        except Exception:
            return False
        if node.spelling in ("free", "printf", "fprintf", "puts", "log", "exit"):
            return False
        if parent_node and parent_node.kind == clang.cindex.CursorKind.COMPOUND_STMT:
            return True
        return False

    def is_dangerous_call(self, node):
        return node.kind == clang.cindex.CursorKind.CALL_EXPR and node.spelling in DANGEROUS_FUNCTIONS

    def is_hardcoded_secret(self, node):
        if node.kind != clang.cindex.CursorKind.VAR_DECL:
            return False
        name = (node.spelling or "").lower()
        if any(k in name for k in SECRET_KEYWORDS):
            if find_child_kind(node, clang.cindex.CursorKind.STRING_LITERAL):
                return True
        return False

    def is_goto_statement(self, node):
        return node.kind == clang.cindex.CursorKind.GOTO_STMT

    def is_null_pointer_dereference(self, node, parent_node):
        """Detect malloc/calloc/realloc result being dereferenced before NULL check."""
        if node.kind != clang.cindex.CursorKind.VAR_DECL:
            return False
        var_name = node.spelling
        init_call = find_child_kind(node, clang.cindex.CursorKind.CALL_EXPR)
        if not init_call or init_call.spelling not in ALLOC_FUNCTIONS:
            return False

        block = parent_node
        while block and block.kind != clang.cindex.CursorKind.COMPOUND_STMT:
            block = block.semantic_parent
        if not block:
            return False

        siblings = list(block.get_children())
        try:
            idx = [i for i, s in enumerate(siblings) if s.hash == node.hash][0]
        except Exception:
            return False

        for stmt in siblings[idx + 1: idx + 4]:
            src = self.safe_get_source(stmt)
            if f"{var_name}[" in src or f"*{var_name}" in src:
                if "if" in src and var_name in src:
                    return False
                return True
        return False

    def is_insecure_file_permission(self, node):
        """Detect open/creat/fopen with 0777-like modes."""
        if node.kind != clang.cindex.CursorKind.CALL_EXPR:
            return False
        if node.spelling not in FILE_OPEN_FUNCTIONS:
            return False
        args = list(node.get_children())
        for a in args:
            if a.kind == clang.cindex.CursorKind.INTEGER_LITERAL:
                val = next(a.get_tokens(), None)
                if val:
                    try:
                        mode = int(val.spelling, 0)
                        if (mode & 0o002) or (mode & 0o020):
                            return True
                    except Exception:
                        pass
        return False

    def check_use_after_free(self, node, parent_node):
        """Detect reading/writing variable after it was freed."""
        if parent_node and parent_node.kind == clang.cindex.CursorKind.CALL_EXPR and parent_node.spelling == "free":
            return False
        if node.kind == clang.cindex.CursorKind.DECL_REF_EXPR and self.current_function:
            freed_vars = self.freed_vars_by_func.get(self.current_function, set())
            if node.spelling in freed_vars:
                return True
        return False

    # ----------------- Main traversal -----------------
    def find_bugs_and_suggestions(self, node, parent_node=None):
        if not node or (node.location.file and node.location.file.name != "test.c"):
            return

        # skip macros/includes
        if node.kind in (
            clang.cindex.CursorKind.MACRO_DEFINITION,
            clang.cindex.CursorKind.INCLUSION_DIRECTIVE
        ):
            return

        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            self.current_function = node.spelling
            if self.current_function not in self.freed_vars_by_func:
                self.freed_vars_by_func[self.current_function] = set()

        # track free()
        if node.kind == clang.cindex.CursorKind.CALL_EXPR and node.spelling == "free":
            try:
                var = list(node.get_children())[1]
                name = var.spelling.strip()
                self.freed_vars_by_func[self.current_function].add(name)
            except Exception:
                pass

        bug_type = None
        if self.is_dangerous_call(node):
            bug_type = "DANGEROUS_FUNCTION"
        elif self.is_insecure_file_permission(node):
            bug_type = "INSECURE_FILE_PERMISSIONS"
        elif self.is_hardcoded_secret(node):
            bug_type = "HARDCODED_SECRET"
        elif self.is_null_pointer_dereference(node, parent_node):
            bug_type = "NULL_POINTER_DEREFERENCE"
        elif self.is_unused_return_bug(node, parent_node):
            bug_type = "UNUSED_RETURN"
        elif self.is_goto_statement(node):
            bug_type = "GOTO_STATEMENT"
        elif self.check_use_after_free(node, parent_node):
            bug_type = "USE_AFTER_FREE"

        if bug_type:
            line = getattr(node.location, "line", -1)
            spelling = getattr(node, "spelling", "").strip()
            sig = f"{bug_type}:{self.current_function}:{spelling}"
            if sig not in self._bug_signatures:
                self._bug_signatures.add(sig)
                self.bugs_found.append({
                    "node": node,
                    "bug_type": bug_type,
                    "source_text": self.safe_get_source(node)
                })

        for child in node.get_children():
            self.find_bugs_and_suggestions(child, node)

    # ----------------- DOT generation -----------------
    def generate_dot_and_bugs(self, c_code):
        self.node_counter = 0
        self.dot_nodes = []
        self.dot_edges = []
        self.bugs_found = []
        self.consequence_nodes = set()
        self.freed_vars_by_func = {}
        self.current_function = None
        self.c_code = c_code
        self._bug_signatures = set()

        index = clang.cindex.Index.create()
        tu = index.parse(
            "test.c",
            unsaved_files=[("test.c", c_code)],
            args=["-I.", "-nostdinc", "-nostdinc++"],
            options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        )
        if not tu:
            raise RuntimeError("Unable to parse C code")

        root = tu.cursor
        self.find_bugs_and_suggestions(root)

        bug_hashes = {b["node"].hash for b in self.bugs_found}

        def walk(node, parent_id=None):
            if node.location.file and node.location.file.name != "test.c":
                return
            if node.kind in (
                clang.cindex.CursorKind.MACRO_DEFINITION,
                clang.cindex.CursorKind.INCLUSION_DIRECTIVE
            ):
                return

            node_id = self.get_unique_id()
            color = "red" if node.hash in bug_hashes else "lightblue"
            label = sanitize_label(node.kind.name)
            if node.spelling:
                label += f"\\n({sanitize_label(node.spelling)})"
            self.dot_nodes.append(f'{node_id} [label="{label}", fillcolor="{color}"];')
            if parent_id:
                self.dot_edges.append(f'"{parent_id}" -> "{node_id}";')
            for c in node.get_children():
                walk(c, node_id)

        root_id = self.get_unique_id()
        self.dot_nodes.append(f'{root_id} [label="ROOT", fillcolor="lightblue"];')
        for n in root.get_children():
            walk(n, root_id)

        dot = (
            "digraph G {\n"
            "rankdir=TB;\n"
            "node [shape=box, style=filled];\n"
            + "\n".join(self.dot_nodes)
            + "\n"
            + "\n".join(self.dot_edges)
            + "\n}"
        )
        return dot, self.bugs_found


# ----------------- Test Runner -----------------
if __name__ == "__main__":
    test_code = r"""
    #include <string.h>
    #include <stdlib.h>
    #include <fcntl.h>

    int is_admin(int user_id) { return 0; }
    void delete_file(const char* f) {}

    void process_data(int user_id, char* input) {
        is_admin(user_id); 
        delete_file("system.db");

        char buffer[100];
        strcpy(buffer, input); 

        char *api_key = "sk_live_12345";

        char *data = (char*)malloc(1024);
        data[0] = 'A';

        int fd = open("logfile.txt", 1, 0777);

        free(data);
        data[1] = 'B';

        if (user_id < 0) {
            goto error_handler;
        }

    error_handler:
        return;
    }
    """

    try:
        print("Running AST Analysis...\n")
        conv = AstToDot()
        dot, bugs = conv.generate_dot_and_bugs(test_code)

        Path("ast_graph.dot").write_text(dot)
        print("✅ DOT file written: ast_graph.dot")

        try:
            subprocess.run(
                ["dot", "-Tsvg", "ast_graph.dot", "-o", "ast_graph.svg"],
                check=True,
                capture_output=True
            )
            print("✅ AST graph rendered successfully: ast_graph.svg")
        except subprocess.CalledProcessError as e:
            print("⚠️ Graphviz Render Error:")
            print(e.stderr.decode())

        result = [
            {
                "bug_type": b["bug_type"],
                "source_text": b["source_text"].strip(),
                "line": getattr(b["node"].location, "line", -1),
            }
            for b in bugs
        ]

        print(json.dumps(result, indent=2))
        print(f"\nTotal Risks Found: {len(result)}")
    except Exception as e:
        print("Error:", e)
        print(traceback.format_exc())
