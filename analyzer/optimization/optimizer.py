# analyzer/optimization/optimizer.py

import clang.cindex

# Import all our analysis phases
from .cfg import CFGBuilder
from .liveness import LivenessAnalysis, find_dead_code
from .available_expr import AvailableExpressionsAnalysis, find_common_subexpressions
from .loops import find_loop_invariant_code

# Set libclang path
clang.cindex.Config.set_library_path("/usr/lib/llvm-14/lib")

class Optimizer:
    def __init__(self):
        self.c_code = ""
        self.optimizations_found = []
        self.tu = None  # Translation Unit

    def get_source_code(self, node):
        """Helper to get the source code for a given node."""
        try:
            extent = node.extent
            start = extent.start.offset
            end = extent.end.offset
            return self.c_code[start:end]
        except Exception:
            return f"(Could not get source for node {node.hash})"

    def _find_constant_folding(self, node):
        """
        Recursively finds constant folding opportunities (AST-based).
        """
        if node.location.file and node.location.file.name != 'test.c':
            return

        if node.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                left_child, right_child = children

                if (left_child.kind == clang.cindex.CursorKind.INTEGER_LITERAL and
                    right_child.kind == clang.cindex.CursorKind.INTEGER_LITERAL):

                    try:
                        left_val = int(next(left_child.get_tokens()).spelling)
                        right_val = int(next(right_child.get_tokens()).spelling)

                        # --- Extract operator symbol ---
                        op_token = None
                        for token in node.get_tokens():
                            if token.location.offset > left_child.extent.end.offset and \
                               token.location.offset < right_child.extent.start.offset:
                                op_token = token.spelling
                                break
                        if not op_token:
                            op_token = node.spelling

                        result = 0
                        if op_token == '+': result = left_val + right_val
                        elif op_token == '-': result = left_val - right_val
                        elif op_token == '*': result = left_val * right_val
                        elif op_token == '/': result = int(left_val / right_val)
                        elif op_token == '%': result = left_val % right_val

                        if result != 0 or (left_val == 0 or right_val == 0):
                            self.optimizations_found.append({
                                "opt_type": "CONSTANT_FOLDING",
                                "source_text": self.get_source_code(node),
                                "suggestion": f"This expression can be pre-calculated at compile time to '{result}'.",
                                "line": node.location.line,
                                "node": node
                            })
                    except Exception as e:
                        print(f"Error parsing constant: {e}")

        # Recurse on children
        for child in node.get_children():
            self._find_constant_folding(child)

    def analyze(self, c_code: str):
        """
        Main function to analyze C code for optimization opportunities.
        """
        self.c_code = c_code
        self.optimizations_found = []

        index = clang.cindex.Index.create()
        self.tu = index.parse(
            'test.c',
            args=[],
            unsaved_files=[('test.c', c_code)],
            options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        )

        if not self.tu:
            raise RuntimeError("Error: Unable to parse the C code.")

        root_node = self.tu.cursor

        # --- 1. Run AST-based analyses (Constant Folding) ---
        print("Running Constant Folding...")
        self._find_constant_folding(root_node)

        # --- 2. Build CFGs for all functions ---
        print("Building CFGs...")
        cfg_builder = CFGBuilder(c_code)
        all_cfgs = cfg_builder.build_cfgs(root_node)

        # --- DEBUG: Print tokens for every BINARY_OPERATOR in the AST ---
        print("\n--- AST Token Debug ---")
        for cursor in root_node.walk_preorder():
            if cursor.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
                tokens = [t.spelling for t in cursor.get_tokens()]
                print(f"Line {cursor.location.line}: Tokens = {tokens}")
        print("--- END TOKEN DEBUG ---\n")

        # --- 3. Run Data Flow Analyses on each function's CFG ---
        for func_name, cfg in all_cfgs.items():
            print(f"Analyzing function: {func_name}")

            # --- Liveness & Dead Code ---
            print("  Running Liveness Analysis...")
            liveness = LivenessAnalysis(cfg)
            liveness_results = liveness.run()
            dead_code = find_dead_code(cfg, liveness_results)
            self.optimizations_found.extend(dead_code)

            # --- Available Expressions & CSE ---
            print("  Running Available Expressions Analysis...")
            avail_expr = AvailableExpressionsAnalysis(cfg)
            avail_expr_results = avail_expr.run()
            cse = find_common_subexpressions(cfg, avail_expr_results)
            self.optimizations_found.extend(cse)

            # --- Loop Invariant Code ---
            print("  Finding Loops...")
            loop_invariants = find_loop_invariant_code(cfg)
            self.optimizations_found.extend(loop_invariants)

        # --- 4. Post-process: Get source code for all findings ---
        final_findings = []
        found_set = set()

        for finding in self.optimizations_found:
            key = (finding["opt_type"], finding["line"], finding["suggestion"])
            if key in found_set:
                continue
            found_set.add(key)

            if "source_text" not in finding or finding["source_text"].startswith("(Could not"):
                finding["source_text"] = self.get_source_code(finding["node"])
            final_findings.append(finding)

        return final_findings


if __name__ == "__main__":
    print("🔍 Running optimizer test...")

    # --- Example test C code ---
    c_code = r"""
    int test_optimizations(int a, int b) {
        int x = a + b;
        int y = a + b;
        for (int i = 0; i < 5; i++) {
            int z = x + 2;
        }
        return y;
    }

    int process_data(int n) {
        int sum = 0;
        int i = 0;
        while (i < n) {
            int temp = n * 2;
            sum += temp;
            i++;
        }
        return sum;
    }
    """

    # Run the optimizer
    opt = Optimizer()
    results = opt.analyze(c_code)

    # Print results
    if not results:
        print("✅ No optimizations found.")
    else:
        print("\n=== Optimization Suggestions ===")
        for r in results:
            print(f"[{r['opt_type']}] Line {r['line']}: {r['suggestion']}")
