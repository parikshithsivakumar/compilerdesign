# analyzer/optimization/available_expr.py

from .dataflow import DataFlowAnalysis
from .utils import get_defined_vars, _parse_expression
from clang.cindex import CursorKind


class AvailableExpressionsAnalysis(DataFlowAnalysis):
    """
    Implements Available Expressions Analysis, a forward data flow analysis.
    Detects expressions like (a + b) and tracks their availability.
    """

    def __init__(self, cfg):
        super().__init__(cfg, max_iterations=100, debug=False)
        self.direction = "forward"

        # Collect all candidate expressions (e.g., a + b, x * y)
        self.all_expressions = self._find_all_expressions(cfg)

        print(f"  Found {len(self.all_expressions)} expressions in function '{cfg.function_name}':")
        for e in self.all_expressions:
            print(f"     {e.left} {e.op} {e.right}")

        # At entry, no expressions are available
        self.initial_value = set()
        self.gen = {}
        self.kill = {}

        self._compute_gen_kill()

    def _find_all_expressions(self, cfg):
        """
        Collect all expressions (like a+b) from *any* nested RHS or declaration initializer.
        Fully recursive to capture expressions inside VAR_DECL → BINARY_OPERATOR chains.
        """
        all_exprs = set()

        def collect_exprs(node):
            expr = _parse_expression(node)
            if expr:
                all_exprs.add(expr)
            for child in node.get_children():
                collect_exprs(child)

        for block in cfg.blocks.values():
            for stmt in block.statements:
                # ✅ Recursively walk every statement — including DECL_STMT contents
                collect_exprs(stmt)

        return all_exprs

    def _compute_gen_kill(self):
        """Compute GEN and KILL sets for each basic block."""
        for block in self.cfg.blocks.values():
            gen_b = set()
            kill_b = set()

            for stmt in block.statements:
                defs = get_defined_vars(stmt)
                if defs:
                    defined_var = list(defs)[0]
                    # Kill any expressions using that variable
                    for expr in self.all_expressions:
                        if defined_var in [expr.left, expr.right]:
                            kill_b.add(expr)

                # GEN: newly computed expressions in this block
                def collect_gen_exprs(node):
                    expr = _parse_expression(node)
                    if expr and expr not in kill_b:
                        gen_b.add(expr)
                    for child in node.get_children():
                        collect_gen_exprs(child)

                collect_gen_exprs(stmt)

            self.gen[block.id] = gen_b
            self.kill[block.id] = kill_b

    def meet_operator(self, sets_to_meet):
        """Meet operator: intersection."""
        if not sets_to_meet:
            return set()
        result = sets_to_meet[0].copy()
        for s in sets_to_meet[1:]:
            result.intersection_update(s)
        return result

    def transfer_function(self, block, in_set):
        """OUT[b] = (IN[b] - KILL[b]) | GEN[b]"""
        gen_b = self.gen[block.id]
        kill_b = self.kill[block.id]
        return (in_set - kill_b) | gen_b


def find_common_subexpressions(cfg, available_expr_results):
    """
    Identify repeated computations (common subexpressions).
    """
    in_sets, out_sets = available_expr_results
    findings = []

    for block in cfg.blocks.values():
        available_now = in_sets[block.id].copy()
        local_seen = set()

        for stmt in block.statements:
            def explore(node):
                expr = _parse_expression(node)
                if expr:
                    if expr in available_now or expr in local_seen:
                        findings.append({
                            "opt_type": "COMMON_SUBEXPRESSION_ELIMINATION",
                            "suggestion": f"The expression '{expr.left} {expr.op} {expr.right}' has already been computed.",
                            "line": node.location.line,
                            "node": node
                        })
                    else:
                        local_seen.add(expr)
                        available_now.add(expr)
                for child in node.get_children():
                    explore(child)

            explore(stmt)

            # Kill invalidated expressions after statement
            defs = get_defined_vars(stmt)
            if defs:
                defined_var = list(defs)[0]
                available_now = {
                    e for e in available_now if defined_var not in [e.left, e.right]
                }

    return findings
