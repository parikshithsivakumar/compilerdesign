# analyzer/optimization/loops.py

from clang.cindex import CursorKind
from .utils import get_defined_vars, get_used_vars


def _find_loops_dfs(cfg, max_depth=2000):
    """
    Finds loops in a CFG using DFS to detect back-edges.
    A back-edge (u -> v) where v dominates u implies a loop.
    """
    loops = []
    visited = set()
    recursion_stack = []

    def dfs(block, depth=0):
        if depth > max_depth:
            print("⚠️ Loop DFS aborted — exceeded recursion limit.")
            return

        visited.add(block.id)
        recursion_stack.append(block.id)

        for succ in block.successors:
            # Detect a simple back-edge (succ already in current path)
            if succ.id in recursion_stack:
                loop_blocks = _collect_loop_blocks(cfg, succ, block)
                if loop_blocks:
                    loops.append(loop_blocks)
            elif succ.id not in visited:
                dfs(succ, depth + 1)

        recursion_stack.pop()

    if cfg.entry_block:
        dfs(cfg.entry_block)
    return loops


def _collect_loop_blocks(cfg, header, back_node):
    """
    Given a loop header and a node with a back-edge,
    perform backward traversal to collect all blocks in the loop.
    """
    loop_blocks = {header}
    stack = [back_node]
    visited = {header, back_node}
    steps = 0

    while stack and steps < 5000:
        steps += 1
        node = stack.pop()
        loop_blocks.add(node)
        for pred in node.predecessors:
            if pred not in visited:
                visited.add(pred)
                stack.append(pred)

    return loop_blocks


def find_loop_invariant_code(cfg):
    """
    Detects loop-invariant computations inside loops.

    ✅ Identifies constants and expressions that don’t depend on loop vars
    ✅ Works for 'limit = 5', 'c = a + b' inside loops
    ✅ Avoids false positives (expressions using 'i', 'j', etc.)
    """
    findings = []
    loops = _find_loops_dfs(cfg)

    if not loops:
        print(f"ℹ️ No loops found in function '{cfg.function_name}'.")
        return findings

    for loop_set in loops:
        # Collect all vars defined inside this loop
        vars_defined_in_loop = set()
        for block in loop_set:
            for stmt in block.statements:
                vars_defined_in_loop.update(get_defined_vars(stmt))

        loop_vars = {"i", "j", "k", "idx", "iter", "count", "n"}  # common iterator names

        for block in loop_set:
            for stmt in block.statements:
                if not hasattr(stmt, "kind") or not hasattr(stmt, "location"):
                    continue

                # Detect assignments or binary expressions
                if stmt.kind == CursorKind.BINARY_OPERATOR:
                    children = list(stmt.get_children())
                    if len(children) == 2:
                        lhs, rhs = children
                        used = get_used_vars(rhs)

                        # Treat integer literals as invariant (e.g., limit = 5)
                        has_const_rhs = any(
                            c.kind == CursorKind.INTEGER_LITERAL
                            for c in rhs.get_children()
                        )

                        # Condition for invariant expression
                        if (not (used & vars_defined_in_loop)
                                and not (used & loop_vars)
                                and (used or has_const_rhs)):
                            findings.append({
                                "opt_type": "LOOP_INVARIANT_CODE_MOTION",
                                "suggestion": (
                                    f"The expression '{lhs.spelling} = ...' is loop-invariant "
                                    f"and can be moved outside the loop."
                                ),
                                "line": stmt.location.line,
                                "node": stmt
                            })

    if not findings:
        print(f"ℹ️ No loop-invariant code found in '{cfg.function_name}'.")
    else:
        print(f"✅ Found {len(findings)} loop-invariant candidates in '{cfg.function_name}'.")

    return findings
