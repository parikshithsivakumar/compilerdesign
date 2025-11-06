# analyzer/optimization/loops.py

from clang.cindex import CursorKind
from .utils import get_defined_vars, get_used_vars


def _find_loops_dfs(cfg, max_depth=5000):
    """
    Finds loops in a CFG using Depth First Search to detect back-edges.
    Includes depth limits to prevent infinite recursion.
    """
    loops = []
    visited = set()
    recursion_stack = []

    def dfs_visit(block, depth=0):
        if depth > max_depth:
            print("⚠️ Loop DFS aborted — exceeded recursion limit.")
            return
        if block.id in recursion_stack:
            return

        recursion_stack.append(block.id)
        visited.add(block.id)

        for succ in block.successors:
            if succ.id not in visited:
                dfs_visit(succ, depth + 1)
            elif succ.id in recursion_stack:
                # Found a back-edge (block → successor)
                loop_blocks = _get_loop_blocks(cfg, succ, block)
                if loop_blocks:
                    loops.append(loop_blocks)

        recursion_stack.pop()

    if cfg.entry_block:
        dfs_visit(cfg.entry_block)
    return loops


def _get_loop_blocks(cfg, header, back_edge_node):
    """
    Given a loop header and a node with a back-edge,
    perform a backward traversal to collect all loop blocks.
    """
    loop_blocks = {header}
    stack = [back_edge_node]
    visited = {header, back_edge_node}

    max_steps = 10000  # Prevent runaway
    steps = 0

    while stack and steps < max_steps:
        steps += 1
        node = stack.pop()
        for pred in node.predecessors:
            if pred not in visited:
                visited.add(pred)
                stack.append(pred)
        loop_blocks.add(node)

    if steps >= max_steps:
        print("⚠️ Stopping loop block search early — too many iterations.")
    return loop_blocks


def find_loop_invariant_code(cfg):
    """
    Finds loops and detects simple loop-invariant computations.
    """
    findings = []
    loops = _find_loops_dfs(cfg)

    for loop_set in loops:  # loop_set is a set of BasicBlock objects

        # Collect all variables defined inside the loop
        vars_defined_in_loop = set()
        for block in loop_set:
            for stmt in block.statements:
                vars_defined_in_loop.update(get_defined_vars(stmt))

        # Analyze each statement inside the loop
        for block in loop_set:
            for stmt in block.statements:
                is_candidate = False
                uses = set()

                # Detect assignment-like binary operations (e.g., x = y + z)
                if stmt.kind == CursorKind.BINARY_OPERATOR:
                    children = list(stmt.get_children())
                    if len(children) == 2:
                        rhs = children[1]
                        uses = get_used_vars(rhs)
                        # Only consider simple RHS expressions
                        if rhs.kind in [CursorKind.BINARY_OPERATOR, CursorKind.DECL_REF_EXPR]:
                            is_candidate = True

                # If expression depends only on variables outside the loop
                if is_candidate:
                    if uses and not (uses & vars_defined_in_loop):
                        findings.append({
                            "opt_type": "LOOP_INVARIANT_CODE_MOTION",
                            "suggestion": (
                                "This calculation uses only loop-invariant variables "
                                "and can be moved outside the loop."
                            ),
                            "line": stmt.location.line,
                            "node": stmt
                        })

    return findings
