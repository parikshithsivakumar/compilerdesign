# analyzer/optimization/utils.py

from clang.cindex import CursorKind
import collections

# A simple, hashable representation of an expression (e.g., 'a + b')
Expression = collections.namedtuple('Expression', ['op', 'left', 'right'])


def _find_decl_ref_or_literal(node):
    """
    Recursively search inside wrapper nodes (UNEXPOSED_EXPR, IMPLICIT_CAST_EXPR,
    PAREN_EXPR, UNARY_OPERATOR, etc.) to find a DECL_REF_EXPR or INTEGER_LITERAL.
    Returns a tuple (kind, spelling) or (None, None) if not found.
    """
    if node is None:
        return (None, None)

    # Direct cases
    if node.kind == CursorKind.DECL_REF_EXPR:
        return (CursorKind.DECL_REF_EXPR, node.spelling)
    if node.kind == CursorKind.INTEGER_LITERAL:
        # integer literal sometimes has token spellings rather than .spelling
        try:
            tok = next(node.get_tokens()).spelling
            return (CursorKind.INTEGER_LITERAL, tok)
        except StopIteration:
            return (CursorKind.INTEGER_LITERAL, None)

    # If this node is a wrapper, dive into children
    for child in node.get_children():
        k, s = _find_decl_ref_or_literal(child)
        if k is not None:
            return (k, s)

    # As a fallback, inspect tokens of this node for an integer literal
    try:
        for t in node.get_tokens():
            if t.spelling.isdigit():
                return (CursorKind.INTEGER_LITERAL, t.spelling)
    except Exception:
        pass

    return (None, None)


def _get_var_name_from_node(node):
    """
    Get a variable or literal name from a node by recursively searching inside wrapper nodes.
    Returns string name or None.
    """
    kind, spelling = _find_decl_ref_or_literal(node)
    if kind == CursorKind.DECL_REF_EXPR:
        return spelling
    if kind == CursorKind.INTEGER_LITERAL:
        return spelling
    return None


def _parse_expression(node):
    """
    Detect arithmetic or relational binary operations robustly,
    even when node.spelling is empty (common in Clang AST).
    Uses token inspection to find operator symbols and uses recursive
    extraction of operand names.
    """
    valid_ops = ['+', '-', '*', '/', '%', '==', '!=', '<', '<=', '>', '>=']

    # Only consider binary operator nodes
    if node.kind != CursorKind.BINARY_OPERATOR:
        return None

    children = list(node.get_children())
    if len(children) != 2:
        return None

    left_node, right_node = children

    # Extract operator token from node tokens
    tokens = [t.spelling for t in node.get_tokens()]
    op_token = None
    # prefer multi-char ops first
    for op in ['==', '!=', '<=', '>=']:
        if op in tokens:
            op_token = op
            break
    if op_token is None:
        for op in ['+', '-', '*', '/', '%', '<', '>']:
            if op in tokens:
                op_token = op
                break

    if not op_token:
        return None

    left_name = _get_var_name_from_node(left_node)
    right_name = _get_var_name_from_node(right_node)

    # Final fallback: if one side is None, try token lookup inside child
    if not left_name:
        try:
            tlist = [t.spelling for t in left_node.get_tokens()]
            # pick first identifier-like token
            for t in tlist:
                if t.isidentifier() or t.isdigit():
                    left_name = t
                    break
        except Exception:
            pass

    if not right_name:
        try:
            tlist = [t.spelling for t in right_node.get_tokens()]
            for t in tlist:
                if t.isidentifier() or t.isdigit():
                    right_name = t
                    break
        except Exception:
            pass

    if not left_name or not right_name:
        return None

    # canonicalize commutative ops
    if op_token in ['+', '*', '==', '!='] and left_name > right_name:
        left_name, right_name = right_name, left_name

    return Expression(op_token, left_name, right_name)


def _find_uses_recursive(node, stop_at_def=True):
    """Recursively find all *uses* (DECL_REF_EXPR) in a node's subtree."""
    uses = set()

    if node.kind == CursorKind.DECL_REF_EXPR:
        parent = node.semantic_parent
        is_def = False

        # On LHS of assignment?
        if parent and parent.kind == CursorKind.BINARY_OPERATOR:
            children = list(parent.get_children())
            if children and children[0].hash == node.hash:
                is_def = True

        # Or part of a declaration (VAR_DECL inside DECL_STMT)
        if parent and parent.kind == CursorKind.VAR_DECL:
            is_def = True

        if not is_def:
            uses.add(node.spelling)

    # Recurse into children
    for child in node.get_children():
        if stop_at_def and child.kind == CursorKind.VAR_DECL:
            continue
        uses.update(_find_uses_recursive(child))

    # Also look inside tokens for identifier-like tokens as a fallback
    try:
        for t in node.get_tokens():
            if t.spelling.isidentifier():
                uses.add(t.spelling)
    except Exception:
        pass

    return uses


def get_used_vars(stmt_node):
    """
    Return all variables *used* (read) in a statement.
    Handles DECL_STMT, VAR_DECL, BINARY_OPERATOR, and nested wrappers.
    """
    uses = set()

    # DECL_STMT usually contains VAR_DECL children
    if stmt_node.kind == CursorKind.DECL_STMT:
        for child in stmt_node.get_children():
            # child is typically VAR_DECL
            for grand in child.get_children():
                uses.update(_find_uses_recursive(grand, stop_at_def=False))

    elif stmt_node.kind == CursorKind.VAR_DECL:
        for child in stmt_node.get_children():
            uses.update(_find_uses_recursive(child, stop_at_def=False))

    elif stmt_node.kind == CursorKind.BINARY_OPERATOR:
        children = list(stmt_node.get_children())
        if len(children) == 2:
            uses.update(_find_uses_recursive(children[1], stop_at_def=False))

    else:
        uses.update(_find_uses_recursive(stmt_node, stop_at_def=False))

    return uses


def get_defined_vars(stmt_node):
    """
    Return all variables *defined* (written to) in a statement.
    Handles DECL_STMT, VAR_DECL, BINARY_OPERATOR, COMPOUND_ASSIGNMENT_OPERATOR.
    """
    defs = set()

    if stmt_node.kind == CursorKind.DECL_STMT:
        for child in stmt_node.get_children():
            if child.kind == CursorKind.VAR_DECL:
                if child.spelling:
                    defs.add(child.spelling)
                else:
                    # try to find DECL_REF_EXPR child spelling
                    for gc in child.get_children():
                        k, s = _find_decl_ref_or_literal(gc)
                        if k == CursorKind.DECL_REF_EXPR and s:
                            defs.add(s)

    elif stmt_node.kind == CursorKind.VAR_DECL:
        if stmt_node.spelling:
            defs.add(stmt_node.spelling)

    elif stmt_node.kind == CursorKind.BINARY_OPERATOR:
        children = list(stmt_node.get_children())
        if children:
            lhs = children[0]
            # lhs may be wrapped; find decl_ref inside it
            k, s = _find_decl_ref_or_literal(lhs)
            if k == CursorKind.DECL_REF_EXPR and s:
                defs.add(s)

    # Note: compound assignment operator handling may need extension depending on AST flavor
    return defs
