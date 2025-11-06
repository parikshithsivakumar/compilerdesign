# analyzer/optimization/cfg.py

import clang.cindex
from clang.cindex import CursorKind

clang.cindex.Config.set_library_path("/usr/lib/llvm-14/lib")


class BasicBlock:
    def __init__(self, block_id, function_name):
        self.id = block_id
        self.function_name = function_name
        self.statements = []
        self.predecessors = set()
        self.successors = set()

    def __repr__(self):
        return f"Block(id={self.id})"

    def add_statement(self, node):
        self.statements.append(node)


class ControlFlowGraph:
    def __init__(self, function_name):
        self.function_name = function_name
        self.blocks = {}
        self.entry_block = None
        self.exit_block = None
        self._block_counter = 0

    def create_block(self):
        block_id = f"{self.function_name}_B{self._block_counter}"
        self._block_counter += 1
        block = BasicBlock(block_id, self.function_name)
        self.blocks[block_id] = block
        return block

    def link_blocks(self, from_block, to_block):
        if from_block and to_block and from_block is not to_block:
            from_block.successors.add(to_block)
            to_block.predecessors.add(from_block)

    def __str__(self):
        lines = [f"CFG for {self.function_name}:"]
        for bid, block in self.blocks.items():
            preds = [p.id for p in block.predecessors]
            succs = [s.id for s in block.successors]
            lines.append(
                f"  {bid}: preds={preds}, succs={succs}, stmts={len(block.statements)}"
            )
        return "\n".join(lines)


class CFGBuilder:
    def __init__(self, c_code):
        self.c_code = c_code
        self.cfgs = {}
        self.current_cfg = None
        self.label_map = {}
        self.loop_stack = []
        self.switch_stack = []

    def build_cfgs(self, tu_root):
        for node in tu_root.get_children():
            if node.location.file and node.location.file.name != "test.c":
                continue

            if node.kind == CursorKind.FUNCTION_DECL and node.is_definition():
                self.build_function_cfg(node)

        return self.cfgs

    def build_function_cfg(self, func_node):
        func_name = func_node.spelling
        cfg = ControlFlowGraph(func_name)
        self.current_cfg = cfg

        cfg.entry_block = cfg.create_block()
        cfg.exit_block = cfg.create_block()

        # Locate function body
        func_body = None
        for child in func_node.get_children():
            if child.kind == CursorKind.COMPOUND_STMT:
                func_body = child
                break

        if func_body is None:
            print(f"⚠️ Skipping {func_name}: no body found.")
            self.cfgs[func_name] = cfg
            self.current_cfg = None
            return

        self._find_labels(func_body)
        end_block = self._process_statements(func_body.get_children(), cfg.entry_block)

        if end_block and not end_block.successors:
            self.current_cfg.link_blocks(end_block, cfg.exit_block)

        self._cleanup_unreachable_blocks(cfg)

        print(f"\n--- CFG Dump for function '{func_name}' ---")
        for bid, block in cfg.blocks.items():
            print(f"Block {bid}: {len(block.statements)} statements")
            for stmt in block.statements:
                print(f"   {stmt.kind.name:25s} | spelling='{stmt.spelling}'")
        print("--- END CFG ---\n")

        self.cfgs[func_name] = cfg
        self.current_cfg = None

    def _find_labels(self, node):
        for child in node.get_children():
            if child.kind == CursorKind.LABEL_STMT:
                self.label_map[child.spelling] = self.current_cfg.create_block()
            elif child.kind == CursorKind.SWITCH_STMT:
                for case_label in child.get_children():
                    if case_label.kind in [CursorKind.CASE_STMT, CursorKind.DEFAULT_STMT]:
                        self.label_map[case_label.hash] = self.current_cfg.create_block()
            if child.kind != CursorKind.FUNCTION_DECL:
                self._find_labels(child)

    def _flatten_statement(self, stmt):
        """
        Extract nested statements like:
            DECL_STMT -> VAR_DECL -> BINARY_OPERATOR
        Returns a list including the statement itself and any nested expressions.
        """
        flat = [stmt]
        for child in stmt.get_children():
            flat.extend(self._flatten_statement(child))
        return flat

    def _process_statements(self, statements_iter, current_block):
        statements = list(statements_iter)
        for stmt in statements:
            if stmt.hash in self.label_map:
                label_block = self.label_map[stmt.hash]
                self.current_cfg.link_blocks(current_block, label_block)
                current_block = label_block

            # --- Control Flow ---
            if stmt.kind == CursorKind.IF_STMT:
                current_block = self._handle_if_stmt(stmt, current_block)
            elif stmt.kind == CursorKind.FOR_STMT:
                current_block = self._handle_for_stmt(stmt, current_block)
            elif stmt.kind == CursorKind.WHILE_STMT:
                current_block = self._handle_while_stmt(stmt, current_block)
            elif stmt.kind == CursorKind.DO_STMT:
                current_block = self._handle_do_stmt(stmt, current_block)
            elif stmt.kind == CursorKind.SWITCH_STMT:
                current_block = self._handle_switch_stmt(stmt, current_block)
            elif stmt.kind in [
                CursorKind.RETURN_STMT,
                CursorKind.BREAK_STMT,
                CursorKind.CONTINUE_STMT,
                CursorKind.GOTO_STMT,
            ]:
                current_block.add_statement(stmt)
            else:
                # ✅ Add flattened internal statements (fix)
                for sub_stmt in self._flatten_statement(stmt):
                    if sub_stmt.kind not in [
                        CursorKind.COMPOUND_STMT,
                        CursorKind.LABEL_STMT,
                        CursorKind.CASE_STMT,
                        CursorKind.DEFAULT_STMT,
                    ]:
                        current_block.add_statement(sub_stmt)
        return current_block

    # === Control structures remain unchanged ===
    def _handle_if_stmt(self, stmt, current_block):
        children = list(stmt.get_children())
        cond = children[0]
        then_body = children[1]
        else_body = children[2] if len(children) > 2 else None
        current_block.add_statement(cond)
        then_block = self.current_cfg.create_block()
        merge_block = self.current_cfg.create_block()
        else_block = merge_block if not else_body else self.current_cfg.create_block()
        self.current_cfg.link_blocks(current_block, then_block)
        self.current_cfg.link_blocks(current_block, else_block)
        then_end = self._process_statements(then_body.get_children(), then_block)
        if then_end and not then_end.successors:
            self.current_cfg.link_blocks(then_end, merge_block)
        if else_body:
            else_end = self._process_statements(else_body.get_children(), else_block)
            if else_end and not else_end.successors:
                self.current_cfg.link_blocks(else_end, merge_block)
        return merge_block

    def _handle_for_stmt(self, stmt, current_block):
        children = list(stmt.get_children())
        init, cond, inc, body = children
        cond_block = self.current_cfg.create_block()
        body_block = self.current_cfg.create_block()
        inc_block = self.current_cfg.create_block()
        merge_block = self.current_cfg.create_block()
        self.loop_stack.append((inc_block, merge_block))
        current_block.add_statement(init)
        self.current_cfg.link_blocks(current_block, cond_block)
        cond_block.add_statement(cond)
        self.current_cfg.link_blocks(cond_block, body_block)
        self.current_cfg.link_blocks(cond_block, merge_block)
        body_end = self._process_statements(body.get_children(), body_block)
        if body_end and not body_end.successors:
            self.current_cfg.link_blocks(body_end, inc_block)
        inc_block.add_statement(inc)
        self.current_cfg.link_blocks(inc_block, cond_block)
        self.loop_stack.pop()
        return merge_block

    def _handle_while_stmt(self, stmt, current_block):
        children = list(stmt.get_children())
        cond, body = children
        cond_block = self.current_cfg.create_block()
        body_block = self.current_cfg.create_block()
        merge_block = self.current_cfg.create_block()
        self.loop_stack.append((cond_block, merge_block))
        self.current_cfg.link_blocks(current_block, cond_block)
        cond_block.add_statement(cond)
        self.current_cfg.link_blocks(cond_block, body_block)
        self.current_cfg.link_blocks(cond_block, merge_block)
        body_end = self._process_statements(body.get_children(), body_block)
        if body_end and not body_end.successors:
            self.current_cfg.link_blocks(body_end, cond_block)
        self.loop_stack.pop()
        return merge_block

    def _handle_do_stmt(self, stmt, current_block):
        children = list(stmt.get_children())
        body, cond = children
        body_block = self.current_cfg.create_block()
        cond_block = self.current_cfg.create_block()
        merge_block = self.current_cfg.create_block()
        self.loop_stack.append((cond_block, merge_block))
        self.current_cfg.link_blocks(current_block, body_block)
        body_end = self._process_statements(body.get_children(), body_block)
        if body_end and not body_end.successors:
            self.current_cfg.link_blocks(body_end, cond_block)
        cond_block.add_statement(cond)
        self.current_cfg.link_blocks(cond_block, body_block)
        self.current_cfg.link_blocks(cond_block, merge_block)
        self.loop_stack.pop()
        return merge_block

    def _handle_switch_stmt(self, stmt, current_block):
        children = list(stmt.get_children())
        cond = children[0]
        body = children[1]
        current_block.add_statement(cond)
        merge_block = self.current_cfg.create_block()
        self.switch_stack.append((current_block, merge_block))
        default_block = None
        for case_label in body.get_children():
            if case_label.kind == CursorKind.CASE_STMT:
                target = self.label_map[case_label.hash]
                self.current_cfg.link_blocks(current_block, target)
            elif case_label.kind == CursorKind.DEFAULT_STMT:
                default_block = self.label_map[case_label.hash]
                self.current_cfg.link_blocks(current_block, default_block)
        if not default_block:
            self.current_cfg.link_blocks(current_block, merge_block)
        end_block = self._process_statements(body.get_children(), current_block)
        if end_block and not end_block.successors:
            self.current_cfg.link_blocks(end_block, merge_block)
        self.switch_stack.pop()
        return merge_block

    def _cleanup_unreachable_blocks(self, cfg):
        reachable = set()

        def dfs(block):
            if block in reachable:
                return
            reachable.add(block)
            for succ in block.successors:
                dfs(succ)

        if cfg.entry_block:
            dfs(cfg.entry_block)

        all_blocks = dict(cfg.blocks)
        for bid, block in all_blocks.items():
            if block not in reachable:
                del cfg.blocks[bid]

        remaining = set(cfg.blocks.values())
        for block in cfg.blocks.values():
            block.predecessors = {p for p in block.predecessors if p in remaining}
            block.successors = {s for s in block.successors if s in remaining}
