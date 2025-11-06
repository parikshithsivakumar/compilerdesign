# analyzer/optimization/liveness.py

from .dataflow import DataFlowAnalysis
from .utils import get_defined_vars, get_used_vars # UPDATED
from clang.cindex import CursorKind


class LivenessAnalysis(DataFlowAnalysis):
    """
    Implements Liveness Analysis, a backward data flow analysis.
    "A variable is 'live' at a point if its value will be read in the future."
    """
    def __init__(self, cfg):
        super().__init__(cfg, max_iterations=100, debug=False)
        self.direction = "backward"
        self.gen = {} # GEN[b] = set of vars used in 'b' *before* being defined
        self.kill = {} # KILL[b] = set of vars defined in 'b'
        
        self._compute_gen_kill()

    def _compute_gen_kill(self):
        """Pre-compute GEN and KILL sets for all blocks."""
        for block in self.cfg.blocks.values():
            gen_b = set()
            kill_b = set()
            
            # Iterate statements *backward* for liveness
            for stmt in reversed(block.statements):
                uses = get_used_vars(stmt) # UPDATED
                defs = get_defined_vars(stmt) # UPDATED
                
                # A var is "generated" if it's used *before* being killed
                gen_b.update(uses - kill_b)
                # A var is "killed" if it's defined
                kill_b.update(defs)
            
            self.gen[block.id] = gen_b
            self.kill[block.id] = kill_b

    def meet_operator(self, sets_to_meet):
        """Meet op for liveness is set union."""
        result = set()
        for s in sets_to_meet:
            result.update(s)
        return result

    def transfer_function(self, block, out_set):
        """IN[b] = (OUT[b] - KILL[b]) | GEN[b]"""
        gen_b = self.gen[block.id]
        kill_b = self.kill[block.id]
        return (out_set - kill_b) | gen_b


def find_dead_code(cfg, liveness_results):
    """
    Uses Liveness results to find dead code (assignments to unused vars).
    """
    in_sets, out_sets = liveness_results
    findings = []
    
    for block in cfg.blocks.values():
        live_now = out_sets[block.id].copy()
        
        for stmt in reversed(block.statements):
            defs = get_defined_vars(stmt) # UPDATED
            uses = get_used_vars(stmt) # UPDATED
            
            is_dead = False
            dead_var = None
            
            # Check if this statement is an assignment to one var
            if len(defs) == 1:
                defined_var = list(defs)[0]
                # If the var we define is NOT in the live_now set, it's dead code!
                if defined_var not in live_now:
                    # Exception: void casts like (void)x; are not dead
                    if stmt.kind == CursorKind.CALL_EXPR and stmt.spelling == "(void)":
                         pass
                    else:
                        is_dead = True
                        dead_var = defined_var

            if is_dead and dead_var:
                findings.append({
                    "opt_type": "DEAD_CODE_ELIMINATION",
                    "suggestion": f"The assignment to '{dead_var}' is never used.",
                    "line": stmt.location.line,
                    "node": stmt
                })

            # Update live_now for the *next* statement (above this one)
            live_now.difference_update(defs)
            live_now.update(uses)
            
    return findings