class DataFlowAnalysis:
    """
    A generic, iterative data flow analysis framework (safe version).
    Provides fixed-point computation for forward/backward analyses.
    Prevents infinite loops by limiting iterations.
    """

    def __init__(self, cfg, max_iterations=100, debug=False):
        self.cfg = cfg
        self.in_sets = {block_id: set() for block_id in cfg.blocks}
        self.out_sets = {block_id: set() for block_id in cfg.blocks}
        self.direction = "forward"  # or "backward"
        self.initial_value = set()
        self.gen = {}
        self.kill = {}
        self.max_iterations = max_iterations
        self.debug = debug

    def run(self):
        """
        Runs the iterative fixed-point algorithm to compute IN/OUT sets safely.
        """
        blocks = list(self.cfg.blocks.values())
        if self.direction == "backward":
            blocks.reverse()

        # Initialize IN/OUT sets
        for block in blocks:
            if self.direction == "forward":
                self.out_sets[block.id] = self.initial_value.copy()
            else:
                self.in_sets[block.id] = self.initial_value.copy()

        changed = True
        iteration = 0

        while changed and iteration < self.max_iterations:
            changed = False
            iteration += 1
            if self.debug:
                print(f"🔁 Iteration {iteration}...")

            for block in blocks:
                if self.direction == "forward":
                    # Meet operator: IN[b] = Meet(OUT[p] for all predecessors)
                    in_set = self.meet_operator(
                        [self.out_sets[p.id] for p in block.predecessors]
                    )

                    # Transfer function: OUT[b] = f(IN[b])
                    new_out_set = self.transfer_function(block, in_set)

                    # Change detection
                    if new_out_set != self.out_sets[block.id]:
                        self.out_sets[block.id] = new_out_set.copy()
                        changed = True

                    self.in_sets[block.id] = in_set.copy()

                else:  # Backward analysis
                    # Meet operator: OUT[b] = Meet(IN[s] for all successors)
                    out_set = self.meet_operator(
                        [self.in_sets[s.id] for s in block.successors]
                    )

                    # Transfer function: IN[b] = f(OUT[b])
                    new_in_set = self.transfer_function(block, out_set)

                    # Change detection
                    if new_in_set != self.in_sets[block.id]:
                        self.in_sets[block.id] = new_in_set.copy()
                        changed = True

                    self.out_sets[block.id] = out_set.copy()

            if self.debug:
                print(f"   -> Changes detected: {changed}")

        if iteration >= self.max_iterations:
            print(f"⚠️ WARNING: DataFlow did not converge after {self.max_iterations} iterations. Stopping early.")

        return self.in_sets, self.out_sets

    # --- Methods to be overridden by subclasses ---

    def meet_operator(self, sets_to_meet):
        """Combine multiple sets (e.g., union or intersection). Must be overridden."""
        raise NotImplementedError

    def transfer_function(self, block, input_set):
        """Compute new set for this block. Must be overridden."""
        raise NotImplementedError
