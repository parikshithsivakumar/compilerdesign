import clang.cindex
import sys
import json

# --- Set your system's libclang path ---
# This path is an example and might be different on your machine.
# Common paths:
# Linux: /usr/lib/llvm-14/lib
# macOS (via brew): /opt/homebrew/opt/llvm/lib
# Windows: C:/Program Files/LLVM/bin
clang.cindex.Config.set_library_path("/usr/lib/llvm-14/lib")

# --- Lists for all bug types ---
DANGEROUS_FUNCTIONS = [
    "gets", 
    "strcpy", 
    "strcat", 
    "sprintf"
]

SECRET_KEYWORDS = [
    "pass", 
    "secret", 
    "token", 
    "key", 
    "api_key", 
    "password"
]

ALLOC_FUNCTIONS = ["malloc", "calloc", "realloc", "fopen"]
FILE_OPEN_FUNCTIONS = ["open", "creat"]

class AstToDot:
    def __init__(self):
        self.node_counter = 0
        self.dot_nodes = []
        self.dot_edges = []
        self.bugs_found = [] # This will store bug details
        self.c_code = ""
        self.consequence_nodes = set()
        self.freed_vars_by_func = {} # e.g., {"main": {"ptr1", "ptr2"}}
        self.current_function = None

    def get_unique_id(self):
        self.node_counter += 1
        return f"node{self.node_counter}"

    # --- BUG 1 ---
    def is_unused_return_bug(self, node, parent_node):
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            # --- FIX: Check if the return type is NOT void to avoid false positives ---
            if node.result_type.kind != clang.cindex.TypeKind.VOID:
                if parent_node.kind == clang.cindex.CursorKind.COMPOUND_STMT:
                    return True
        return False

    # --- BUG 2 ---
    def is_dangerous_call(self, node):
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            if node.spelling in DANGEROUS_FUNCTIONS:
                return True
        return False

    # --- BUG 3 ---
    def is_hardcoded_secret(self, node):
        if node.kind == clang.cindex.CursorKind.VAR_DECL:
            if any(kw in node.spelling.lower() for kw in SECRET_KEYWORDS):
                for child in node.get_children():
                    if child.kind == clang.cindex.CursorKind.STRING_LITERAL:
                        return True
        return False

    # --- BUG 4 ---
    def is_goto_statement(self, node):
        if node.kind == clang.cindex.CursorKind.GOTO_STMT:
            return True
        return False

    # --- BUG 5 ---
    def is_null_pointer_dereference(self, node, parent_node):
        if node.kind != clang.cindex.CursorKind.VAR_DECL:
            return False
            
        var_name = node.spelling
        initializer_call = None
        
        for child in node.get_children():
            if child.kind == clang.cindex.CursorKind.CALL_EXPR:
                if child.spelling in ALLOC_FUNCTIONS:
                    initializer_call = child
                    break
        
        if not initializer_call:
            return False
            
        parent_children = list(parent_node.get_children())
        try:
            current_node_index = [i for i, child in enumerate(parent_children) if child.hash == node.hash][0]
            if current_node_index + 1 < len(parent_children):
                next_sibling = parent_children[current_node_index + 1]
                
                # This is a basic check. A real tool would need data-flow analysis.
                if next_sibling.kind == clang.cindex.CursorKind.IF_STMT:
                    return False # Good, it's being checked.
                
                return True # Bad, it's being used or something else.
                
        except (IndexError, ValueError):
            pass
            
        return False
    
    # --- BUG 6 ---
    def is_insecure_file_permission(self, node):
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            if node.spelling in FILE_OPEN_FUNCTIONS:
                args = list(node.get_children())
                if len(args) >= 3:
                    mode_arg = args[2]
                    if mode_arg.kind == clang.cindex.CursorKind.INTEGER_LITERAL:
                        try:
                            value = next(mode_arg.get_tokens()).spelling
                            permission = int(value, 0) # '0' auto-detects octal
                            
                            # Check for "world writable" (0o2) or "group writable" (0o20)
                            if (permission & 0o002) or (permission & 0o020):
                                return True # Insecure!
                        except (StopIteration, ValueError):
                            pass
        return False

    # --- BUG 7 ---
    def check_use_after_free(self, node):
        if node.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
            if self.current_function:
                freed_set = self.freed_vars_by_func.get(self.current_function, set())
                if node.spelling in freed_set:
                    return True # Bug! This var was freed.
        return False

    def get_source_code(self, node):
        extent = node.extent
        start = extent.start.offset
        end = extent.end.offset
        return self.c_code[start:end]

    def find_bugs_and_suggestions(self, node, parent_node=None):
        if node.location.file and node.location.file.name != 'test.c':
             return
            
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            self.current_function = node.spelling
            if self.current_function not in self.freed_vars_by_func:
                self.freed_vars_by_func[self.current_function] = set()
                
        if node.hash in self.consequence_nodes:
             return

        # --- FIX: This is state-tracking and must run *before* the bug-finding logic. ---
        # It needs to be outside the main if/elif chain.
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            if node.spelling == "free" and self.current_function:
                try:
                    freed_var_node = list(node.get_children())[0]
                    freed_var_name = self.get_source_code(freed_var_node)
                    self.freed_vars_by_func[self.current_function].add(freed_var_name)
                except IndexError:
                    pass # Failed to find var name
        # --- END OF FIX ---

        bug_type = None
        consequence_node = None
        
        # --- Check for all 7 bug types ---
        
        # Check for Bug Type 2: Dangerous Function (High Priority)
        if self.is_dangerous_call(node):
            bug_type = "DANGEROUS_FUNCTION"
            
        # Check for Bug Type 1: Unused Return (Medium Priority)
        elif self.is_unused_return_bug(node, parent_node):
            bug_type = "UNUSED_RETURN"
            children_list = list(parent_node.get_children())
            try:
                current_node_index = [i for i, child in enumerate(children_list) if child.hash == node.hash][0]
                if current_node_index + 1 < len(children_list):
                    consequence_node = children_list[current_node_index+1]
                    self.consequence_nodes.add(consequence_node.hash)
            except IndexError:
                pass 

        # Check for Bug Type 3: Hardcoded Secret
        elif self.is_hardcoded_secret(node):
            bug_type = "HARDCODED_SECRET"
            
        # Check for Bug Type 4: Goto Statement
        elif self.is_goto_statement(node):
            bug_type = "GOTO_STATEMENT"

        # Check for Bug Type 5: NULL Pointer Dereference
        elif self.is_null_pointer_dereference(node, parent_node):
            bug_type = "NULL_POINTER_DEREFERENCE"

        # Check for Bug Type 6: Insecure File Permissions
        elif self.is_insecure_file_permission(node):
            bug_type = "INSECURE_FILE_PERMISSIONS"
            
        # Check for Bug Type 7: Use After Free
        elif self.check_use_after_free(node):
            bug_type = "USE_AFTER_FREE"


        if bug_type:
            bug_details = {
                "node": node,
                "bug_type": bug_type,
                "consequence_node": consequence_node,
                "source_text": self.get_source_code(node)
            }
            if bug_type == "USE_AFTER_FREE":
                if any(b["node"].hash == node.hash for b in self.bugs_found):
                    pass
                else:
                    self.bugs_found.append(bug_details)
            else:
                 self.bugs_found.append(bug_details)

        # Recurse on children
        for child in node.get_children():
            self.find_bugs_and_suggestions(child, node)


    def generate_dot_and_bugs(self, c_code: str):
        """
        Main function to generate the DOT graph and suggestions
        from a C code string.
        """
        # Reset all class state for a new run
        self.c_code = c_code
        self.node_counter = 0
        self.dot_nodes = []
        self.dot_edges = []
        self.bugs_found = []
        self.consequence_nodes = set()
        self.freed_vars_by_func = {}
        self.current_function = None
        
        index = clang.cindex.Index.create()
        tu = index.parse(
            'test.c',
            args=[],
            unsaved_files=[('test.c', c_code)],
            options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        )
        
        if not tu:
            raise RuntimeError("Error: Unable to parse the C code.")
        
        root_node = tu.cursor
        
        # PASS 1: Find all bugs
        self.find_bugs_and_suggestions(root_node, root_node)
        
        # PASS 2: Build the visual graph
        root_id = self.get_unique_id()
        root_label = f"{root_node.kind.name}\\n({root_node.spelling})"
        self.dot_nodes.append(f'{root_id} [label="{root_label}", fillcolor="lightblue"];')
        
        main_file_nodes = [c for c in root_node.get_children() if c.location.file and c.location.file.name == 'test.c']
        
        bug_hashes = {b['node'].hash for b in self.bugs_found}
        con_hashes = self.consequence_nodes
        
        def graph_walker(node, parent_id):
            if node.location.file and node.location.file.name != 'test.c':
                return
                
            node_id = self.get_unique_id()
            
            color = "lightblue"
            if node.hash in bug_hashes:
                color = "red" # All bugs are red
            elif node.hash in con_hashes:
                color = "orange" # Consequence is orange
                
            label = f"{node.kind.name}"
            if node.spelling:
                sanitized_spelling = node.spelling.replace('"', r'\"')
                label += f"\\n({sanitized_spelling})"
                
            self.dot_nodes.append(f'{node_id} [label="{label}", fillcolor="{color}"];')
            if parent_id:
                self.dot_edges.append(f'"{parent_id}" -> "{node_id}";')
                
            for child in node.get_children():
                graph_walker(child, node_id)
        
        for node in main_file_nodes:
            graph_walker(node, root_id)
        
        dot_string = "digraph G {\n"
        dot_string += "    rankdir=\"TB\";\n"
        dot_string += "    node [shape=box, style=\"filled\"];\n\n"
        dot_string += "    // Nodes\n"
        dot_string += "\n".join(self.dot_nodes)
        dot_string += "\n\n    // Edges\n"
        dot_string += "\n".join(self.dot_edges)
        dot_string += "\n}"
        
        return (dot_string, self.bugs_found)

# --- Full __main__ block for testing ---
if __name__ == "__main__":
    # Updated test code to include all 7 bug types
    test_code = """
    #include <string.h>
    #include <stdlib.h>
    #include <fcntl.h> // For open()
    
    int is_admin(int user_id) { return 0; }
    void delete_file(const char* f) {}

    void process_data(int user_id, char* input) {
        // Risk 1: Unused Return
        is_admin(user_id); 
        delete_file("system.db");

        // Risk 2: Dangerous Function
        char buffer[100];
        strcpy(buffer, input); 
        
        // Risk 3: Hardcoded Secret
        char *api_key = "sk_live_12345";
        
        // Risk 5: NULL Pointer Dereference
        char *data = (char*)malloc(1024);
        data[0] = 'A'; // Bug, no check
        
        // Risk 6: Insecure File Permissions
        int fd = open("logfile.txt", 1, 0777);
        
        // Risk 7: Use After Free
        free(data);
        data[1] = 'B'; // Bug, use after free
        
        // Risk 4: Goto Statement
        if (user_id < 0) {
            goto error_handler; 
        }
        
    error_handler:
        return;
    }
    """
    
    print("--- Generating DOT and Bugs for Test Code ---")
    try:
        converter = AstToDot()
        dot_output, bugs_output = converter.generate_dot_and_bugs(test_code)
        
        print("\n--- DOT Output ---")
        print(dot_output)
        
        print("\n--- Bugs Output ---")
        # We use a custom function to print bugs, as the nodes can't be JSONed
        bugs_as_dict = [
            {
                "bug_type": b['bug_type'], 
                "source_text": b['source_text'],
                "line": b['node'].location.line
            } for b in bugs_output
        ]
        print(json.dumps(bugs_as_dict, indent=2))
        
        print(f"\n--- Total Bugs Found: {len(bugs_as_dict)} ---")
        
    except Exception as e:
        print(f"An error occurred: {e}")
        print("\nNOTE: Did you set the correct libclang path at the top of the file?")
        print("      clang.cindex.Config.set_library_path(...)")