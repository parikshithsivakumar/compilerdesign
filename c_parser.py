import clang.cindex
import sys

# Tell libclang where to find the C library (if it can't)
# We are now using Python clang 14, so we point to the LLVM 14 library path
clang.cindex.Config.set_library_path("/usr/lib/llvm-14/lib")

# This is our sample C code, just for testing
TEST_C_CODE = """
void delete_critical_file(int user_id) {
    if (user_id == 1) {
        is_admin(user_id);
        delete_file("system.db");
    }
}
"""

def walk_ast(node, depth=0):
    """
    This is a recursive function that "walks" down the AST
    and prints out the kind and name of each node.
    """
    
    # Indent based on depth in the tree
    indent = "  " * depth
    
    # Print the node's "kind" (e.g., FUNCTION_DECL) 
    # and "spelling" (e.g., the function name)
    print(f"{indent}{node.kind.name}: {node.spelling}")

    # --- This is the key part ---
    # Recursively call this function on all children of the current node
    for child in node.get_children():
        walk_ast(child, depth + 1)

def main():
    print("--- Starting C Code AST Walk ---.")
    
    # 1. Create a clang "index"
    # This is the entry point to the libclang library
    index = clang.cindex.Index.create()
    
    # 2. Parse the C code
    # We create a "translation unit" from our code string.
    # "from_buffer" is used because we're using a string, not a real file.
    tu = index.parse(
        'test.c',  # A "fake" file name
        args=[], 
        unsaved_files=[('test.c', TEST_C_CODE)],
        options=0
    )
    
    if not tu:
        print("Error: Unable to parse the C code.")
        return

    # 3. Walk the AST
    # "tu.cursor" is the root node of the AST
    walk_ast(tu.cursor)
    
    print("--- Finished AST Walk ---")

if __name__ == "__main__":
    main()