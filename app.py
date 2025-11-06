import streamlit as st
import graphviz
from ast_to_dot import AstToDot
import traceback
import os
from openai import AzureOpenAI
from dotenv import load_dotenv

# --- Load all variables from .env file ---
load_dotenv()

# --- Our fix from before (still important) ---
os.environ["PATH"] += os.pathsep + '/usr/bin'

# --- Read keys securely from Environment (now loaded from .env) ---
api_key = os.environ.get("AZURE_API_KEY")
api_endpoint = os.environ.get("AZURE_API_ENDPOINT")
deployment_name = os.environ.get("AZURE_DEPLOYMENT_NAME")

# 1. --- Configuration & Modern UI Setup ---
st.set_page_config(
    layout="wide",
    page_title="Visual Security Auditor",
    page_icon="🕵️"
)

# --- CUSTOM CSS FOR "MIDNIGHT SLATE" THEME ---
st.markdown("""
<style>
    /* Main app layout */
    .block-container {
        padding: 2rem;
    }

    /* Style for each bug "card" */
    .bug-card {
        background-color: #1F2937; /* Modern dark-slate gray */
        border: 1px solid #374151; /* Lighter gray border */
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
        transition: border 0.3s ease, box-shadow 0.3s ease;
    }
    
    .bug-card:hover {
        border: 1px solid #6366F1; /* Indigo accent on hover */
        box-shadow: 0 6px 16px rgba(0, 0, 0, 0.6);
    }

    /* Header inside the card */
    .bug-header {
        font-size: 1.25rem;
        font-weight: 600;
        color: #E5E7EB; /* Off-white */
        margin-bottom: 0.5rem;
    }
    
    /* Sub-header for line number */
    .bug-location {
        font-size: 0.9rem;
        color: #9CA3AF; /* Softer gray */
        margin-bottom: 1rem;
        font-family: 'monospace';
    }
    
    /* Header for the GPT-4 analysis (inside expander) */
    .gpt-header {
        font-size: 1.1rem;
        font-weight: 600;
        color: #A78BFA; /* Light violet accent */
        margin-bottom: 0.5rem;
        padding-top: 0.5rem;
    }
    
    /* Improve spacing for code blocks within cards */
    .bug-card .stCodeBlock {
        margin: 0.5rem 0;
    }
    
    /* Style tabs */
    .stTabs [data-baseweb="tab"] {
        font-size: 1.1rem;
        font-weight: 500;
    }
    
    /* Style the expander button */
    .bug-card .stExpander > summary {
        background-color: transparent !important;
        font-weight: 600;
        color: #A78BFA; /* Light violet */
        border: 1px solid #4B5563;
        border-radius: 8px;
        margin-top: 1rem;
    }
    
    .bug-card .stExpander > summary:hover {
        background-color: #374151 !important;
    }

</style>
""", unsafe_allow_html=True)


st.title("Intelligent Visual Security Auditor 🕵️")
st.caption("A modern, GPT-4 powered tool to analyze C code for potential vulnerabilities.")
st.divider()

# --- Initialize the Azure client ---
client = None
if api_endpoint and api_key and deployment_name:
    try:
        client = AzureOpenAI(
            api_key=api_key,
            api_version="2024-02-01",
            azure_endpoint=api_endpoint
        )
        st.sidebar.success("Azure Client Configured!")
    except Exception as e:
        st.sidebar.error(f"Error configuring client: {e}")
else:
    st.sidebar.error("Azure credentials not found.")
    st.warning("Azure credentials not found. Did you create your .env file?")

# --- Initialize the converter ---
@st.cache_resource
def get_converter():
    return AstToDot()

converter = get_converter()

# --- Azure OpenAI Call Function (No changes needed) ---
@st.cache_data
def get_azure_openai_suggestion(bug_type, bug_code, func_name):
    # 1. --- SIMPLE FILTER ---
    if func_name in ["printf", "puts", "log_message"]:
        print(f"Skipping API call for noise function: {func_name}")
        return None 
    
    # 2. --- Build the Prompt ---
    system_prompt = """
    You are an expert C code security auditor.
    A static analysis tool has flagged a line of code.
    For the user's request, provide a concise, expert analysis:
    1.  **The Risk:** Briefly explain what this security risk means.
    2.  **The Fix:** Provide a corrected, safer code snippet (if possible).
    3.  **Explanation:** Briefly explain *why* the new code is safer or what to do.
    Keep your entire response in Markdown format.
    """
    
    user_prompt = f"""
    The tool flagged this line:
    ```c
    {bug_code}
    ```
    It classified this risk as: "{bug_type}"
    """
    
    # 3. --- Call the API ---
    if not client:
        return "Error: Azure client is not configured. Check credentials."
        
    try:
        response = client.chat.completions.create(
            model=deployment_name, 
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error calling Azure OpenAI: {e}"

# --- Initialize Session State ---
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None

# 2. --- UI Layout ---
col1, col2 = st.columns([1, 1.2], gap="large") 

# --- Column 1: Code Input ---
with col1:
    st.header("C Code Editor")
    
    c_code = st.text_area("Paste your C code below:", height=800, value="""
#include <string.h>
#include <stdlib.h>
#include <fcntl.h> // For open()

// Forward declarations
int is_admin(int user_id);
void delete_file(const char* f);

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
    int fd = open("logfile.txt", 1, 0777); // O_CREAT=1, 0777=insecure
    
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
""")
    
    # --- Submit and Edit Buttons ---
    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        submit_button = st.button(
            "Submit Analysis", 
            use_container_width=True, 
            type="primary"
        )
    with btn_col2:
        edit_button = st.button(
            "Clear & Edit New", 
            use_container_width=True
        )

# --- Column 2: Analysis & Visualization ---
with col2:
    st.header("Analysis & Visualization")
    
    # --- State Management Logic ---
    if submit_button:
        try:
            with st.spinner("Parsing C code and generating AST..."):
                dot_code, bugs_found = converter.generate_dot_and_bugs(c_code)
            
            # Store results in session state
            st.session_state.analysis_results = {
                "dot_code": dot_code,
                "bugs_found": bugs_found
            }
        except Exception as parse_error:
            st.session_state.analysis_results = None # Clear on error
            st.error(f"Error parsing C code: {parse_error}")
            st.code(traceback.format_exc())

    if edit_button:
        st.session_state.analysis_results = None
        st.rerun() # Rerun to clear the UI

    # --- Display Logic (Conditional) ---
    if st.session_state.analysis_results:
        # Load results from state
        dot_code = st.session_state.analysis_results["dot_code"]
        bugs_found = st.session_state.analysis_results["bugs_found"]
        
        # --- Create the TABS ---
        tab1, tab2 = st.tabs(["🔒 Security Analysis", "🌳 Visual AST"])
        
        # --- Tab 1: Security Analysis ---
        with tab1:
            st.metric(label="Potential Risks Found", value=f"🔴 {len(bugs_found)}")
            st.divider()

            if not client:
                st.warning("Azure client is not configured. GPT-4 analysis is disabled.")
            
            if bugs_found:
                for i, bug in enumerate(bugs_found):
                    # --- Create a "Card" for each bug ---
                    st.markdown('<div class="bug-card">', unsafe_allow_html=True)
                    
                    st.markdown(f'<div class="bug-header">Risk #{i+1}: {bug["bug_type"]}</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="bug-location">Found on line {bug["node"].location.line}</div>', unsafe_allow_html=True)
                    
                    st.code(bug['source_text'], language="c")
                    
                    # --- NEW: Use st.expander to show/hide the analysis ---
                    if client:
                        with st.expander("👁️ View GPT-4 Fix"):
                            with st.spinner(f"Asking GPT-4 about '{bug['source_text']}'..."):
                                suggestion = get_azure_openai_suggestion(
                                    bug_type=bug['bug_type'],
                                    bug_code=bug['source_text'],
                                    func_name=bug['node'].spelling
                                )
                            
                            if suggestion:
                                st.markdown(f'<div class="gpt-header">GPT-4\'s Analysis:</div>', unsafe_allow_html=True)
                                st.markdown(suggestion)
                            else:
                                st.info("This issue was classified as 'Noise' and skipped.")
                    
                    st.markdown('</div>', unsafe_allow_html=True) # Close the card div
            else:
                st.success("🎉 No potential risks found in the code!")

        # --- Tab 2: Abstract Syntax Tree ---
        with tab2:
            st.subheader("Rendered Graph")
            if dot_code:
                try:
                    graph = graphviz.Source(dot_code)
                    svg_data = graph.pipe(format='svg')
                    st.image(svg_data.decode('utf-8'))
                    
                    with st.expander("Show DOT source code"):
                        st.code(dot_code, language="dot")
                        
                except Exception as render_error:
                    st.error(f"Graphviz Render Error: {render_error}")
            else:
                st.info("No AST to display.")
                
    else:
        # Default view before submission
        st.info("Paste your C code in the editor and click 'Submit Analysis' to begin.")