import streamlit as st
import time
import pandas as pd
import networkx as nx
from pyvis.network import Network
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest

# -------------------------------------------------------------------
# INITIAL SETUP
# -------------------------------------------------------------------

st.set_page_config(page_title="TechNova Security System", layout="wide")

BRANCHES = ["Mumbai-HQ", "Bengaluru", "Hyderabad", "Pune-DR"]

FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# Central logs stored in session
if "logs" not in st.session_state:
    st.session_state.logs = []


# -------------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------------

def add_log(src, dst, size, action, status):
    st.session_state.logs.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "src": src,
        "dst": dst,
        "size_bytes": size,
        "action": action,
        "status": status
    })

def encrypt_message(msg: str) -> bytes:
    return fernet.encrypt(msg.encode())

def decrypt_message(token: bytes) -> str:
    return fernet.decrypt(token).decode()

def get_logs_df():
    if not st.session_state.logs:
        return pd.DataFrame(columns=["timestamp","src","dst","size_bytes","action","status"])
    return pd.DataFrame(st.session_state.logs)

def run_anomaly_detection():
    df = get_logs_df()
    if df.empty:
        return pd.DataFrame(), "No logs available."

    df["action_code"] = df["action"].astype("category").cat.codes

    if len(df) < 5:
        return pd.DataFrame(), "Not enough logs for model."

    model = IsolationForest(contamination=0.15, random_state=42)
    df["anomaly"] = model.fit_predict(df[["size_bytes","action_code"]])
    anomalies = df[df["anomaly"] == -1]

    return anomalies, f"Anomalies found: {len(anomalies)}"

def simulate_attack(target, pps=50, duration=3):
    count = 0
    for _ in range(pps * duration):
        add_log("Attacker", target, 64, "flood_packet", "suspicious")
        count += 1
    return count


# -------------------------------------------------------------------
# NETWORK GRAPH GENERATOR
# -------------------------------------------------------------------

def generate_network_graph():

    df = get_logs_df()
    G = nx.DiGraph()

    # Add branch nodes
    for b in BRANCHES:
        G.add_node(b)

    # Build edges from logs
    for _, row in df.iterrows():
        src = row["src"]
        dst = row["dst"]

        # skip attacker self-nodes
        if src == "Attacker":
            G.add_node("Attacker")
        
        # Weight edges by number of messages
        if G.has_edge(src, dst):
            G[src][dst]["weight"] += 1
        else:
            G.add_edge(src, dst, weight=1)

    # PyVis graph
    net = Network(
        height="600px",
        width="100%",
        directed=True,
        bgcolor="#111111",
        font_color="white"
    )

    net.barnes_hut()

    # Add nodes visually
    for node in G.nodes():
        color = "#00c3ff" if node in BRANCHES else "#ff4444"
        net.add_node(node, label=node, color=color)

    # Add edges visually
    for src, dst, data in G.edges(data=True):
        width = min(data["weight"] * 0.8, 8)
        color = "#4fd1c5"  # aqua
        if src == "Attacker":
            color = "#ff4444"
        net.add_edge(src, dst, value=data["weight"], color=color, width=width)

    net.save_graph("network_graph.html")

    # Load HTML into Streamlit
    with open("network_graph.html", "r", encoding="utf-8") as f:
        html = f.read()

    return html


# -------------------------------------------------------------------
# STREAMLIT UI
# -------------------------------------------------------------------

st.title("🔐 TechNova — Data Security Simulation (with Live Network Graph)")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📤 Encrypted Transfer",
    "📊 SOC Logs",
    "🤖 AI Threat Analysis",
    "⚠️ Attack Simulation",
    "🌐 Live Network Graph"
])


# -------------------------------------------------------------------
# TAB 1: ENCRYPTED TRANSFER
# -------------------------------------------------------------------
with tab1:
    st.subheader("📤 Send Encrypted Data")

    col1, col2 = st.columns(2)
    src = col1.selectbox("Source Branch", BRANCHES)
    dst = col2.selectbox("Destination Branch", BRANCHES)

    message = st.text_area("Message", "Confidential payroll - FY 2025")

    if st.button("Encrypt & Send"):
        token = encrypt_message(message)
        size = len(token)

        add_log(src, dst, size, "encrypted_transfer", "success")

        st.success("Encrypted data sent successfully!")
        st.code(token.decode())

    st.info("Using AES-128 style encryption via Fernet (AES-CBC + HMAC).")


# -------------------------------------------------------------------
# TAB 2: VIEW LOGS
# -------------------------------------------------------------------
with tab2:
    st.subheader("📊 Security Operations Center Logs")

    df = get_logs_df()
    st.dataframe(df, height=500, use_container_width=True)

    if st.button("Clear Logs"):
        st.session_state.logs = []
        st.warning("Logs cleared.")


# -------------------------------------------------------------------
# TAB 3: AI ANALYSIS
# -------------------------------------------------------------------
with tab3:
    st.subheader("🤖 AI-Powered Threat Detection")

    anomalies, msg = run_anomaly_detection()
    st.info(msg)

    if not anomalies.empty:
        st.error("⚠️ Anomalies Found!")
        st.dataframe(anomalies, height=400, use_container_width=True)
    else:
        st.success("No suspicious activity detected.")


# -------------------------------------------------------------------
# TAB 4: ATTACK SIMULATION
# -------------------------------------------------------------------
with tab4:
    st.subheader("⚠️ Simulate a DoS Attack")

    target = st.selectbox("Target Branch", BRANCHES)
    pps = st.slider("Packets per second", 10, 200, 50)
    duration = st.slider("Duration (seconds)", 1, 10, 3)

    if st.button("Launch Attack 🚨"):
        count = simulate_attack(target, pps, duration)
        st.error(f"{count} malicious packets generated (simulated)!")


# -------------------------------------------------------------------
# TAB 5: LIVE NETWORK GRAPH
# -------------------------------------------------------------------
with tab5:
    st.subheader("🌐 Real-Time Network Graph")

    html = generate_network_graph()
    st.components.v1.html(html, height=600, scrolling=True)

    st.caption("Graph updates on every message/attack to show live traffic patterns.")
