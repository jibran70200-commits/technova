import streamlit as st
import time
import pandas as pd
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest

# -------------------------------------------------------------------
# INITIAL SETUP
# -------------------------------------------------------------------

st.set_page_config(page_title="TechNova Security Simulation", layout="wide")

# Branches
BRANCHES = ["Mumbai-HQ", "Bengaluru", "Hyderabad", "Pune-DR"]

# Encryption (AES simulation using Fernet = AES128 + HMAC)
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# Central logs
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

    # Encode actions numerically
    df["action_code"] = df["action"].astype("category").cat.codes

    if len(df) < 5:
        return pd.DataFrame(), "Not enough logs for model."

    try:
        model = IsolationForest(contamination=0.15, random_state=42)
        df["anomaly"] = model.fit_predict(df[["size_bytes", "action_code"]])
        anomalies = df[df["anomaly"] == -1]
        return anomalies, f"Anomalies found: {len(anomalies)}"
    except:
        return pd.DataFrame(), "AI analysis failed — insufficient data."

def simulate_attack(target, pps=50, duration=3):
    count = 0
    for _ in range(pps * duration):
        add_log("Attacker", target, 64, "flood_packet", "suspicious")
        count += 1
    return count


# -------------------------------------------------------------------
# STREAMLIT UI
# -------------------------------------------------------------------

st.title("🔐 TechNova — Branch-to-Branch Data Security Simulation")

tab1, tab2, tab3, tab4 = st.tabs(["📤 Encrypted Transfer", "📊 SOC Logs", "🤖 AI Threat Analysis", "⚠️ Attack Simulation"])


# -------------------------------------------------------------------
# TAB 1: ENCRYPTED TRANSFER
# -------------------------------------------------------------------
with tab1:
    st.subheader("📤 Send Encrypted Message Between Branches")

    col1, col2 = st.columns(2)
    with col1:
        src = st.selectbox("Source Branch", BRANCHES)
    with col2:
        dst = st.selectbox("Destination Branch", BRANCHES)

    message = st.text_area("Enter message", "Confidential payroll file FY-2025")

    if st.button("Encrypt & Send", use_container_width=True):
        token = encrypt_message(message)
        size = len(token)

        add_log(src, dst, size, "encrypted_transfer", "success")

        st.success("Encrypted transfer sent successfully!")
        st.code(token.decode())

    st.info("AES-style encryption is simulated using Fernet (AES128 + HMAC).")


# -------------------------------------------------------------------
# TAB 2: VIEW LOGS
# -------------------------------------------------------------------
with tab2:
    st.subheader("📊 Central SOC Logs")

    df = get_logs_df()
    st.dataframe(df, use_container_width=True, height=500)

    if st.button("Clear Logs ❌", use_container_width=True):
        st.session_state.logs = []
        st.warning("All logs cleared.")


# -------------------------------------------------------------------
# TAB 3: AI ANOMALY DETECTION
# -------------------------------------------------------------------
with tab3:
    st.subheader("🤖 AI-Based Threat Analysis")

    anomalies, msg = run_anomaly_detection()
    st.info(msg)

    if not anomalies.empty:
        st.error("⚠️ Threats Detected in Network Traffic")
        st.dataframe(anomalies, use_container_width=True)
    else:
        st.success("No anomalies detected.")


# -------------------------------------------------------------------
# TAB 4: ATTACK SIMULATION
# -------------------------------------------------------------------
with tab4:
    st.subheader("⚠️ Simulate Flood / DoS Attack")

    target = st.selectbox("Target Branch", BRANCHES)
    pps = st.slider("Packets per second", 10, 200, 60)
    duration = st.slider("Attack Duration (seconds)", 1, 10, 4)

    if st.button("Launch Attack 🚨", use_container_width=True):
        count = simulate_attack(target, pps, duration)
        st.error(f"Attack simulated! {count} malicious packets added to logs.")

    st.caption("Use this to test anomaly detection system.")
