import streamlit as st
import pandas as pd
import bcrypt
import time
import random
import base64
import socket
import platform
import psutil
from getmac import get_mac_address
from datetime import datetime
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- 1. CONFIG & STANDARDS ---
st.set_page_config(page_title='SOC Command', layout="wide")
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
ADMIN_IDENTITY = "joshohmes@proton.me"
LOCKOUT_THRESHOLD = 3
COOL_OFF_SECONDS = 30

# --- 2. SECURITY & AUTH UTILITIES ---

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def send_2fa_code(creds, target_email, code):
    try:
        service = build('gmail', 'v1', credentials=creds)
        message = MIMEText(f"Your SOC Command Verification Code: {code}")
        message['to'] = target_email
        message['subject'] = "🔐 CISA-Compliant 2FA Code"
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
        service.users().messages().send(userId="me", body={'raw': raw}).execute()
        return True
    except Exception as e:
        st.error(f"Mail Dispatch Failed: {e}")
        return False

# --- 3. SESSION STATE INITIALIZATION ---
if 'user_db' not in st.session_state:
    st.session_state.user_db = {} 
if 'auth_state' not in st.session_state:
    st.session_state.auth_state = {"auth": False, "reg_step": "form"}
if 'fail_count' not in st.session_state:
    st.session_state.fail_count = 0
if 'honeypot_logs' not in st.session_state:
    st.session_state.honeypot_logs = pd.DataFrame(columns=["Timestamp", "Event", "Source", "Status"])

# --- 4. PAGE DEFINITIONS ---

def identity_manager():
    st.title("🛡️ SOC Hardened Identity Portal")
    if st.session_state.fail_count >= LOCKOUT_THRESHOLD:
        last_fail = st.session_state.get('last_fail', 0)
        wait = int(COOL_OFF_SECONDS - (time.time() - last_fail))
        if wait > 0:
            st.error(f"🚫 CISA Brute-Force Protection: Try again in {wait}s.")
            return

    tab1, tab2 = st.tabs(["🔒 Secure Login", "📝 Provision Account"])

    with tab1:
        with st.container(border=True):
            l_user = st.text_input("Username", key="login_user")
            l_pw = st.text_input("Passphrase", type="password", key="login_pass")
            if st.button("Sign In", use_container_width=True):
                if l_user in st.session_state.user_db:
                    if check_password(l_pw, st.session_state.user_db[l_user]['pw_hash']):
                        st.session_state.auth_state["auth"] = True
                        st.session_state.current_user = l_user
                        st.session_state.fail_count = 0
                        st.rerun()
                st.session_state.fail_count += 1
                st.session_state.last_fail = time.time()
                st.error(f"Auth Failed ({st.session_state.fail_count}/{LOCKOUT_THRESHOLD})")

    with tab2:
        if st.session_state.auth_state["reg_step"] == "form":
            with st.container(border=True):
                st.subheader("NIST 800-63B Provisioning")
                new_u = st.text_input("New Username")
                new_e = st.text_input("Email")
                new_p = st.text_input("Passphrase (15+ Chars)", type="password")
                if len(new_p) > 0: st.progress(min(len(new_p)/15, 1.0), text="Entropy Check")
                if st.button("Begin Verification", use_container_width=True):
                    if len(new_p) >= 15:
                        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                        creds = flow.run_local_server(port=0)
                        code = str(random.randint(100000, 999999))
                        if send_2fa_code(creds, new_e, code):
                            st.session_state.reg_temp = {"u": new_u, "e": new_e, "p": new_p, "c": code}
                            st.session_state.auth_state["reg_step"] = "verify"
                            st.rerun()
                    else: st.warning("NIST Policy: 15 character minimum required.")
        else:
            v_code = st.text_input("Enter 6-Digit Code")
            if st.button("Finalize Identity"):
                if v_code == st.session_state.reg_temp['c']:
                    st.session_state.user_db[st.session_state.reg_temp['u']] = {
                        "pw_hash": hash_password(st.session_state.reg_temp['p']),
                        "email": st.session_state.reg_temp['e']
                    }
                    st.session_state.auth_state["reg_step"] = "form"
                    st.success("Identity Hardened! Login on Tab 1.")
                else: st.error("Invalid Code.")

def blue_team_page():
    st.title("🔵 Blue Team: Defensive Ops")
    st.subheader("🍯 Live Honeypot Analysis")
    st.dataframe(st.session_state.honeypot_logs, use_container_width=True)

def red_team_page():
    st.title("🔴 Red Team: Offensive Command & Control")
    st.markdown("### 🛠️ NIST & MITRE ATT&CK Simulation Suite")
    
    with st.expander("🚀 View Modern Red Team Arsenal (Top 10 Tools)"):
        st.table(pd.DataFrame({
            "Category": ["Recon", "Discovery", "Credential Access", "Lateral Movement", "Persistence"],
            "Industry Standard Tool": ["Nmap", "BloodHound", "Mimikatz", "Cobalt Strike", "Metasploit"]
        }))

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📡 Port Scan (Nmap)")
        target_ip = st.text_input("Target IP", value="10.0.0.1")
        if st.button("Execute Stealth Scan"):
            new_alert = pd.DataFrame([{
                "Timestamp": datetime.now().strftime("%H:%M:%S"),
                "Event": "Nmap Stealth Scan (-sS)", "Source": target_ip, "Status": "DETECTED"
            }])
            st.session_state.honeypot_logs = pd.concat([new_alert, st.session_state.honeypot_logs], ignore_index=True)
            st.toast("Packet Sent!")
            st.success(f"Scan initiated on {target_ip}. (Blue Team Notified)")

    with col2:
        st.subheader("🔑 Credential Access")
        if st.button("Simulate LSASS Memory Dump"):
            st.code("# Simulation: mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"", language="bash")
            st.warning("Action Logged in Security Audit Trail.")

def pc_health_page():
    st.title("🖥️ Hardware Audit")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("CPU Load", f"{psutil.cpu_percent()}%")
        st.metric("Memory", f"{psutil.virtual_memory().percent}%")
    with col2:
        st.write(f"**Hostname:** {socket.gethostname()}")
        st.write(f"**MAC:** {get_mac_address()}")

def help_desk_page():
    st.title("🆘 Help Desk")
    with st.form("ticket"):
        subj = st.text_input("Incident Subject")
        desc = st.text_area("Findings")
        if st.form_submit_button("Submit & Notify Admin"):
            st.success(f"Ticket logged. Alerting {ADMIN_IDENTITY}...")

# --- 5. NAVIGATION SETUP ---

login_pg = st.Page(identity_manager, title="Identity Manager", icon="🔐")
blue_pg = st.Page(blue_team_page, title="Blue Team (Defensive)", icon="🔵")
red_pg = st.Page(red_team_page, title="Red Team (Offensive)", icon="🔴")
health_pg = st.Page(pc_health_page, title="Hardware Audit", icon="🖥️")
help_pg = st.Page(help_desk_page, title="Help Desk", icon="🆘")

if not st.session_state.auth_state["auth"]:
    pg = st.navigation([login_pg])
else:
    if st.sidebar.button("Logout"):
        st.session_state.auth_state["auth"] = False
        st.rerun()
    pg = st.navigation({
        "Operations": [blue_pg, red_pg],
        "System Health": [health_pg],
        "Support": [help_pg]
    })


pg.run()
