import streamlit as st
import pandas as pd
import bcrypt
import time
import random
import base64
import socket
from datetime import datetime
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- 1. CONFIG & STANDARDS ---
st.set_page_config(page_title='josh ohmes | SOC Fortress', layout="wide")
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
ADMIN_IDENTITY = "joshohmes@proton.me"

# --- 2. THE CALLBACK LISTENER ---
# Checks for the Google Auth code in the URL when returning to the site
query_params = st.query_params
if "code" in query_params and st.session_state.get("auth_state", {}).get("reg_step") == "callback_waiting":
    auth_code = query_params["code"]
    try:
        client_config = st.secrets["google_credentials"]
        # We pull the redirect URI directly from your Secrets dictionary
        r_uri = client_config["web"]["redirect_uris"][0]
        
        flow = InstalledAppFlow.from_client_config(client_config, SCOPES, redirect_uri=r_uri)
        flow.fetch_token(code=auth_code)
        
        # Generate SOC 2FA code
        soc_code = str(random.randint(100000, 999999))
        
        # Send Email
        service = build('gmail', 'v1', credentials=flow.credentials)
        msg = MIMEText(f"Your SOC Verification Code: {soc_code}")
        msg['to'] = st.session_state.reg_temp['e']
        msg['subject'] = "🔐 SOC Command 2FA"
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        service.users().messages().send(userId="me", body={'raw': raw}).execute()

        st.session_state.reg_temp['c'] = soc_code
        st.session_state.auth_state["reg_step"] = "verify"
        st.query_params.clear()
        st.rerun()
    except Exception as e:
        st.error(f"Callback Handshake Failed: {e}")

# --- 3. UTILITIES ---
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def log_security_event(user, event_type, status="ALERT"):
    new_entry = pd.DataFrame([{
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Event": f"{event_type}: {user}",
        "Source": "Cloud-Node-01",
        "Status": status
    }])
    st.session_state.honeypot_logs = pd.concat([new_entry, st.session_state.honeypot_logs], ignore_index=True)

# --- 4. SESSION STATE ---
if 'user_db' not in st.session_state: st.session_state.user_db = {} 
if 'auth_state' not in st.session_state: st.session_state.auth_state = {"auth": False, "reg_step": "form"}
if 'fail_count' not in st.session_state: st.session_state.fail_count = 0
if 'honeypot_logs' not in st.session_state:
    st.session_state.honeypot_logs = pd.DataFrame(columns=["Timestamp", "Event", "Source", "Status"])

# --- 5. PAGE FUNCTIONS ---
def identity_manager():
    st.title("🛡️ SOC Hardened Web Portal")
    if st.session_state.fail_count >= 3:
        st.error("🚫 CISA Rate-Limit: Brute-Force Lockout Active.")
        return

    t1, t2 = st.tabs(["🔒 Sign In", "📝 Register"])

    with t1:
        u = st.text_input("Username", key="l_user")
        p = st.text_input("Password", type="password", key="l_pass")
        if st.button("Login", use_container_width=True):
            if u in st.session_state.user_db and check_password(p, st.session_state.user_db[u]['pw_hash']):
                st.session_state.auth_state["auth"] = True
                st.session_state.current_user = u
                st.session_state.fail_count = 0
                log_security_event(u, "Auth Success", "SUCCESS")
                st.rerun()
            else:
                st.session_state.fail_count += 1
                log_security_event(u, "Auth Failure", "CRITICAL")
                st.error(f"Invalid Credentials ({st.session_state.fail_count}/3)")

    with t2:
        if st.session_state.auth_state["reg_step"] == "form":
            new_u = st.text_input("New User", key="r_user")
            new_e = st.text_input("Email", key="r_email")
            new_p = st.text_input("Passphrase (15+)", type="password", key="r_pass")
            if st.button("Authorize with Google"):
                if len(new_p) >= 15:
                    st.session_state.reg_temp = {"u": new_u, "e": new_e, "p": new_p}
                    c_config = st.secrets["google_credentials"]
                    flow = InstalledAppFlow.from_client_config(c_config, SCOPES, redirect_uri=c_config["web"]["redirect_uris"][0])
                    auth_url, _ = flow.authorization_url(prompt='consent')
                    st.session_state.auth_state["reg_step"] = "callback_waiting"
                    st.markdown(f"### [🔐 Click to Verify via Google]({auth_url})")
                else: st.warning("NIST Requirement: 15 character minimum.")
        
        elif st.session_state.auth_state["reg_step"] == "verify":
            v = st.text_input("Enter 6-Digit Code")
            if st.button("Finalize Account"):
                if v == st.session_state.reg_temp['c']:
                    st.session_state.user_db[st.session_state.reg_temp['u']] = {
                        "pw_hash": hash_password(st.session_state.reg_temp['p']),
                        "email": st.session_state.reg_temp['e']
                    }
                    st.session_state.auth_state["reg_step"] = "form"
                    st.success("Registration Successful! Please sign in.")
                else: st.error("Code Mismatch.")

def blue_page():
    st.title("🔵 SIEM Dashboard")
    st.dataframe(st.session_state.honeypot_logs, use_container_width=True)

def red_page():
    st.title("🔴 C2 Simulator")
    if st.button("Launch Network Scan"):
        log_security_event(st.session_state.current_user, "Nmap Scan Simulation", "ALERT")
        st.toast("Scanning...")

# --- 6. NAVIGATION ---
login_pg = st.Page(identity_manager, title="Login", icon="🔐")
blue_pg = st.Page(blue_page, title="Blue Team", icon="🔵")
red_pg = st.Page(red_page, title="Red Team", icon="🔴")

if not st.session_state.auth_state["auth"]:
    pg = st.navigation([login_pg])
else:
    if st.sidebar.button("Logout"):
        st.session_state.auth_state["auth"] = False
        st.rerun()
    pg = st.navigation({"SOC Operations": [blue_pg, red_pg]})

pg.run()
