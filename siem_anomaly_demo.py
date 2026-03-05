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
st.set_page_config(page_title='SOC Fortress', layout="wide")
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# --- 2. THE RECOVERY LISTENER (CRITICAL FOR WEB) ---
# This part catches the user when they return from Google with an auth code.
query_params = st.query_params

if "code" in query_params:
    auth_code = query_params["code"]
    
    # Check if this is a returning registration attempt
    if "reg_e" in query_params:
        try:
            client_config = st.secrets["google_credentials"]
            r_uri = client_config["web"]["redirect_uris"][0]
            
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES, redirect_uri=r_uri)
            flow.fetch_token(code=auth_code)
            
            # Generate and Send SOC 2FA code
            soc_code = str(random.randint(100000, 999999))
            service = build('gmail', 'v1', credentials=flow.credentials)
            msg = MIMEText(f"Your SOC Verification Code: {soc_code}")
            msg['to'] = query_params["reg_e"]
            msg['subject'] = "🔐 SOC Command 2FA"
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            service.users().messages().send(userId="me", body={'raw': raw}).execute()

            # Restore the registration state into the NEW session memory
            st.session_state.reg_temp = {
                "u": query_params.get("reg_u", "User"),
                "e": query_params["reg_e"],
                "p": query_params.get("reg_p", ""), # Note: For simulation only
                "c": soc_code
            }
            st.session_state.auth_state = {"auth": False, "reg_step": "verify"}
            
            # Clear the sensitive URL parameters and stay on the page
            st.query_params.clear()
            st.rerun()
        except Exception as e:
            st.error(f"Handshake Failed: {e}")

# --- 3. UTILITIES ---
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def log_security_event(user, event_type, status="ALERT"):
    new_entry = pd.DataFrame([{
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Event": f"{event_type}: {user}",
        "Source": "Cloud-Node-Alpha",
        "Status": status
    }])
    if 'honeypot_logs' not in st.session_state:
        st.session_state.honeypot_logs = new_entry
    else:
        st.session_state.honeypot_logs = pd.concat([new_entry, st.session_state.honeypot_logs], ignore_index=True)

# --- 4. SESSION INITIALIZATION ---
if 'user_db' not in st.session_state: st.session_state.user_db = {} 
if 'auth_state' not in st.session_state: st.session_state.auth_state = {"auth": False, "reg_step": "form"}
if 'fail_count' not in st.session_state: st.session_state.fail_count = 0
if 'honeypot_logs' not in st.session_state:
    st.session_state.honeypot_logs = pd.DataFrame(columns=["Timestamp", "Event", "Source", "Status"])

# --- 5. PAGE FUNCTIONS ---

def identity_manager():
    st.title("🛡️ SOC Hardened Identity Portal")
    
    if st.session_state.fail_count >= 3:
        st.error("🚫 Brute-Force Lockout Active. Contact Admin.")
        return

    tab1, tab2 = st.tabs(["🔒 Secure Login", "📝 Provision Account"])

    with tab1:
        u = st.text_input("Username", key="l_u")
        p = st.text_input("Password", type="password", key="l_p")
        if st.button("Login", use_container_width=True):
            if u in st.session_state.user_db and check_password(p, st.session_state.user_db[u]['pw_hash']):
                st.session_state.auth_state["auth"] = True
                st.session_state.current_user = u
                st.session_state.fail_count = 0
                log_security_event(u, "Successful Login", "SUCCESS")
                st.rerun()
            else:
                st.session_state.fail_count += 1
                log_security_event(u, "FAILED LOGIN", "CRITICAL")
                st.error(f"Invalid Credentials ({st.session_state.fail_count}/3)")

    with tab2:
        if st.session_state.auth_state["reg_step"] == "form":
            new_u = st.text_input("Username", key="reg_user")
            new_e = st.text_input("Email", key="reg_email")
            new_p = st.text_input("Passphrase (15+ Chars)", type="password", key="reg_pass")
            
            if st.button("Authorize with Google"):
                if len(new_p) >= 15:
                    # Smuggle the registration data into the URL so it survives the redirect
                    st.query_params["reg_u"] = new_u
                    st.query_params["reg_e"] = new_e
                    st.query_params["reg_p"] = new_p 
                    
                    c_config = st.secrets["google_credentials"]
                    flow = InstalledAppFlow.from_client_config(
                        c_config, SCOPES, redirect_uri=c_config["web"]["redirect_uris"][0]
                    )
                    auth_url, _ = flow.authorization_url(prompt='consent')
                    
                    st.session_state.auth_state["reg_step"] = "callback_waiting"
                    st.markdown(f"### [🔐 Click here to verify with Google]({auth_url})")
                else:
                    st.warning("NIST Requirement: Passphrase must be at least 15 characters.")
        
        elif st.session_state.auth_state["reg_step"] == "verify":
            st.success(f"Verification code sent to your inbox.")
            v_code = st.text_input("Enter 6-Digit Code")
            if st.button("Finalize Identity"):
                if v_code == st.session_state.reg_temp['c']:
                    st.session_state.user_db[st.session_state.reg_temp['u']] = {
                        "pw_hash": hash_password(st.session_state.reg_temp['p']),
                        "email": st.session_state.reg_temp['e']
                    }
                    st.session_state.auth_state["reg_step"] = "form"
                    st.success("Identity Provisioned! You can now log in.")
                else:
                    st.error("Invalid Code.")

def blue_page():
    st.title("🔵 Blue Team: SIEM Dashboard")
    st.dataframe(st.session_state.honeypot_logs, use_container_width=True)

def red_page():
    st.title("🔴 Red Team: C2 Simulator")
    if st.button("Simulate Nmap Stealth Scan"):
        log_security_event(st.session_state.current_user, "Nmap -sS Scan Detected", "ALERT")
        st.toast("Scan Packet Sent")

# --- 6. NAVIGATION ---
login_pg = st.Page(identity_manager, title="Identity Manager", icon="🔐")
blue_pg = st.Page(blue_page, title="Blue Team (Defensive)", icon="🔵")
red_pg = st.Page(red_page, title="Red Team (Offensive)", icon="🔴")

if not st.session_state.auth_state["auth"]:
    pg = st.navigation([login_pg])
else:
    if st.sidebar.button("Logout"):
        st.session_state.auth_state["auth"] = False
        st.rerun()
    pg = st.navigation({"Operations": [blue_pg, red_pg]})

pg.run()

