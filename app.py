# ------------------------------------------------------------------------------
# Trust-IP Intelligence Tool
# Copyright (c) 2026 Yair Solomon
# Licensed under the MIT License.
# GitHub: https://github.com/YairSol/Trust-IP
# ------------------------------------------------------------------------------
import streamlit as st
import requests
import datetime
from collections import Counter
import folium
from streamlit_folium import st_folium
import concurrent.futures
import ipaddress
import pandas as pd
import re

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Trust-IP Intelligence", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="expanded" 
)

# --- CUSTOM CSS ---
st.markdown("""
<style>
    html, body, [class*="css"] {
        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important;
    }
    
    /* --- SIDEBAR --- */
    [data-testid="stSidebar"] {
        background-color: #0e1117;
        border-right: 1px solid #333;
    }
    
    [data-testid="stSidebar"] button.step-up {
        background: transparent !important;
        border: none !important;
        color: #ffffff !important;
        font-size: 26px !important; 
        font-weight: 800 !important;
        text-align: left !important;
        width: 100%;
        padding: 0px 40px !important;
        margin-bottom: 30px;
        line-height: 1.2;
        text-shadow: 0 0 20px rgba(66, 165, 245, 0.6);
        transition: transform 0.3s ease;
    }
    
    [data-testid="stSidebar"] button.step-up:hover {
        transform: scale(1.02);
    }

    div[data-testid="stTextInput"] input, div[data-testid="stTextArea"] textarea {
        background-color: #0d1117 !important;
        color: #ffffff !important;
        border: 1px solid #30363d !important;
        border-radius: 8px;
        padding: 12px;
        font-size: 15px;
    }
    
    div[data-testid="stTextInput"] input:focus, div[data-testid="stTextArea"] textarea:focus {
        border-color: #4DA6FF !important; 
        box-shadow: 0 0 10px rgba(77, 166, 255, 0.3) !important;
        outline: none !important;
    }
    
    [data-testid="InputInstructions"] { display: none !important; }
    
    [data-testid="stForm"] button {
        background-color: transparent !important;
        color: #4DA6FF !important; 
        border: 2px solid #4DA6FF !important; 
        border-radius: 12px;
        
        padding: 32px 0; 
        font-size: 26px;
        
        font-weight: 800;
        width: 100%;
        margin-top: 30px;
        text-transform: uppercase !important;
        letter-spacing: 3px; 
        transition: all 0.4s ease;
        
        box-shadow: 0 0 10px rgba(77, 166, 255, 0.15) !important;
        text-shadow: 0 0 8px rgba(77, 166, 255, 0.3);
    }
    
    [data-testid="stForm"] button:hover {
        background-color: rgba(77, 166, 255, 0.1) !important; 
        color: #ffffff !important; 
        border-color: #4DA6FF !important;
        
        box-shadow: 0 0 25px rgba(77, 166, 255, 0.7) !important;
        text-shadow: 0 0 15px rgba(77, 166, 255, 0.9);
        
        transform: translateY(-4px);
    }
    
    [data-testid="stForm"] button:active {
        transform: scale(0.98);
        box-shadow: 0 0 15px rgba(77, 166, 255, 0.5) !important;
    }

    div[data-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px;
        border-radius: 8px;
        color: white;
    }
    
    [data-testid="stForm"] {
        border: 0px none !important;
        padding: 0px !important;
        background-color: transparent !important;
    }
</style>
""", unsafe_allow_html=True)

# --- API KEYS CHECK ---
try:
    VT_API_KEY = st.secrets.get("VT_API_KEY")
    ABUSE_API_KEY = st.secrets.get("ABUSE_API_KEY")
    OTX_API_KEY = st.secrets.get("OTX_API_KEY")
    VPNAPI_KEY = st.secrets.get("VPNAPI_KEY")
    
    if not all([VT_API_KEY, ABUSE_API_KEY, OTX_API_KEY]):
        st.error("⚠️ Core API Keys are missing in secrets.toml")
        st.stop()
except Exception:
    st.error("⚠️ Error reading secrets.")
    st.stop()

# --- HELPER FUNCTIONS ---

def validate_ip_address(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return False, "⚠️ Private/Local IP (LAN)."
        if ip_obj.is_loopback:
            return False, "⚠️ Loopback IP (localhost)."
        return True, ""
    except ValueError:
        return False, "❌ Invalid IP address (IPv4/IPv6)."

def get_flag_emoji(country_code):
    if not country_code or len(country_code) != 2: return "🌐"
    return "".join(chr(127397 + ord(c.upper())) for c in country_code)

# --- API CLIENT FUNCTIONS ---

@st.cache_data(ttl=3600)
def get_vt_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try: return requests.get(url, headers=headers).json().get('data', {}).get('attributes', {})
    except: return {}

@st.cache_data(ttl=3600)
def get_vt_resolutions(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=10"
    headers = {"x-apikey": VT_API_KEY}
    try: return requests.get(url, headers=headers).json().get('data', [])
    except: return []

@st.cache_data(ttl=3600)
def get_vt_communicating_files(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files?limit=10"
    headers = {"x-apikey": VT_API_KEY}
    try: return requests.get(url, headers=headers).json().get('data', [])
    except: return []

@st.cache_data(ttl=3600)
def get_vt_referrers(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/referrer_files?limit=10"
    headers = {"x-apikey": VT_API_KEY}
    try: return requests.get(url, headers=headers).json().get('data', [])
    except: return []

@st.cache_data(ttl=3600)
def get_abuse_data(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': True}
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    try: return requests.get(url, headers=headers, params=params).json().get('data', {})
    except: return {}

@st.cache_data(ttl=3600)
def get_vpnapi_data(ip):
    if not VPNAPI_KEY: return {} 
    url = f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
    except: return {}
    return {}

@st.cache_data(ttl=3600)
def get_otx_data(ip):
    try:
        # OTX requires knowing if it's IPv4 or IPv6 in the URL path
        ip_version = ipaddress.ip_address(ip).version
        ip_type = "IPv6" if ip_version == 6 else "IPv4"
        url = f"https://otx.alienvault.com/api/v1/indicators/{ip_type}/{ip}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        return requests.get(url, headers=headers, timeout=5).json()
    except: return {}

def process_single_ip_for_bulk(ip):
    """פונקציה לסריקה מהירה עבור רשימות IP"""
    abuse = get_abuse_data(ip)
    vpn_data = get_vpnapi_data(ip)
    
    score = abuse.get('abuseConfidenceScore', 0)
    security = vpn_data.get('security', {})
    network = vpn_data.get('network', {})
    
    is_vpn = security.get('vpn', False)
    is_proxy = security.get('proxy', False)
    is_tor = security.get('tor', False)
    
    provider = network.get('autonomous_system_organization') or abuse.get('isp') or "Unknown"

    risk_clean = "Low"
    if score > 50: risk_clean = "High"
    elif score > 0: risk_clean = "Medium"
    
    risk_ui = "🔴 " + risk_clean if risk_clean == "High" else "🟠 " + risk_clean if risk_clean == "Medium" else "🟡 " + risk_clean if risk_clean == "Suspicious" else "🟢 " + risk_clean

    display_type = abuse.get('usageType', 'Unknown')
    if is_tor: display_type = "Tor Node"
    elif is_vpn: display_type = "VPN"
    elif is_proxy: display_type = "Proxy"
    elif 'Data Center' in display_type: display_type = "Data Center"

    return {
        "IP Address": ip,
        "Risk": risk_ui, 
        "Clean Risk": risk_clean, 
        "Abuse Score": score,
        "ISP / Provider": provider,
        "Country": abuse.get('countryName', 'Unknown'), 
        "Total Reports": abuse.get('totalReports', 0), 
        "Last Reported": abuse.get('lastReportedAt', 'N/A')[:10] if abuse.get('lastReportedAt') else 'N/A', 
        "Domain": abuse.get('domain', 'N/A') 
    }

# --- STATE MANAGEMENT ---
if 'results' not in st.session_state:
    st.session_state['results'] = None
if 'bulk_results' not in st.session_state:
    st.session_state['bulk_results'] = None

# --- SIDEBAR DESIGN ---
with st.sidebar:
    st.markdown('<button class="step-up" onclick="window.location.reload();">🛡️ Trust-IP Intelligence</button>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Mode Selector
    operation_mode = st.radio("⚙️ Select Investigation Mode:", ["Single IP", "Bulk Scan"])
    st.markdown("<br>", unsafe_allow_html=True)
    
    if operation_mode == "Single IP":
        with st.form(key='search_form'):
            st.markdown("<div style='margin-bottom: 12px; font-weight: 700; color: #8b949e; font-size: 14px; letter-spacing: 1px;'>ENTER IP ADDRESS:</div>", unsafe_allow_html=True)
            ip_input_raw = st.text_input("IP Address", placeholder="e.g. 8.8.8.8 or 2001:4860:4860::8888", label_visibility="collapsed")
            submit_btn = st.form_submit_button(label="Analyze IP", type="primary", use_container_width=True)
            ip_input = ip_input_raw.strip()
            
    elif operation_mode == "Bulk Scan":
        with st.form(key='bulk_form'):
            st.markdown("<div style='margin-bottom: 12px; font-weight: 700; color: #8b949e; font-size: 14px; letter-spacing: 1px;'>PASTE LOGS / IPS:</div>", unsafe_allow_html=True)
            bulk_input_raw = st.text_area("Logs", height=150, placeholder="185.15.2.1\n2001:0db8:85a3::8a2e:0370:7334\netc...", label_visibility="collapsed")
            bulk_submit_btn = st.form_submit_button(label="Run Bulk Scan", type="primary", use_container_width=True)

    st.markdown("---")
    st.caption("🛠️ **Developed by Yair Solomon**")
    st.caption("© Trustnet SOC Team 2026")

# --- MAIN LOGIC ---

# 1. BULK SCAN LOGIC
if operation_mode == "Bulk Scan":
    if 'bulk_submit_btn' in locals() and bulk_submit_btn:
        if not bulk_input_raw.strip():
            st.warning("⚠️ Please paste some logs or IPs to scan.")
        else:
            # Splitting text smartly by common separators instead of strict IPv4 regex
            raw_tokens = re.split(r'[\s,;\"\'\[\]\(\)<>]+', bulk_input_raw)
            valid_ips = []
            
            for token in set(raw_tokens):
                token = token.strip()
                if not token: continue
                
                # Clean up IPv4 addresses that might have a port attached (e.g. 192.168.1.1:80)
                if token.count('.') == 3 and token.count(':') == 1:
                    token = token.split(':')[0]
                    
                is_valid, _ = validate_ip_address(token)
                if is_valid: 
                    valid_ips.append(token)
            
            if not valid_ips:
                st.error("❌ No valid public IPv4/IPv6 addresses found in the text.")
            else:
                with st.status(f"🚀 Scanning {len(valid_ips)} IPs...", expanded=True) as status:
                    progress_bar = st.progress(0)
                    results_data = []
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                        futures = {executor.submit(process_single_ip_for_bulk, ip): ip for ip in valid_ips}
                        completed = 0
                        for future in concurrent.futures.as_completed(futures):
                            try: results_data.append(future.result())
                            except: pass
                            completed += 1
                            progress_bar.progress(completed / len(valid_ips))
                    
                    st.session_state['bulk_results'] = results_data
                    status.update(label="✅ Bulk Scan Complete!", state="complete", expanded=False)
                    st.session_state['results'] = None # Clear single results

    # Display Bulk Results
    if st.session_state['bulk_results']:
        df = pd.DataFrame(st.session_state['bulk_results'])
        st.header("⚡ Bulk Investigation Results")
        
        malicious_count = len(df[df['Abuse Score'] > 0])
        
        c1, c2 = st.columns(2)
        c1.metric("Total IPs Scanned", len(df))
        c2.metric("Malicious Detections", malicious_count, delta_color="inverse")
        
        st.markdown("---")
        
        display_df = df.drop(columns=['Clean Risk'])
        
        st.dataframe(
            display_df.style.background_gradient(subset=['Abuse Score'], cmap='RdYlGn_r', vmin=0, vmax=100),
            use_container_width=True,
            hide_index=True
        )
        
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download CSV Report",
            data=csv,
            file_name=f"trust_ip_bulk_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv",
        )

        st.markdown("---")
        st.subheader("📋 Raw Text Reports")
        
        full_report_text = f"Bulk IP Investigation Report ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M')})\n"
        full_report_text += "=" * 45 + "\n\n"
        
        for index, row in df.iterrows():
            safe_ip = row['IP Address'].replace('.', '[.]')
            
            full_report_text += f"Target IP: {safe_ip}\n"
            full_report_text += f"Risk Level: {row['Clean Risk']}\n" 
            full_report_text += f"Abuse Score: {row['Abuse Score']}%\n"
            
            if row['Total Reports'] > 0:
                full_report_text += f"Total Reports: {row['Total Reports']} (Last Seen: {row['Last Reported']})\n"
            
            if row['Domain'] and row['Domain'] != 'N/A':
                full_report_text += f"Associated Domain: {row['Domain']}\n"
                
            full_report_text += f"ISP/Provider: {row['ISP / Provider']}\n"
            full_report_text += f"Country: {row['Country']}\n" 
            full_report_text += "-" * 45 + "\n"
            
        st.code(full_report_text, language='text')

# 2. SINGLE IP LOGIC
elif operation_mode == "Single IP":
    if 'submit_btn' in locals() and submit_btn:
        if not ip_input:
            st.warning("⚠️ Please enter an IP address.")
        else:
            is_valid, error_msg = validate_ip_address(ip_input)
            
            if not is_valid:
                st.error(error_msg)
            else:
                with st.status("🚀 Launching Investigation Probes...", expanded=True) as status:
                    
                    st.write("⚡ Querying Reputation & Passive DNS...")
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future_vt = executor.submit(get_vt_data, ip_input)
                        future_vt_res = executor.submit(get_vt_resolutions, ip_input)
                        future_vt_comm = executor.submit(get_vt_communicating_files, ip_input)
                        future_vt_ref = executor.submit(get_vt_referrers, ip_input)
                        
                        future_abuse = executor.submit(get_abuse_data, ip_input)
                        future_vpnapi = executor.submit(get_vpnapi_data, ip_input)
                        future_otx = executor.submit(get_otx_data, ip_input)

                    vt_res = future_vt.result()
                    vt_resolutions = future_vt_res.result()
                    vt_communicating = future_vt_comm.result()
                    vt_referrers = future_vt_ref.result()
                    
                    st.write("🌍 Geolocating & Checking Threat Intel...")
                    abuse_res = future_abuse.result()
                    vpn_res = future_vpnapi.result()
                    otx_res = future_otx.result()

                st.session_state['results'] = {
                    'ip': ip_input,
                    'vt': vt_res,
                    'vt_res': vt_resolutions,
                    'vt_comm': vt_communicating,
                    'vt_ref': vt_referrers,
                    'abuse': abuse_res,
                    'vpnapi': vpn_res,
                    'otx': otx_res
                }
                st.session_state['bulk_results'] = None # Clear bulk results
                status.update(label="✅ Investigation Complete!", state="complete", expanded=False)

    # Display Single IP Results
    if st.session_state['results']:
        res = st.session_state['results']
        vt = res['vt']
        abuse = res['abuse']
        vpn_data = res.get('vpnapi', {})
        otx = res['otx']
        current_ip = res['ip']

        st.header(f"🔎 Analysis Report: {current_ip}")
        
        vt_score = vt.get('last_analysis_stats', {}).get('malicious', 0)
        abuse_score = abuse.get('abuseConfidenceScore', 0)
        
        location_data = vpn_data.get('location', {})
        country = abuse.get('countryName') or location_data.get('country', 'Unknown')
        country_code = abuse.get('countryCode') or location_data.get('country_code')
        flag = get_flag_emoji(country_code)
        
        m1, m2, m3 = st.columns(3)
        m1.metric("VT Detections", f"{vt_score}", delta="Vendors", delta_color="inverse" if vt_score > 0 else "normal")
        m2.metric("Abuse Score", f"{abuse_score}%", delta="Confidence", delta_color="inverse" if abuse_score > 0 else "normal")
        m3.metric("Location", country, delta=flag)
        st.markdown("---")
        
        # Tool buttons row 1
        c1, c2, c3, c4 = st.columns(4)
        with c1: st.link_button("🦠 VirusTotal", f"https://www.virustotal.com/gui/ip-address/{current_ip}", use_container_width=True)
        with c2: st.link_button("⚠️ AbuseIPDB", f"https://www.abuseipdb.com/check/{current_ip}", use_container_width=True)
        with c3: st.link_button("🔍 Talos Intel", f"https://talosintelligence.com/reputation_center/lookup?search={current_ip}", use_container_width=True)
        with c4: st.link_button("🚓 CriminalIP", f"https://www.criminalip.io/asset/report/{current_ip}", use_container_width=True)

# Tool buttons row 2
        c5, c6, c7, c8 = st.columns(4)
        with c5: st.link_button("🎯 Spur", f"https://spur.us/context/{current_ip}", use_container_width=True)
        with c6: st.link_button("🌐 Censys", f"https://search.censys.io/hosts/{current_ip}", use_container_width=True)
        with c7: st.link_button("📌 IPinfo", f"https://ipinfo.io/{current_ip}", use_container_width=True)
        with c8: st.link_button("👽 OTX AlienVault", f"https://otx.alienvault.com/indicator/ip/{current_ip}", use_container_width=True)

        st.markdown("---")
        
        col_vt, col_abuse = st.columns([1, 1])

        with col_vt:
            st.subheader("🌐 VirusTotal Analysis")
            if vt:
                stats = vt.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                
                if malicious > 0:
                    st.progress(min(malicious * 2, 100) / 100, text=f"Detection Rate: {malicious}/{total}")
                else:
                    st.progress(0, text="Clean Reputation")

                tab1, tab2, tab3 = st.tabs(["🎯 Detections", "📝 Details", "🔗 Relations"])
                
                with tab1:
                    malicious_engines = [e for e, r in vt.get('last_analysis_results', {}).items() if r['category'] == 'malicious']
                    if malicious_engines:
                        st.error(f"⚠️ Flagged malicious by {len(malicious_engines)} vendors")
                        st.markdown(", ".join([f"`{e}`" for e in malicious_engines[:12]]))
                    else:
                        st.success("✅ Clean across all major security vendors")
                
                with tab2:
                    st.write(f"**ASN:** {vt.get('asn', 'N/A')}")
                    st.write(f"**Owner:** {vt.get('as_owner', 'N/A')}")
                    https_cert = vt.get('last_https_certificate', {})
                    if https_cert:
                        st.info(f"🔐 **Cert Issuer:** {https_cert.get('issuer', {}).get('CN', 'N/A')}")
                    else:
                        st.info("No HTTPS certificate found")

                with tab3:
                    resolutions = res.get('vt_res', [])
                    if resolutions:
                        st.markdown("### 🌐 Passive DNS")
                        dns_data = []
                        for item in resolutions:
                            dns_data.append({
                                "Domain": item.get('attributes', {}).get('host_name', 'Unknown'),
                                "Last Seen": datetime.datetime.fromtimestamp(item.get('attributes', {}).get('date', 0)).strftime('%Y-%m-%d')
                            })
                        st.dataframe(dns_data, use_container_width=True, hide_index=True)
                        st.divider()

                    def render_compact_file_row(title, files_list):
                        if not files_list: return
                        st.markdown(f"### {title}")
                        h1, h2, h3 = st.columns([3, 4, 2])
                        h1.markdown("**File Name**")
                        h2.markdown("**SHA256**")
                        h3.markdown("**Detections**")
                        st.markdown("---")

                        for f in files_list:
                            attr = f.get('attributes', {})
                            name = attr.get('meaningful_name') or attr.get('type_description') or 'Unknown'
                            sha = attr.get('sha256', 'N/A')
                            score = attr.get('last_analysis_stats', {}).get('malicious', 0)
                            
                            icon = "🔴" if score > 0 else "🟢"
                            score_color = "red" if score > 0 else "green"
                            
                            c1, c2, c3 = st.columns([3, 4, 2])
                            c1.markdown(f"📄 **{name}**", help=name)
                            c2.caption(f"`{sha}`")
                            c3.markdown(f"{icon} :{score_color}[**{score}** / 90]")
                            st.markdown("""<hr style="margin: 5px 0px; opacity: 0.2;">""", unsafe_allow_html=True)

                    comm_files = res.get('vt_comm', [])
                    if comm_files:
                        render_compact_file_row("📡 Communicating Files", comm_files)

                    ref_files = res.get('vt_ref', [])
                    if ref_files:
                        render_compact_file_row("📂 Referrer Files", ref_files)
                    
                    if not (resolutions or comm_files or ref_files):
                        st.info("No significant relations found.")
            else:
                st.warning("No Data from VirusTotal")

        with col_abuse:
            st.subheader("⚠️ AbuseIPDB Intelligence")
            if abuse:
                c_name = abuse.get('countryName') or 'N/A'
                
                abuse_report = f"""DB Results:
IP: {current_ip}
Abuse Score: {abuse_score}%
Total Reports: {abuse.get('totalReports', 0)}
ISP: {abuse.get('isp', 'N/A')}
Usage Type: {abuse.get('usageType', 'N/A')}
Domain: {abuse.get('domain', 'N/A')}
Country: {c_name}"""

                st.code(abuse_report, language='text')
                st.markdown("---")
                
                with st.expander("💬 View Community Reports"):
                    reports = abuse.get('reports', [])
                    if reports:
                        for r in reports[:3]:
                            st.caption(f"📅 {r.get('reportedAt', '')[:10]}")
                            st.text(r.get('comment', 'No comment'))
                            st.markdown("---")
                    else:
                        st.write("No community reports available.")
            else:
                st.warning("No Data from AbuseIPDB")

        st.markdown("---")
        st.subheader("🧠 Threat Intel")
        if otx and otx.get('pulse_info', {}).get('count', 0) > 0:
            pulses = otx.get('pulse_info', {}).get('pulses', [])
            all_tags = [tag for p in pulses for tag in p.get('tags', [])]
            if all_tags:
                top_tags = [tag for tag, c in Counter(all_tags).most_common(8)]
                st.markdown(" ".join([f"<span style='background-color:#333; padding:4px 8px; border-radius:4px; margin-right:5px;'>{tag}</span>" for tag in top_tags]), unsafe_allow_html=True)
        else:
            st.info("No threat intelligence data available")

        st.markdown("---")
        st.subheader("🕵️ Connectivity & Geo-Location")
        
        security = vpn_data.get('security', {})
        network = vpn_data.get('network', {})
        location = vpn_data.get('location', {})
        
        clean_company = network.get('autonomous_system_organization') or abuse.get('isp') or "Unknown"

        is_vpn = security.get('vpn', False)
        is_proxy = security.get('proxy', False)
        is_tor = security.get('tor', False)
        is_relay = security.get('relay', False)

        safe_providers = [
            'Microsoft', 'Google', 'Amazon', 'AWS', 'Cloudflare', 'Akamai', 
            'Facebook', 'Meta', 'Oracle', 'IBM', 'Alibaba', 'Salesforce', 'Apple'
        ]
        is_big_tech = any(tech.lower() in str(clean_company).lower() for tech in safe_providers)

        final_status = "Clean / Residential"
        status_type = "success"
        display_type_text = "Residential / Corporate"

        if is_big_tech:
            final_status = f"Cloud Infrastructure ({clean_company})"
            status_type = "info"
            display_type_text = "Cloud / Data Center"
        elif is_tor:
            display_type_text = "Tor Anonymizer"
            final_status = "Tor Network (High Risk)"
            status_type = "error"
        elif is_vpn:
            display_type_text = "VPN Endpoint"
            final_status = "Commercial VPN Detected"
            status_type = "warning"
        elif is_proxy:
            display_type_text = "Public Proxy"
            final_status = "Open Proxy Detected"
            status_type = "error"
        elif is_relay:
            display_type_text = "Apple/Cloud Relay"
            final_status = "Private Relay (Low Risk)"
            status_type = "info"
        elif 'Data Center' in (abuse.get('usageType') or ''):
            final_status = "Data Center Traffic"
            status_type = "warning"
        else:
            final_status = "Clean / Residential"
            status_type = "success"
            display_type_text = "Residential / Corporate"

        if status_type == "error": st.error(f"**Status:** {final_status}")
        elif status_type == "warning": st.warning(f"**Status:** {final_status}")
        elif status_type == "info": st.info(f"**Status:** {final_status}")
        else: st.success(f"**Status:** {final_status}")

        c1, c2, c3 = st.columns([1, 1, 2])
        with c1: st.write(f"🏢 **Provider:** {clean_company}")
        with c2: st.write(f"📡 **Type:** {display_type_text}")
        
        with c3:
            def parse_coord(c):
                try:
                    if c is None or str(c).strip() == '': return None
                    return float(c)
                except (ValueError, TypeError):
                    return None

            COUNTRY_DEFAULTS = {
                "United States": [37.0902, -95.7129],
                "Australia": [-25.2744, 133.7751],
                "China": [35.8617, 104.1954],
                "Russia": [61.5240, 105.3188],
                "India": [20.5937, 78.9629],
                "Brazil": [-14.2350, -51.9253],
                "United Kingdom": [55.3781, -3.4360],
                "Germany": [51.1657, 10.4515],
                "France": [46.2276, 2.2137],
                "Israel": [31.0461, 34.8516],
                "Japan": [36.2048, 138.2529],
                "Canada": [56.1304, -106.3468]
            }

            lat = parse_coord(location_data.get('latitude'))
            lon = parse_coord(location_data.get('longitude'))
            zoom_level = 9 

            if lat is None or lon is None:
                if country in COUNTRY_DEFAULTS:
                    lat, lon = COUNTRY_DEFAULTS[country]
                    zoom_level = 3 

            if lat is not None and lon is not None:
                try:
                    m = folium.Map(location=[lat, lon], zoom_start=zoom_level, tiles="CartoDB dark_matter")
                    folium.Marker(
                        [lat, lon], 
                        icon=folium.Icon(color="blue", icon="info-sign"),
                        tooltip=f"{country} ({current_ip})"
                    ).add_to(m)
                    st_folium(m, height=250, use_container_width=True)
                except Exception:
                    st.warning("⚠️ Map render failed")
            else:
                st.info(f"🌐 Map coordinates unavailable for {country}")

        with st.expander("🐞 Raw API Data"):
            st.json(vpn_data)

# 3. WELCOME SCREEN (Shown when no results)
if not st.session_state['results'] and not st.session_state['bulk_results']:
    st.markdown("""
<style>
[data-testid="stAppViewContainer"] {
    background-image: linear-gradient(rgba(14, 17, 23, 0.85), rgba(14, 17, 23, 0.85)), url("https://raw.githubusercontent.com/YairSol/Trust-IP/4a397f39b4c480aa5f423daab0eb8440aa850b8a/map.svg");
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
    background-attachment: fixed;
    background-color: #0e1117;
}

[data-testid="stHeader"] {
    background-color: rgba(0,0,0,0);
}

.info-box {
    background-color: rgba(14, 17, 23, 0.9);
    padding: 30px;
    border-radius: 15px;
    border: 1px solid #333;
    box-shadow: 0 0 20px rgba(77, 166, 255, 0.2);
    max-width: 500px;
    margin: 15vh auto;
    text-align: center;
}

.sources {
    color: #888;
    font-size: 14px;
    margin-top: 15px;
    letter-spacing: 1px;
}
</style>

<div class='info-box'>
<h1 style='font-size: 60px; margin: 0;'>🛡️</h1>
<h1 style='margin-top: -10px; font-weight: 800; color: white;'>Trust-IP</h1>
<div style='margin: 25px 0; font-size: 18px; color: #e0e0e0;'>
👈 <b>Choose an option</b> in the sidebar to start
</div>
<hr style='border-color: #333; margin: 20px 0;'>
<div class='sources'>
Get real-time intelligence from multiple global threat feeds.
</div>
</div>
""", unsafe_allow_html=True)
