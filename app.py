import streamlit as st
import requests
import datetime
from collections import Counter
import folium
from streamlit_folium import st_folium
import concurrent.futures
import ipaddress

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
    h1, h2, h3 { font-family: 'Courier New', monospace; font-weight: bold; }
    div[data-testid="stMetric"] {
        background-color: #262730;
        border: 1px solid #4F4F4F;
        padding: 10px;
        border-radius: 5px;
        color: white;
    }
    .block-container { padding-top: 3.5rem; }
    
    div.stButton > button { border-radius: 8px; font-weight: bold; width: 100%; }
    
    [data-testid="stForm"] {
        border: 0px none !important;
        padding: 0px !important;
        box-shadow: none !important;
        background-color: transparent !important;
    }
    
    [data-testid="InputInstructions"] {
        display: none !important;
    }
</style>
""", unsafe_allow_html=True)

# --- API KEYS ---
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
    OTX_API_KEY = st.secrets["OTX_API_KEY"]
    PROXYCHECK_API_KEY = st.secrets["PROXYCHECK_API_KEY"]
except Exception:
    st.error("⚠️ API Keys missing! Please configure them in Streamlit Cloud Secrets.")
    st.stop()

# --- HELPER FUNCTIONS ---

def validate_ip_address(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return False, "⚠️ This is a Private/Local IP (LAN). No external intelligence available."
        if ip_obj.is_loopback:
            return False, "⚠️ This is a Loopback IP (localhost)."
        return True, ""
    except ValueError:
        return False, "❌ Invalid IP Address format. Please enter a valid IPv4 address."

def get_flag_emoji(country_code):
    if not country_code or len(country_code) != 2: return "🌐"
    return "".join(chr(127397 + ord(c.upper())) for c in country_code)

# --- API CLIENT FUNCTIONS ---

def get_vt_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try: return requests.get(url, headers=headers).json().get('data', {}).get('attributes', {})
    except: return {}

def get_vt_resolutions(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=10"
    headers = {"x-apikey": VT_API_KEY}
    try: return requests.get(url, headers=headers).json().get('data', [])
    except: return []

def get_vt_communicating_files(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files?limit=10"
    headers = {"x-apikey": VT_API_KEY}
    try: return requests.get(url, headers=headers).json().get('data', [])
    except: return []

def get_vt_referrers(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/referrer_files?limit=10"
    headers = {"x-apikey": VT_API_KEY}
    try: return requests.get(url, headers=headers).json().get('data', [])
    except: return []

def get_abuse_data(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': True}
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    try: return requests.get(url, headers=headers, params=params).json().get('data', {})
    except: return {}

def get_proxycheck_data(ip):
    url = f"http://proxycheck.io/v2/{ip}?key={PROXYCHECK_API_KEY}&vpn=1&asn=1&risk=1&port=1&seen=1&tag=msg&node=1"
    try:
        data = requests.get(url, timeout=5).json()
        if data.get('status') == 'ok': return data.get(ip, {})
    except: return {}
    return {}

def get_otx_data(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try: return requests.get(url, headers=headers, timeout=5).json()
    except: return {}

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ Trust-IP Intelligence")
    st.markdown("---")
    
    with st.form(key='search_form'):
        ip_input_raw = st.text_input("Enter IP Address:", placeholder="167.71.5.161")
        submit_btn = st.form_submit_button(label="🚀 Analyze IP", type="primary", use_container_width=True)
    
    ip_input = ip_input_raw.strip()

    st.markdown("---")
    st.caption("🛠️ **Developed by Yair Solomon**")
    st.caption("© Trustnet SOC Team 2026")

# --- MAIN LOGIC ---
if 'results' not in st.session_state:
    st.session_state['results'] = None

if submit_btn:
    if not ip_input:
        st.warning("⚠️ Please enter an IP address to begin.")
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
                    future_proxy = executor.submit(get_proxycheck_data, ip_input)
                    future_otx = executor.submit(get_otx_data, ip_input)
                    
                    vt_res = future_vt.result()
                    vt_resolutions = future_vt_res.result()
                    vt_communicating = future_vt_comm.result()
                    vt_referrers = future_vt_ref.result()
                    
                    st.write("🌍 Geolocating & Checking Threat Intel...")
                    abuse_res = future_abuse.result()
                    proxy_res = future_proxy.result()
                    otx_res = future_otx.result()

                st.session_state['results'] = {
                    'ip': ip_input,
                    'vt': vt_res,
                    'vt_res': vt_resolutions,
                    'vt_comm': vt_communicating,
                    'vt_ref': vt_referrers,
                    'abuse': abuse_res,
                    'proxy': proxy_res,
                    'otx': otx_res
                }
                
                status.update(label="✅ Investigation Complete!", state="complete", expanded=False)

# --- DASHBOARD OR WELCOME SCREEN ---
if st.session_state['results']:
    res = st.session_state['results']
    vt = res['vt']
    abuse = res['abuse']
    proxy_data = res['proxy']
    otx = res['otx']
    current_ip = res['ip']

    # --- TOP METRICS ---
    st.header(f"🔎 Analysis Report: {current_ip}")
    
    vt_score = vt.get('last_analysis_stats', {}).get('malicious', 0)
    abuse_score = abuse.get('abuseConfidenceScore', 0)
    country = proxy_data.get('country', abuse.get('countryName', 'Unknown'))
    flag = get_flag_emoji(abuse.get('countryCode'))
    
    m1, m2, m3 = st.columns(3)
    m1.metric("VT Detections", f"{vt_score}", delta="Vendors", delta_color="inverse" if vt_score > 0 else "normal")
    m2.metric("Abuse Score", f"{abuse_score}%", delta="Confidence", delta_color="inverse" if abuse_score > 0 else "normal")
    m3.metric("Location", country, delta=flag)
    
    st.markdown("---")

    # --- MAIN COLUMNS ---
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

            # --- TABS ---
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

            # --- INVESTIGATION TAB (Relations) ---
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
            st.markdown(f"**Total Reports:** {abuse.get('totalReports', 0)}")
            st.markdown(f"**ISP:** {abuse.get('isp', 'N/A')}")
            st.markdown(f"**Usage Type:** {abuse.get('usageType', 'N/A')}")
            st.markdown(f"**Domain:** {abuse.get('domain', 'N/A')}")
            
            with st.expander("💬 View Community Reports"):
                reports = abuse.get('reports', [])
                if reports:
                    for r in reports[:3]:
                        st.caption(f"📅 {r['reportedAt'][:10]}")
                        st.text(r['comment'])
                        st.divider()
                else:
                    st.write("No community reports available.")
            
            st.divider()
            abuse_report = f"""DB Results:
Target IP: {current_ip}
Score: {abuse_score}%
Total Reports: {abuse.get('totalReports', 0)}
ISP: {abuse.get('isp', 'N/A')}
Usage Type: {abuse.get('usageType', 'N/A')}
Domain: {abuse.get('domain', 'N/A')}"""
            st.code(abuse_report, language='text')
        else:
            st.warning("No Data from AbuseIPDB")

    # --- OTX ---
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

    # --- SECTION 3: SMART CONNECTIVITY & GEO-LOCATION ---
    st.markdown("---")
    st.subheader("🕵️ Connectivity & Geo-Location")
    
    raw_op = proxy_data.get('operator')
    if isinstance(raw_op, dict):
        clean_company = raw_op.get('name', 'Unknown')
    elif isinstance(raw_op, str):
        clean_company = raw_op
    else:
        clean_company = proxy_data.get('provider') or abuse.get('isp') or "Unknown"

    # 2. Smart Logic: Whitelist
    safe_providers = [
        'Microsoft', 'Google', 'Amazon', 'AWS', 'Cloudflare', 'Akamai', 
        'Facebook', 'Meta', 'Oracle', 'IBM', 'Alibaba', 'Salesforce', 
        'Fastly', 'Apple'
    ]
    is_big_tech = any(tech.lower() in str(clean_company).lower() for tech in safe_providers)

    # 3. VPN Brand Detection
    vpn_brands = [
        'Proton', 'Nord', 'ExpressVPN', 'Mullvad', 'CyberGhost', 'Surfshark', 
        'PureVPN', 'HMA', 'PrivateInternetAccess', 'ZenMate', 'IPVanish', 
        'Windscribe', 'TunnelBear', 'Hotspot Shield'
    ]
    is_known_vpn_brand = any(brand.lower() in str(clean_company).lower() for brand in vpn_brands)

    pc_proxy = proxy_data.get('proxy') == 'yes'
    raw_type = proxy_data.get('type') or 'N/A'
    abuse_usage = abuse.get('usageType') or ''

    final_status = "Clean / Residential"
    status_type = "success"
    
    display_type_text = raw_type 

    if pc_proxy:
        if "TOR" in raw_type.upper():
             display_type_text = "Tor Anonymizer"
        elif "Compromised" in raw_type:
             display_type_text = "Compromised Server"
        elif any(x in raw_type.upper() for x in ['SOCKS', 'HTTP', 'CONNECT', 'WEB']):
             display_type_text = "Proxy (Confirmed)"
        elif is_known_vpn_brand:
             display_type_text = "VPN (Confirmed)"
        else:
             display_type_text = "VPN / Proxy"

    if is_big_tech:
        final_status = f"Cloud Infrastructure ({clean_company})"
        status_type = "info" 
        display_type_text = "Cloud / Business"
        
    elif pc_proxy:
        final_status = f"{display_type_text}"
        status_type = "error" 
        
    elif 'Data Center' in abuse_usage or 'Web Hosting' in abuse_usage:
        final_status = "Data Center Traffic"
        status_type = "warning" 

    if status_type == "error": st.error(f"**Status:** {final_status}")
    elif status_type == "warning": st.warning(f"**Status:** {final_status}")
    elif status_type == "info": st.info(f"**Status:** {final_status}")
    else: st.success(f"**Status:** {final_status}")

    c1, c2, c3 = st.columns([1, 1, 2])
    with c1: st.write(f"🏢 **Provider:** {clean_company}")
    with c2: st.write(f"📡 **Type:** {display_type_text}")
    
    with c3:
        lat, lon = proxy_data.get('latitude'), proxy_data.get('longitude')
        if lat and lon:
            try:
                m = folium.Map(location=[float(lat), float(lon)], zoom_start=9, tiles="CartoDB dark_matter")
                folium.Marker([float(lat), float(lon)], icon=folium.Icon(color="red", icon="crosshairs", prefix='fa')).add_to(m)
                st_folium(m, height=250, use_container_width=True)
            except: st.error("Map Error")

    with st.expander("🐞 Raw API Data"):
        st.json(proxy_data)

else:
    st.markdown("""
    <div style='text-align: center; padding-top: 50px;'>
        <h1 style='font-size: 60px;'>🛡️</h1>
        <h1>Trust-IP Intelligence</h1>
        <br>
        <div style='background-color: #262730; padding: 20px; border-radius: 10px; border: 1px solid #4F4F4F; display: inline-block; text-align: left;'>
            <h3>🚀 How to start?</h3>
            <p>1. Enter an <b>IP Address</b> in the sidebar on the left.</p>
            <p>2. Hit <b>ENTER</b> or click <b>Analyze IP</b>.</p>
            <p>3. Get real-time intelligence from multiple global threat feeds.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)



