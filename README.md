# 🛡️ Trust-IP Intelligence

### 🚀 Leveling Up SOC Automation

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit)
![Security](https://img.shields.io/badge/Security-SOC_Automation-green?style=for-the-badge)

**Trust-IP** is an open-source threat intelligence dashboard designed to automate the enrichment process for SOC Analysts. instead of manually checking multiple tabs (VirusTotal, AbuseIPDB, VPN checks), Trust-IP orchestrates these checks simultaneously and presents a unified risk assessment in seconds.

---

## 🎥 Demo
https://github.com/user-attachments/assets/f07d3931-f8f3-41ab-9cef-4416a9b9602f

---

## 💡 Key Features

* ⚡ **Instant Risk Assessment:** Aggregates reputation scores and historical abuse reports to determine IP risk levels in seconds.
* 🧠 **Smart Caching:** Optimizes API usage using `@st.cache_data` for faster repeated queries.
* ⚡ **Parallel Execution:** Uses `concurrent.futures` to query multiple threat feeds simultaneously.
* 🗺️ **Interactive Geolocation:** Dynamic mapping with smart fallback logic.
* 🔍 **Unified Detection Engine:** Correlates verdicts from **VirusTotal**, **AbuseIPDB**, and **Talos**.
* ☁️ **Smart Classification:** Distinguishes between legitimate Cloud infrastructure (AWS, Azure) and high-risk Anonymizers (Tor, VPN, Proxy).

---

## 🛠️ Tech Stack

* **Core:** Python 3.x
* **UI Framework:** Streamlit
* **Data Handling:** Pandas
* **APIs Integration:** Requests
* **Visualization:** PyDeck (Maps), Plotly

---

## 🚀 Getting Started

### Prerequisites

You will need API Keys for the following services (some are optional but recommended):
* VirusTotal
* AbuseIPDB
* IPinfo / VPNAPI (for detection)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YairSol/Trust-IP.git](https://github.com/YairSol/Trust-IP.git)
    cd Trust-IP
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application:**
    ```bash
    streamlit run streamlit_app.py
    ```

---

## ⚙️ Configuration

To make the APIs work, you need to set up your secrets.
Create a file named `.streamlit/secrets.toml` in the project directory and add your keys:

```toml
[api_keys]
virustotal = "YOUR_VT_KEY"
abuseipdb = "YOUR_ABUSEIPDB_KEY"
vpnapi = "YOUR_VPNAPI_KEY"
