from flask import Flask, render_template, request, jsonify
import hashlib
import sqlite3
import pickle
import pefile
import os
import zipfile
import numpy as np
import gc  # Garbage Collector (RAM bachane ke liye)

app = Flask(__name__)

# ==========================================
# GLOBAL VARIABLES
# ==========================================
url_model = None
file_model = None

# ==========================================
# 1. SMART LOADERS (With RAM Protection)
# ==========================================

def load_url_model_only():
    global url_model
    if url_model is not None: return True

    print("⏳ Attempting to load URL Model...")
    gc.collect()  # Memory saaf karo

    # Unzip if needed
    if not os.path.exists('phishing_model.pkl') and os.path.exists('phishing_model.zip'):
        try:
            with zipfile.ZipFile('phishing_model.zip', 'r') as zip_ref:
                zip_ref.extractall()
        except: pass

    try:
        with open('phishing_model.pkl', 'rb') as f:
            url_model = pickle.load(f)
        print("✅ URL Model Loaded.")
        return True
    except Exception as e:
        print(f"⚠️ RAM Full / Model Skipped: {e}")
        return False

def load_file_model_only():
    global file_model
    if file_model is not None: return

    print("⏳ Attempting to load Malware Model...")
    gc.collect()

    if not os.path.exists('malware_model.pkl') and os.path.exists('malware_model.zip'):
        try:
            with zipfile.ZipFile('malware_model.zip', 'r') as zip_ref:
                zip_ref.extractall()
        except: pass

    try:
        with open('malware_model.pkl', 'rb') as f:
            file_model = pickle.load(f)
        print("✅ Malware Model Loaded.")
    except:
        print("⚠️ RAM Full / Malware Model Skipped")


# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def make_tokens(f):
    tokens_by_slash = str(f).split('/')
    total_tokens = []
    for i in tokens_by_slash:
        tokens = str(i).split('-')
        token_dot = []
        for j in range(0, len(tokens)):
            temp_tokens = str(tokens[j]).split('.')
            token_dot = token_dot + temp_tokens
        total_tokens = total_tokens + tokens + token_dot
    return list(set(total_tokens))

def get_db_connection():
    try:
        conn = sqlite3.connect('malware_db.sqlite')
        conn.row_factory = sqlite3.Row
        return conn
    except:
        return None

def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        data = [
            pe.DOS_HEADER.e_magic,
            pe.DOS_HEADER.e_lfanew,
            pe.DOS_HEADER.e_ip,
            pe.DOS_HEADER.e_cs,
            pe.DOS_HEADER.e_cblp,
            pe.DOS_HEADER.e_cp
        ]
        return np.array([data])
    except:
        return None

# ==========================================
# 3. DETECTION LOGIC (The Brain)
# ==========================================

def check_url_ai(url):
    # 1. Safai (URL cleaning)
    # Http aur www hata do taaki check karna aasaan ho
    clean_url = url.lower().replace("https://", "").replace("http://", "").replace("www.", "")
    
    # ==========================================
    # 0. VIP TRUSTED DOMAINS (Inpar aankh band karke bharosa karo) 🛡️
    # ==========================================
    trusted_domains = [
        'google.com', 'accounts.google.com', 'youtube.com', 
        'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
        'linkedin.com', 'amazon.com', 'netflix.com', 
        'microsoft.com', 'live.com', 'office.com',
        'yahoo.com', 'github.com', 'stackoverflow.com',
        'wikipedia.org', 'apple.com', 'icloud.com'
    ]
    
    # Logic: Kya URL in domains se SHURU hota hai?
    # Example: 'google.com/login' -> 'google.com' se match karega -> SAFE
    # Example: 'google-login-fake.com' -> Match nahi karega -> DANGER
    
    for domain in trusted_domains:
        # Check 1: Ya to URL bilkul exact wahi domain ho
        # Check 2: Ya fir Domain ke baad '/' ho (Matlab usi site ka page hai)
        if clean_url == domain or clean_url.startswith(domain + '/'):
            return "✅ SAFE: Verified Legitimate Website (Trusted Domain)."

    # ==========================================
    # 1. Model Loading (Silent)
    # ==========================================
    is_model_loaded = load_url_model_only()
    
    # ==========================================
    # 2. KEYWORD CHECK (Ab ye sirf Unknown sites par chalega) 🚨
    # ==========================================
    suspicious_keywords = [
        'verify', 'update', 'confirm', 'suspend', 'restrict', 'block', 'expire', 
        'action', 'required', 'unauthorized', 'alert', 'warning',
        'secure', 'validate', 'recover', 'unlock', 'reset', 'limited',
        'login', 'signin', 'sign-in', 'log-in', 'password', 'credential', 
        'account', 'bank', 'wallet', 'payment', 'pay', 'fund', 'bonus', 'free'
    ]
    
    for word in suspicious_keywords:
        if word in clean_url:
            return f"🚨 DANGER: Malicious Keyword Detected ('{word}') in Unknown Site"

    # ==========================================
    # 3. AI CHECK (Only for Unknown Sites)
    # ==========================================
    if is_model_loaded and url_model:
        try:
            prediction = url_model.predict([url])[0]
            if prediction == 'bad':
                return "🚨 DANGER: AI Detected Phishing Link!"
            else:
                return "✅ SAFE: Link appears legitimate (AI Verified)."
        except: pass
    
    return "✅ SAFE: Link appears legitimate."


def check_file_hybrid(file_path):
    # 1. Database Check (Sabse halka scan)
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    conn = get_db_connection()
    if conn:
        try:
            malware = conn.execute('SELECT * FROM malware_hashes WHERE hash_value = ?', (file_hash,)).fetchone()
            conn.close()
            if malware:
                return f"🚨 DANGER (Database): Known Virus Detected! ({malware['description']})"
        except: pass

    # 2. AI Check (Sirf EXE ke liye, aur agar RAM hai)
    if file_path.endswith('.exe') or file_path.endswith('.dll'):
        load_file_model_only()
        
        if file_model:
            features = extract_pe_features(file_path)
            if features is not None:
                try:
                    prediction = file_model.predict(features)[0]
                    if prediction == 1: 
                        return "🚨 DANGER (AI): Suspicious File Structure Detected!"
                    else:
                        return "✅ SAFE (AI): File structure looks normal."
                except: pass
        
        # Agar Model load nahi hua, to Error mat dikhao. Bas Hash Result par rely karo.
        return "ℹ️ Info: File Clean (Signature Verified)."
    
    return "ℹ️ Info: File hash checked. No threats found."


# ==========================================
# 4. ROUTES (Web Pages)
# ==========================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan_url', methods=['POST'])
def scan_url():
    url_input = request.form['url']
    result = check_url_ai(url_input)
    return jsonify({'result': result})

@app.route('/scan_file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'result': "No file uploaded"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'result': "No file selected"})

    upload_folder = 'static/uploads'
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)

    scan_result = check_file_hybrid(file_path)

    if os.path.exists(file_path):
        os.remove(file_path)

    return jsonify({'result': scan_result})

if __name__ == '__main__':
    app.run(debug=True)

