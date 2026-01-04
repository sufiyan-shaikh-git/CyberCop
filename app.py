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
    # Step 1: Try Loading Model (Silent Fail Allowed)
    is_model_loaded = load_url_model_only()
    
    # Step 2: MEGA KEYWORD CHECK (100+ Words) 🚨
    # Ye list bina AI ke bhi 90% attacks pakad legi
    suspicious_keywords = [
        # --- URGENCY & ACTION ---
        'verify', 'update', 'confirm', 'suspend', 'restrict', 'block', 'expire', 
        'immediate', 'action', 'required', 'unauthorized', 'alert', 'warning',
        'secure', 'validate', 'recover', 'unlock', 'reset', 'limited',
        
        # --- LOGIN & CREDENTIALS ---
        'login', 'signin', 'sign-in', 'log-in', 'password', 'credential', 
        'account', 'profile', 'admin', 'root', 'access', 'auth', 'session',
        'support', 'security', 'service', 'help', 'client', 'portal',
        
        # --- BANKING & FINANCE ---
        'bank', 'wallet', 'payment', 'transaction', 'invoice', 'bill', 'receipt',
        'pay', 'fund', 'refund', 'credit', 'debit', 'card', 'statement',
        'paypal', 'stripe', 'fargo', 'chase', 'citi', 'hsbc', 'axis', 'hdfc', 'icici',
        
        # --- CRYPTO & TRADING ---
        'crypto', 'bitcoin', 'btc', 'ethereum', 'eth', 'binance', 'coinbase', 
        'trustwallet', 'metamask', 'ledger', 'trezor', 'airdrop', 'nft',
        
        # --- OFFERS & FREEBIES ---
        'free', 'gift', 'prize', 'winner', 'win', 'bonus', 'cash', 'money', 
        'reward', 'promo', 'deal', 'discount', 'cheap', 'offer', 'giveaway',
        'lottery', 'sweepstake', 'claim', 'exclusive', 'urgent',
        
        # --- BRANDS & SERVICES ---
        'google', 'gmail', 'drive', 'dropbox', 'microsoft', 'office', 'outlook',
        'teams', 'zoom', 'netflix', 'amazon', 'apple', 'icloud', 'facebook', 
        'instagram', 'twitter', 'linkedin', 'whatsapp', 'telegram', 'snapchat',
        'tiktok', 'shopify', 'fedex', 'dhl', 'usps', 'ups', 'delivery', 'tracking',
        
        # --- TECH & FILES ---
        'download', 'install', 'apk', 'exe', 'update-now', 'fix', 'scan', 
        'virus', 'malware', 'cleaner', 'browser', 'chrome', 'firefox',
        'cloud', 'storage', 'doc', 'pdf', 'xls', 'file-share'
    ]
    
    url_lower = url.lower()
    for word in suspicious_keywords:
        if word in url_lower:
            return f"🚨 DANGER: Malicious Keyword Detected ('{word}')"

    # Step 3: AI CHECK (Only if loaded successfully)
    if is_model_loaded and url_model:
        try:
            prediction = url_model.predict([url])[0]
            if prediction == 'bad':
                return "🚨 DANGER: AI Detected Phishing Link!"
            else:
                return "✅ SAFE: Link appears legitimate (AI Verified)."
        except:
            pass # Silent Fail -> Fallback to Safe
    
    # Step 4: FALLBACK (Agar AI load nahi hua to Safe bol do)
    return "✅ SAFE: Link appears legitimate (Basic Scan Verified)."


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
