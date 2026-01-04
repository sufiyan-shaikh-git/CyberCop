from flask import Flask, render_template, request, jsonify
import hashlib
import sqlite3
import pickle
import pefile
import os
import zipfile
import numpy as np

app = Flask(__name__)

# ==========================================
# GLOBAL VARIABLES (Models initially None)
# ==========================================
url_model = None
file_model = None

# ==========================================
# 1. SMART SEPARATE LOADERS (RAM Saving Fix)
# ==========================================

def load_url_model_only():
    global url_model
    # Agar pehle se loaded hai to wapas mat load karo
    if url_model is not None:
        return

    print("⏳ Loading ONLY URL Model...")
    
    # Check if zip exists and unzip
    if not os.path.exists('phishing_model.pkl') and os.path.exists('phishing_model.zip'):
        try:
            with zipfile.ZipFile('phishing_model.zip', 'r') as zip_ref:
                zip_ref.extractall()
        except: pass

    try:
        with open('phishing_model.pkl', 'rb') as f:
            url_model = pickle.load(f)
        print("✅ URL Model Loaded.")
    except Exception as e:
        print(f"⚠️ URL Model Failed: {e}")

def load_file_model_only():
    global file_model
    # Agar pehle se loaded hai to wapas mat load karo
    if file_model is not None:
        return

    print("⏳ Loading ONLY Malware Model...")

    # Check if zip exists and unzip
    if not os.path.exists('malware_model.pkl') and os.path.exists('malware_model.zip'):
        try:
            with zipfile.ZipFile('malware_model.zip', 'r') as zip_ref:
                zip_ref.extractall()
        except: pass

    try:
        with open('malware_model.pkl', 'rb') as f:
            file_model = pickle.load(f)
        print("✅ Malware Model Loaded.")
    except Exception as e:
        print(f"⚠️ Malware Model Failed: {e}")


# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
# (Ye Tokenizer zaroori hai URL model ke liye)
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
# 3. DETECTION LOGIC (Targeted Loading)
# ==========================================

def check_url_ai(url):
    # SIRF URL MODEL LOAD KARO
    load_url_model_only()
    
    suspicious_keywords = ['free-money', 'hack', 'crack', 'unlimited', 'bonus', 'bank-update']
    for word in suspicious_keywords:
        if word in url.lower():
            return f"🚨 DANGER: Malicious Keyword Detected ('{word}')"

    if url_model:
        try:
            prediction = url_model.predict([url])[0]
            if prediction == 'bad':
                return "🚨 DANGER: AI Detected Phishing Link!"
            else:
                return "✅ SAFE: Link appears legitimate."
        except:
            return "⚠️ Error scanning URL."
    return "⚠️ URL Model could not load (RAM Issue)."

def check_file_hybrid(file_path):
    # DATABASE CHECK KE LIYE MODEL KI ZAROORAT NAHI
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

    # SIRF AB LOAD KARO FILE MODEL (Agar DB me nahi mila)
    if file_path.endswith('.exe') or file_path.endswith('.dll'):
        load_file_model_only() # <--- Load only here
        
        if file_model:
            features = extract_pe_features(file_path)
            if features is not None:
                prediction = file_model.predict(features)[0]
                if prediction == 1: 
                    return "🚨 DANGER (AI): Suspicious File Structure Detected!"
                else:
                    return "✅ SAFE (AI): File structure looks normal."
            return "⚠️ Error reading file headers."
        return "⚠️ Malware Model not loaded."
    
    return "ℹ️ Info: Only .exe files are scanned by AI. File hash is Safe."


# ==========================================
# 4. ROUTES
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
