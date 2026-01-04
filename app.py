from flask import Flask, render_template, request, jsonify
import hashlib
import sqlite3
import pickle
import pefile
import os
import zipfile  # Zip files kholne ke liye
import numpy as np

app = Flask(__name__)

# ==========================================
# 1. AUTO-UNZIP LOGIC (GitHub Deployment Fix)
# ==========================================
# Kyunki GitHub par 25MB limit thi, humne zip daala hai.
# Ye code server start hote hi zip khol dega.

def unzip_if_needed(model_name):
    pkl_file = model_name + '.pkl'
    zip_file = model_name + '.zip'
    
    # Agar .pkl nahi hai, par .zip hai -> To Unzip karo
    if not os.path.exists(pkl_file) and os.path.exists(zip_file):
        print(f"📂 Unzipping {zip_file}...")
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall()
        print(f"✅ {pkl_file} extracted successfully!")

# Server start hone se pehle check karo
unzip_if_needed('phishing_model')
unzip_if_needed('malware_model')


# ==========================================
# 2. HELPER FUNCTIONS (Tokenizer & Database)
# ==========================================

# URL Tokenizer (Ye Model load hone se pehle define hona zaroori hai)
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

# Database Connection Helper
def get_db_connection():
    try:
        conn = sqlite3.connect('malware_db.sqlite')
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Database Error: {e}")
        return None

# ==========================================
# 3. LOAD AI MODELS
# ==========================================

print("⏳ Loading Models...")

# (A) Phishing Model
try:
    with open('phishing_model.pkl', 'rb') as f:
        url_model = pickle.load(f)
    print("✅ Phishing Model Loaded.")
except Exception as e:
    url_model = None
    print(f"⚠️ Phishing Model Error: {e}")

# (B) Malware Model
try:
    with open('malware_model.pkl', 'rb') as f:
        file_model = pickle.load(f)
    print("✅ Malware Model Loaded.")
except Exception as e:
    file_model = None
    print(f"⚠️ Malware Model Error: {e}")


# ==========================================
# 4. FEATURE EXTRACTION (EXE Files)
# ==========================================
def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        # Wahi features jo training me use hue the
        data = [
            pe.DOS_HEADER.e_magic,
            pe.DOS_HEADER.e_lfanew,
            pe.DOS_HEADER.e_ip,
            pe.DOS_HEADER.e_cs,
            pe.DOS_HEADER.e_cblp,
            pe.DOS_HEADER.e_cp
        ]
        return np.array([data])
    except Exception as e:
        return None


# ==========================================
# 5. DETECTION LOGIC (The Brain)
# ==========================================

# --- Logic: Check URL ---
def check_url_ai(url):
    # Rule 1: Dangerous Keywords
    suspicious_keywords = ['free-money', 'hack', 'crack', 'unlimited', 'bonus', 'bank-update']
    for word in suspicious_keywords:
        if word in url.lower():
            return f"🚨 DANGER: Malicious Keyword Detected ('{word}')"

    # Rule 2: AI Prediction
    if url_model:
        try:
            prediction = url_model.predict([url])[0]
            if prediction == 'bad':
                return "🚨 DANGER: AI Detected Phishing Link!"
            else:
                return "✅ SAFE: Link appears legitimate."
        except:
            return "⚠️ Error scanning URL."
    return "⚠️ URL Model not loaded."

# --- Logic: Check File (Signature + AI) ---
def check_file_hybrid(file_path):
    # Step 1: Database Check (Signature)
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    conn = get_db_connection()
    if conn:
        malware = conn.execute('SELECT * FROM malware_hashes WHERE hash_value = ?', (file_hash,)).fetchone()
        conn.close()
        if malware:
            return f"🚨 DANGER (Database): Known Virus Detected! ({malware['description']})"

    # Step 2: AI Check (Heuristic) - Only for EXE/DLL
    if file_path.endswith('.exe') or file_path.endswith('.dll'):
        if file_model:
            features = extract_pe_features(file_path)
            if features is not None:
                prediction = file_model.predict(features)[0]
                # Note: Adjust 0/1 based on your specific training. Assuming 1 = Malware here.
                if prediction == 1: 
                    return "🚨 DANGER (AI): Suspicious File Structure Detected!"
                else:
                    return "✅ SAFE (AI): File structure looks normal."
            return "⚠️ Error reading file headers."
        return "⚠️ Malware Model not loaded."
    
    return "ℹ️ Info: Only .exe files are scanned by AI. File hash is Safe."


# ==========================================
# 6. ROUTES (Web Pages)
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

    # Save file temporarily
    upload_folder = 'static/uploads'
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    
    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)

    # Scan
    scan_result = check_file_hybrid(file_path)

    # Cleanup (Delete file after scan)
    if os.path.exists(file_path):
        os.remove(file_path)

    return jsonify({'result': scan_result})

if __name__ == '__main__':
    # Render requires port definition, but gunicorn handles it in production
    app.run(debug=True)