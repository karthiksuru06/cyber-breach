
import os
import pickle
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from PIL import Image

def validate_system():
    print("\n==============================================")
    print("   CYBER GUARD AI - SYSTEM INTEGRITY TEST")
    print("==============================================\n")
    
    # 1. Load Resources
    print("[INIT] Loading Neural Engines...")
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        url_model_path = os.path.join(base_dir, 'url_lstm_v1.h5')
        img_model_path = os.path.join(base_dir, 'img_autoencoder_v1.h5')
        tokenizer_path = os.path.join(base_dir, 'tokenizer.pkl')

        url_model = load_model(url_model_path, compile=False)
        img_model = load_model(img_model_path, compile=False)
        with open(tokenizer_path, 'rb') as handle:
            tokenizer = pickle.load(handle)
        print("[OK] Models & Tokenizer Online.\n")
    except Exception as e:
        print(f"[FAIL] Critical Resource Missing: {e}")
        return

    # 2. URL UNIT TESTS
    print("--- SEQUENCE ANALYSIS TESTS (LSTM) ---")
    
    test_suite_urls = [
        # (URL, Expected Class)
        ("https://www.google.com", "Safe"),
        ("https://stackoverflow.com", "Safe"),
        ("http://secure-login-attempt-verify.com", "Malicious"), # Keyword stuffing
        ("http://example.com/login.php?id=1 OR 1=1", "Malicious"), # SQL Injection Pattern
        ("http://bank-of-america-update.net", "Malicious") # Typosquatting
    ]

    padding_len = 200
    
    for url, expected in test_suite_urls:
        seq = tokenizer.texts_to_sequences([url])
        pad = pad_sequences(seq, maxlen=padding_len)
        score = url_model.predict(pad, verbose=0)[0][0]
        result = "Malicious" if score > 0.5 else "Safe"
        
        status = "PASS" if result == expected else "FAIL"
        print(f"[{status}] Inputs: {url[:30]}... | Pred: {result} ({score:.4f})")


    # 3. VISUAL ANOMALY TESTS
    print("\n--- VISUAL ANOMALY TESTS (AUTOENCODER) ---")
    
    img_tests = [
        ("test_data/test_legit_cv.png", "Legitimate (Low MSE)"),
        ("test_data/test_phish_cv.png", "Phishing (High MSE)")
    ]
    
    threshold = 0.018 # New Strict Threshold

    for img_path, expected_desc in img_tests:
        if not os.path.exists(img_path):
            print(f"[SKIP] {img_path} not found. Run generate_test_images.py first.")
            continue
            
        try:
            # Matches app.py logic
            img = Image.open(img_path).convert('RGB')
            img = img.resize((128, 128))
            arr = np.array(img).astype('float32') / 255.0
            arr = np.expand_dims(arr, axis=0) # (1, 128, 128, 3)
            
            recon = img_model.predict(arr, verbose=0)
            mse = np.mean(np.power(arr - recon, 2))
            
            is_anomaly = mse > threshold
            res_str = "PHISHING" if is_anomaly else "LEGITIMATE"
            
            # Simple soft assertion for display
            expected_type = "PHISHING" if "Phishing" in expected_desc else "LEGITIMATE"
            status = "PASS" if res_str == expected_type else "WARN"
            
            print(f"[{status}] File: {os.path.basename(img_path)}")
            print(f"       MSE: {mse:.5f} (Threshold: {threshold})")
            print(f"       Result: {res_str}")
            
        except Exception as e:
            print(f"[ERR] Processing {img_path}: {e}")

    print("\n==============================================")
    print("   TEST SEQUENCE COMPLETE")
    print("==============================================")

if __name__ == "__main__":
    validate_system()
