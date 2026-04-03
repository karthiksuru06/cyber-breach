# 🚀 Quick Start Guide - Cyber Guard AI v3.0

## ✅ Pre-Flight Checklist

Your project is **fully sanitized and ready to run!**

- ✅ No sensitive data
- ✅ No real phishing URLs
- ✅ No bank screenshots
- ✅ Clean dataset (30 fictional URLs)
- ✅ All AI models present

---

## 📦 Installation (First Time)

### Step 1: Verify Python Installation
```bash
python --version
# Should be Python 3.10 or higher
```

### Step 2: Create Virtual Environment (if not exists)
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

**Note:** This may take 5-10 minutes depending on your internet speed (TensorFlow is large).

---

## 🏃 Running the Application

### Option 1: Direct Python
```bash
# Activate virtual environment first
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# Run the application
python run.py
```

### Option 2: Create a Launch Script

**Windows - Create `run_app.bat`:**
```batch
@echo off
call .venv\Scripts\activate
python run.py
pause
```

**Linux/Mac - Create `run_app.sh`:**
```bash
#!/bin/bash
source .venv/bin/activate
python run.py
```

Then simply double-click the script to launch!

---

## 🌐 Accessing the Application

Once running, you'll see:
```
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.x.x:5000
```

**Open your browser and navigate to:**
```
http://localhost:5000
```

---

## 🧪 Testing the Application

### Test URL Analysis
1. Enter a URL in the "URL INTELLIGENCE" card
2. Try these examples:
   - `https://google.com` → Should return **SAFE** (whitelisted)
   - `fake-login-example2.tk` → Should return **MALICIOUS** (in dataset)
   - `phish-example-fake1.xyz` → Should return **MALICIOUS/PHISHING**

### Test Image Analysis
1. Upload a screenshot (PNG/JPG) in the "VISUAL ANOMALY" card
2. The AI will analyze it for phishing patterns
3. View the heatmap showing suspicious regions

### View Threat Feed
- Scroll down to see the live threat feed
- All analyses are logged in real-time
- Database is stored in `instance/threat_logs.db`

---

## 🔧 Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'flask'"
**Solution:** Activate virtual environment and install dependencies
```bash
.venv\Scripts\activate  # or source .venv/bin/activate
pip install -r requirements.txt
```

### Issue: "Port 5000 already in use"
**Solution:** Change port in `run.py`
```python
if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Change to any available port
```

### Issue: "Model file not found"
**Solution:** Ensure `models/` folder contains:
- `url_lstm_v1.h5`
- `img_autoencoder_v1.h5`
- `tokenizer.pkl`

### Issue: "WHOIS timeout"
**Solution:** The app works fine even if WHOIS fails. It will fall back to neural analysis.

---

## 📊 Project Structure

```
cyber-guard-ai/
├── run.py                  # ← Start here
├── requirements.txt        # Dependencies
├── app/                    # Application code
│   ├── routes/            # Web routes
│   ├── ai_engine/         # Neural models
│   └── utils/             # Helper functions
├── models/                # Pre-trained AI models
├── templates/             # HTML interface
├── static/                # CSS and uploads
└── data/                  # Dataset (sanitized)
```

---

## 🎯 What to Show Your Client

### Demo Flow:
1. **Launch the app** → Show the futuristic UI
2. **Test a safe URL** (google.com) → Show whitelist protection
3. **Test a malicious URL** from dataset → Show threat detection
4. **Upload a screenshot** → Show visual phishing detection
5. **Show the threat feed** → Demonstrate real-time logging

### Key Features to Highlight:
- ✨ **Multi-layered AI** (Whitelist → Reputation → Neural)
- ✨ **LSTM for URL analysis** (character-level deep learning)
- ✨ **Autoencoder for visual detection** (anomaly detection)
- ✨ **Live threat intelligence** feed
- ✨ **Forensic analysis** with heatmaps and feature attribution
- ✨ **Production-ready** architecture

---

## 🔐 Security Notes

### This Version is Safe Because:
- ✅ Dataset contains only 30 fictional URLs
- ✅ No real phishing sites or bank references
- ✅ No screenshots of actual spoofed websites
- ✅ Uploads are temporary and auto-cleaned
- ✅ Database stores only analysis results

### Before Production Deployment:
- ⚠️ Add authentication (JWT/OAuth)
- ⚠️ Implement rate limiting
- ⚠️ Enable HTTPS/TLS
- ⚠️ Use production WSGI server (Gunicorn/uWSGI)
- ⚠️ Integrate real threat intelligence feeds

---

## 📞 Support

If you encounter any issues:

1. **Check this guide** for common solutions
2. **Review README.md** for detailed documentation
3. **Check SECURITY_SANITIZATION_REPORT.md** for data safety info
4. **Run verification script:** `bash verify_project_clean.sh`

---

## 🎉 You're All Set!

Your Cyber Guard AI application is:
- ✅ **Clean** and sanitized
- ✅ **Ready** to run
- ✅ **Safe** to demonstrate
- ✅ **Professional** and production-quality

**Just run `python run.py` and enjoy!** 🚀

---

*Last Updated: 2026-02-18*
*Version: 3.0 (Fully Sanitized Edition)*
