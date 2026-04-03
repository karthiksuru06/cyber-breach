from fpdf import FPDF
import qrcode
import os
from PIL import Image

class CyberGuidePDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.primary_color = (10, 25, 47)      # Dark Navy
        self.accent_color = (100, 255, 218)     # Cyber Teal
        self.secondary_color = (204, 214, 246) # Light Gray
        self.muted_color = (136, 146, 176)     # Muted Gray
        self.alert_color = (240, 84, 84)       # Coral Red

    def header(self):
        if self.page_no() > 1:
            self.set_fill_color(*self.primary_color)
            self.rect(0, 0, 210, 20, 'F')
            self.set_font("helvetica", "B", 10)
            self.set_text_color(*self.accent_color)
            self.set_xy(10, 5)
            self.cell(0, 10, "CYBER GUARD AI v3.0 // Interactive Project Guide", ln=1)
            self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(*self.muted_color)
        self.cell(0, 10, f"Page {self.page_no()} | Built for Cyber Security Awareness", 0, 0, 'C')

    def add_title_page(self):
        self.add_page()
        # Background
        self.set_fill_color(*self.primary_color)
        self.rect(0, 0, 210, 297, 'F')
        
        # Techy Shapes (Simple Rects for effect)
        self.set_fill_color(*self.accent_color)
        self.rect(20, 40, 5, 20, 'F')
        self.rect(20, 240, 5, 20, 'F')
        
        # Title
        self.set_y(80)
        self.set_font("helvetica", "B", 42)
        self.set_text_color(*self.accent_color)
        self.multi_cell(180, 15, "CYBER GUARD AI\nv3.0", align='C')
        
        self.ln(10)
        self.set_font("helvetica", "I", 18)
        self.set_text_color(*self.secondary_color)
        self.multi_cell(180, 10, "The Ultimate Interactive Guide\nto Zero-Day Phishing Detection", align='C')
        
        # Tagline for 1st year guy
        self.set_y(220)
        self.set_font("helvetica", "B", 14)
        self.set_text_color(*self.accent_color)
        self.multi_cell(180, 10, "FROM SCRATCH TO MACHINE LEARNING PRO", align='C')
        
        self.set_y(240)
        self.set_font("helvetica", "", 12)
        self.set_text_color(*self.muted_color)
        self.multi_cell(180, 10, "Interactive Deep-Dive for B.Tech First Year Students", align='C')

    def add_intro_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 24)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "1. What on Earth is Phishing?", ln=1)
        self.ln(10)
        
        self.set_font("helvetica", "", 12)
        self.set_text_color(20, 20, 20)
        intro_text = (
            "Hey Future Engineer! Ever clicked a link from an 'Unknown Number' promising a free Rs 500 Amazon coupon? "
            "That's the trap. Phishing is like a digital fishing rod where hackers use 'Bait' (Fake sites) to catch your "
            "'Hook' (Usernames & Passwords).\n\n"
            "Traditional apps are slow - they only block sites that have already been reported. But what if "
            "THEY target YOU with a brand new link today? That's a 'Zero-Day' attack. \n\n"
            "This project, Cyber Guard AI, is built to catch these invisible threats using AI that 'THINKS' like a human but 'SPEEDS' like a machine."
        )
        self.multi_cell(0, 7, intro_text)
        
        # Box for "Did you Know?"
        self.ln(10)
        self.set_fill_color(*self.accent_color)
        self.set_draw_color(*self.primary_color)
        self.set_line_width(0.5)
        self.rect(self.get_x(), self.get_y(), 190, 30, 'FD')
        self.set_xy(self.get_x() + 5, self.get_y() + 5)
        self.set_font("helvetica", "B", 12)
        self.set_text_color(*self.primary_color)
        self.multi_cell(180, 5, "DID YOU KNOW?\n3.4 Billion spam emails are sent per day. Almost 90% of data breaches start with a single phishing email!")

    def add_architecture_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 20)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "2. Deep Dive: The 4-Layer Shield", ln=1)
        self.ln(5)
        
        layers = [
            ("L1: The VIP Whitelist", "Like a security guard at a high-end club. It checks if the URL is from Mega-Celebs like Google or Amazon. If yes, it's SAFE immediately! (Cost: Near Zero)"),
            ("L2: The 'Most Wanted' List", "We have a database of 210,857+ confirmed hacker sites. It's an O(1) Search (super fast!) to see if the URL is on the blacklist."),
            ("L3: WHOIS Reputation", "We check the domain's 'Birth Certificate'. Legitimate sites like 'stanford.edu' are 30+ years old. Hacker sites are often born just YESTERDAY. Older = Safer!"),
            ("L4: The Neural Super-Brain (Bi-LSTM)", "If the URL survives the first 3 layers, our AI scans every character. It reads from Start-to-End AND End-to-Start to find hidden malicious patterns.")
        ]
        
        for title, desc in layers:
            self.set_font("helvetica", "B", 14)
            self.set_text_color(*self.primary_color)
            self.cell(0, 10, title, ln=1)
            self.set_font("helvetica", "", 12)
            self.set_text_color(50, 50, 50)
            self.multi_cell(0, 6, desc)
            self.ln(5)

    def add_url_logic_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 20)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "3. Character Decoding: The Bi-LSTM", ln=1)
        self.ln(5)
        
        text = (
            "Wait, how does a computer 'read' a URL? It's all about probabilities. \n\n"
            "Imagine the word 'login'. In google.com/login, it's normal. But in secure-site-update-login-72k.com, "
            "it's suspicious! \n\n"
            "Our Bi-LSTM (Bidirectional Long Short-Term Memory) engine reads the URL in two directions:\n"
            "1. Forward: Looks at the 'Bait' (e.g., 'amaz0n...')\n"
            "2. Backward: Looks at the 'Hook' (e.g., '...xyz.tk')\n\n"
            "When these signals meet, it calculates a Confidence Score. If it's 99.9%, it's GAME OVER for the hacker!"
        )
        self.set_font("helvetica", "", 12)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 7, text)
        
        # QR Code Placeholder for "Interactive Diagram"
        self.ln(10)
        self.set_fill_color(240, 240, 240)
        self.rect(60, 180, 80, 80, 'F')
        self.set_xy(60, 215)
        self.set_font("helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.multi_cell(80, 5, "[INTERACTIVE DIAGRAM]\nBi-LSTM Information Flow", align='C')

    def add_visual_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 20)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "4. Pixel Perfect: The Image Autoencoder", ln=1)
        self.ln(5)
        
        text = (
            "Sometimes, hackers create 'Pixel-Perfect' copies of your bank's website. They look identical, but "
            "their skeleton is different. \n\n"
            "We use a Convolutional Autoencoder. It works like this:\n"
            "1. Compression: We shrink the screenshot to a tiny 128x128 thumbnail.\n"
            "2. Reconstruction: We ask the AI to 'Draw it back from memory'.\n\n"
            "If the site is REAL, the AI draws it perfectly (MSE < 0.022). If it's a FAKE, the AI gets confused - "
            "the colors are slightly off, the buttons are misaligned - and we detect it instantly!"
        )
        self.set_font("helvetica", "", 12)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 7, text)
        
        # Comparison Table
        self.ln(10)
        self.set_font("helvetica", "B", 12)
        self.set_text_color(*self.primary_color)
        self.cell(60, 10, "METRIC", 1, 0, 'C')
        self.cell(60, 10, "SAFE SITE", 1, 0, 'C')
        self.cell(60, 10, "HACKER SITE", 1, 1, 'C')
        
        self.set_font("helvetica", "", 11)
        self.cell(60, 10, "MSE (Pixel Error)", 1, 0, 'C')
        self.cell(60, 10, "LOW (<0.022)", 1, 0, 'C')
        self.set_text_color(*self.alert_color)
        self.cell(60, 10, "HIGH (>0.030)", 1, 1, 'C')
        
        self.set_text_color(20, 20, 20)
        self.cell(60, 10, "SSIM (Structure)", 1, 0, 'C')
        self.cell(60, 10, "STABLE (>0.75)", 1, 0, 'C')
        self.set_text_color(*self.alert_color)
        self.cell(60, 10, "WEAK (<0.65)", 1, 1, 'C')

    def add_math_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 20)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "5. The Math: MSE & SSIM Explained", ln=1)
        self.ln(5)
        
        self.set_font("helvetica", "B", 14)
        self.cell(0, 10, "Mean Squared Error (MSE)", ln=1)
        self.set_font("helvetica", "", 12)
        self.multi_cell(0, 7, "MSE measures the difference between every pixel in the original image and our AI's reconstruction. \nFormula: MSE = (1/N) * sum( (xi - yi)^2 )\nThink of it as the 'Blurriness Factor' - the more the AI struggles to draw it, the higher the MSE.")
        
        self.ln(5)
        self.set_font("helvetica", "B", 14)
        self.cell(0, 10, "Structural Similarity Index (SSIM)", ln=1)
        self.set_font("helvetica", "", 12)
        self.multi_cell(0, 7, "SSIM is smarter. It looks at the 'Skeleton' of the page - the boxes, the gaps, and the layout. If a hacker shifts the login button even by 10 pixels, SSIM will catch it!")

    def add_database_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 20)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "6. The Vault: 210,857 Known Threats", ln=1)
        self.ln(10)
        
        self.set_font("helvetica", "", 12)
        self.multi_cell(0, 7, "We don't always need AI. Sometimes, we already know a site is 'Bad'. Our system loads a massive CSV file containing 210,857 confirmed phishing URLs at startup.\n\n"
                               "We use a Python Dictionary to store these. This makes lookups O(1) time complexity. Whether we have 10 threats or 10 Million, the check takes the same tiny fraction of a second!")

    def add_future_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 20)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "7. The Future of Cyber Guard", ln=1)
        self.ln(10)
        
        future_ideas = [
            ("Browser Extension", "Imagine the AI living inside your Chrome or Firefox, scanning links before you even click them!"),
            ("Real-time Learning", "The system could learn from its mistakes every night, becoming smarter as hackers try new tricks."),
            ("Dark Web Scanning", "Automatically hunting for leaked credentials on the dark web and alerting users.")
        ]
        
        for idea, desc in future_ideas:
            self.set_font("helvetica", "B", 14)
            self.set_text_color(*self.primary_color)
            self.cell(0, 10, idea, ln=1)
            self.set_font("helvetica", "", 11)
            self.multi_cell(0, 6, desc)
            self.ln(5)

    def add_tech_stack_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 20)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "8. The Developer's Toolkit", ln=1)
        self.ln(10)
        
        tools = [
            ("Python", "The backbone of everything. Versatile and powerful."),
            ("Flask", "The web engine that connects our AI to the world."),
            ("TensorFlow / Keras", "The 'Brain Surgery' tools we use to build neural networks."),
            ("Pandas", "Handles our 210,000+ threat database entries in a blink.")
        ]
        
        for tool, desc in tools:
            self.set_font("helvetica", "B", 14)
            self.set_text_color(*self.primary_color)
            self.cell(0, 10, f"- {tool}", ln=1)
            self.set_font("helvetica", "", 11)
            self.set_text_color(50, 50, 50)
            self.multi_cell(0, 6, desc)
            self.ln(3)

    def add_how_to_run_page(self):
        self.add_page()
        self.set_font("helvetica", "B", 20)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, "9. Launching Your Own Cyber Shield", ln=1)
        self.ln(10)
        
        steps = [
            "1. Clone the project code to your machine.",
            "2. Install the powers: pip install -r requirements.txt",
            "3. Wake up the engine: python run.py",
            "4. Go to http://localhost:5000 in your browser.",
            "5. Login (or Sign up) and start hunting for phishing sites!"
        ]
        
        self.set_font("helvetica", "", 12)
        self.set_fill_color(240, 240, 240)
        for step in steps:
            self.cell(0, 10, step, ln=1, fill=True)
            self.ln(2)
        
        self.ln(20)
        self.set_font("helvetica", "B", 14)
        self.set_text_color(*self.primary_color)
        self.multi_cell(0, 10, "CONGRATULATIONS! You now understand how modern AI defends the internet. Welcome to the world of Cyber Security!", align='C')

def generate_pdf():
    pdf = CyberGuidePDF()
    pdf.add_title_page()
    pdf.add_intro_page()
    pdf.add_architecture_page()
    pdf.add_url_logic_page()
    pdf.add_visual_page()
    pdf.add_math_page()
    pdf.add_database_page()
    pdf.add_future_page()
    pdf.add_tech_stack_page()
    pdf.add_how_to_run_page()
    
    # Generate a QR Code for the project (Github or internal)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data("https://github.com/Antigravity/cyber-guard-ai")
    qr.make(fit=True)
    img_qr = qr.make_image(fill_color="black", back_color="white")
    img_qr.save("project_qr.png")
    
    # Output
    output_file = "CyberGuard_Project_Guide.pdf"
    pdf.output(output_file)
    print(f"PDF Generated: {output_file}")

if __name__ == "__main__":
    generate_pdf()
