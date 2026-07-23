# DeshGarv - Secure Online Voting Portal with Facial Recognition

DeshGarv is a web-based, secure online voting portal built to enable citizens to cast their votes from the comfort of their homes. To ensure election integrity and security, the application integrates a two-factor Aadhaar OTP check and a real-time computer vision-based facial verification module. 

The application is styled with an Election Commission of India (ECI) theme and is designed with extensive accessibility controls, including translation, font scaling, high contrast, and automated Text-to-Speech (TTS) voter guidance.

---

## Key Features

- **2-Factor Authentication:** Aadhaar lookup integrated with a simulated SMS gateway OTP verification code.
- **AI Face Match Scan:** Real-time webcam check comparing the voter against their Aadhaar registry photo utilizing the **DeepFace** library.
- **Coercion & Impersonation Prevention:** Facial checking thread automatically disables matches and flags a warning if multiple faces are detected in the webcam frame.
- **Ballot Secrecy & Cybersecurity:** Complete decoupling between voter identities and candidate choices. Cast ballots are recorded with custom SHA-256 integrity hashes.
- **Accessibility Suite:** Native browser-based Speech Synthesis (Text-to-Speech) for visually impaired voters, text zoom resizing controls, high contrast mode, and multi-language translation.
- **Real-Time Results Dashboard:** Real-time vote totals rendered dynamically using **Chart.js**, paired with a public participant ledger.

---

## Prerequisites

- **Python:** Version 3.8 to 3.11 is recommended.
- **Hardware:** A functional web camera (for facial recognition verification).
- **Internet Connection:** Required on the first run to download the default deepface model weights (VGG-Face).

---

## Installation & Setup

Follow these steps to run the application locally:

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

### 2. Set Up a Virtual Environment (Optional but Recommended)
On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```
On macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
Install all required libraries listed in `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## Operating the System

### 1. Start the Flask Server
Run the Flask server from the repository root:
```bash
python app.py
```
On start, the application will initialize a local SQLite database file (`evoting.db`) and seed standard test records automatically.

### 2. Access the Portal
Open your web browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## How to Test (Step-by-Step Scenarios)

The local database is seeded with mock voter credentials for demonstration. Use the scenarios below to verify system features:

### Scenario A: Successful Verification (Test Face Recognition)
1. **Aadhaar Number:** `123456789012` (Registered name: *Samarth Kapoor*).
2. Click **Send OTP**.
3. A success banner will display containing the simulated 6-digit OTP code (e.g. `123456` or similar). Enter this code and click **Verify OTP**.
4. The system will activate your webcam. Sit in front of your camera. 
5. The system compares your face against `static/reference.jpg`. Once the frame text changes to green **"MATCH!"**, the **Proceed to Vote** button will unlock. Click it.
6. Hover over the candidate tiles on the ballot sheet to hear the names read aloud. Click **Vote**, confirm in the modal, and download your **E-Receipt** text file containing the SHA-256 voting hash.

### Scenario B: Double Voting Prevention
1. **Aadhaar Number:** `444455556666` (Registered name: *Aarav Sharma*).
2. Click **Send OTP**.
3. The system blocks the login showing a warning: *"This citizen has already cast their vote."*

### Scenario C: Multi-Face Coercion Block
1. Log in as Samarth Kapoor (Scenario A).
2. During the face match step, have a second person stand in the camera frame, or show a face photo.
3. The video stream will flag: **"NO MATCH! ONLY 1 PERSON ALLOWED"** and lock the Proceed button, demonstrating anti-coercion security.

### Scenario D: Real-Time Results Board
1. Click **Election Results** in the top navigation bar or go directly to [http://127.0.0.1:5000/results](http://127.0.0.1:5000/results).
2. Toggle the dropdown between constituencies ("New Delhi" or "Mumbai South") to view voting charts and verify timestamps in the public ledger.

---

## File Structure

```
├── app.py                  # Core Flask server and API routing logic
├── camera.py               # Real-time CV2/DeepFace camera recognition thread
├── evoting.db              # SQLite Database (auto-generated on launch)
├── requirements.txt        # Python package dependencies
├── static/                 # Folder containing JS scripts, CSS styles, and graphics
│   ├── styles.css          # Core stylesheet containing layout and theme classes
│   ├── homepage.js         # Navigation, accessibility, and OTP UI scripts
│   ├── reference.jpg       # Facial template used to match test voter (Samarth)
│   └── (ECI image files)   # Visual logos, backgrounds, and app banner assets
└── templates/              # HTML layout templates
    ├── index.html          # Main voter registration / verification homepage
    ├── voting.html         # Candidate ballot selection sheet
    └── results.html        # Public audit log and standings dashboard
```
