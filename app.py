from flask import Flask, render_template, Response, request, jsonify, session, redirect
from camera import FaceRecognitionCamera
import time
import os
import sqlite3
import random
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = "DESHGARV_E_VOTING_SECRET_KEY_2026"

DATABASE = 'evoting.db'
camera = None

def get_camera():
    global camera
    if camera is None:
        camera = FaceRecognitionCamera()
    return camera

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    # Create voters table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS voters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aadhaar TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            constituency TEXT NOT NULL,
            reference_photo TEXT NOT NULL,
            has_voted INTEGER DEFAULT 0,
            otp TEXT,
            vote_timestamp TEXT
        )
    ''')
    # Create candidates table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            party TEXT NOT NULL,
            logo TEXT,
            constituency TEXT NOT NULL,
            votes INTEGER DEFAULT 0
        )
    ''')
    # Create encrypted votes logs (for audit log transparency)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS votes_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_hash TEXT NOT NULL,
            constituency TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()

    # Seed voters
    cursor.execute("SELECT COUNT(*) FROM voters")
    if cursor.fetchone()[0] == 0:
        voters_data = [
            # The test voter (Samarth Kapoor) will map to reference.jpg in static folder
            ('123456789012', 'Samarth Kapoor', '9876543210', 'New Delhi', 'static/reference.jpg', 0),
            # Already voted voter (to test block)
            ('444455556666', 'Aarav Sharma', '8877665544', 'New Delhi', 'static/reference.jpg', 1),
            # Another dummy voter
            ('111122223333', 'Vipul Mehta', '9988776655', 'Mumbai South', 'static/reference2.jpg', 0)
        ]
        cursor.executemany('''
            INSERT INTO voters (aadhaar, name, phone, constituency, reference_photo, has_voted)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', voters_data)
        conn.commit()

    # Ensure reference2.jpg exists on startup (for Vipul Mehta)
    import shutil
    current_dir = os.path.dirname(os.path.abspath(__file__))
    ref_jpg = os.path.join(current_dir, 'static', 'reference2.jpg')
    ref_jpeg = os.path.join(current_dir, 'static', 'reference2.jpeg')
    ref_default = os.path.join(current_dir, 'static', 'reference.jpg')
    
    if not os.path.exists(ref_jpg):
        if os.path.exists(ref_jpeg):
            shutil.copy(ref_jpeg, ref_jpg)
            print("Copied reference2.jpeg to reference2.jpg successfully.")
        elif os.path.exists(ref_default):
            shutil.copy(ref_default, ref_jpg)
            print("Copied reference.jpg to reference2.jpg successfully.")

    # Seed candidates
    cursor.execute("SELECT COUNT(*) FROM candidates")
    if cursor.fetchone()[0] == 0:
        candidates_data = [
            # Candidates for New Delhi
            ('Rahul Sharma', 'Bharatiya Janata Party (BJP)', 'lotus', 'New Delhi'),
            ('Priya Patel', 'Indian National Congress (INC)', 'hand', 'New Delhi'),
            ('Amit Singh', 'Aam Aadmi Party (AAP)', 'broom', 'New Delhi'),
            ('None of the Above (NOTA)', 'NOTA', 'nota', 'New Delhi'),
            # Candidates for Mumbai South
            ('Vikram Rao', 'Bharatiya Janata Party (BJP)', 'lotus', 'Mumbai South'),
            ('Sanjay Dutt', 'Indian National Congress (INC)', 'hand', 'Mumbai South'),
            ('Anjali Menon', 'Independent', 'ind', 'Mumbai South'),
            ('None of the Above (NOTA)', 'NOTA', 'nota', 'Mumbai South')
        ]
        cursor.executemany('''
            INSERT INTO candidates (name, party, logo, constituency)
            VALUES (?, ?, ?, ?)
        ''', candidates_data)
        conn.commit()

    conn.close()

# Initialize DB on startup
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify')
def verify():
    return render_template('verify.html')

# Admin credentials (hardcoded for demo)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

@app.route('/admin')
def admin_login_page():
    if session.get('admin_logged_in'):
        return redirect('/results')
    return render_template('admin.html')

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return jsonify({"success": True, "message": "Login successful."})
    else:
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect('/')

# Ensure uploads directory exists
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_CONSTITUENCIES = ['New Delhi', 'Mumbai South']

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_voter():
    name = request.form.get('name', '').strip()
    aadhaar = request.form.get('aadhaar', '').strip()
    phone = request.form.get('phone', '').strip()
    constituency = request.form.get('constituency', '').strip()
    photo = request.files.get('photo')

    # Validate inputs
    if not name or len(name) < 2:
        return jsonify({"success": False, "message": "Please enter a valid name."}), 400
    if not aadhaar or len(aadhaar) != 12 or not aadhaar.isdigit():
        return jsonify({"success": False, "message": "Invalid Aadhaar number. Must be exactly 12 digits."}), 400
    if not phone or len(phone) != 10 or not phone.isdigit():
        return jsonify({"success": False, "message": "Invalid phone number. Must be exactly 10 digits."}), 400
    if constituency not in ALLOWED_CONSTITUENCIES:
        return jsonify({"success": False, "message": "Invalid constituency selection."}), 400
    if not photo:
        return jsonify({"success": False, "message": "Please upload a reference face photo."}), 400

    # Check file extension
    allowed_extensions = {'jpg', 'jpeg', 'png'}
    filename = photo.filename
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in allowed_extensions:
        return jsonify({"success": False, "message": "Photo must be a JPG or PNG file."}), 400

    # Check for duplicate Aadhaar
    conn = get_db_connection()
    existing = conn.execute("SELECT aadhaar FROM voters WHERE aadhaar = ?", (aadhaar,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"success": False, "message": "This Aadhaar number is already registered."}), 409

    # Save the photo with a unique name
    import uuid
    safe_filename = f"voter_{aadhaar}_{uuid.uuid4().hex[:8]}.{ext}"
    photo_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    photo.save(photo_path)

    # Store relative path for the database (relative to project root)
    db_photo_path = f"static/uploads/{safe_filename}"

    # Insert into database
    conn.execute(
        "INSERT INTO voters (aadhaar, name, phone, constituency, reference_photo, has_voted) VALUES (?, ?, ?, ?, ?, 0)",
        (aadhaar, name, phone, constituency, db_photo_path)
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"Voter {name} registered successfully."})

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    aadhaar = data.get('aadhaar')
    
    if not aadhaar or len(aadhaar) != 12 or not aadhaar.isdigit():
        return jsonify({"success": False, "message": "Invalid Aadhaar number format."}), 400
        
    conn = get_db_connection()
    voter = conn.execute("SELECT id, name, has_voted FROM voters WHERE aadhaar = ?", (aadhaar,)).fetchone()
    
    if not voter:
        conn.close()
        return jsonify({"success": False, "message": "Aadhaar number not registered."}), 404
        
    if voter['has_voted'] == 1:
        conn.close()
        return jsonify({"success": False, "message": "This citizen has already cast their vote."}), 400
        
    # Generate random 6 digit OTP
    otp = str(random.randint(100000, 999999))
    conn.execute("UPDATE voters SET otp = ? WHERE aadhaar = ?", (otp, aadhaar))
    conn.commit()
    conn.close()
    
    # Print to console for server logs audit and test visibility
    print(f"\n[SMS GATEWAY] OTP sent to registered mobile for Aadhaar {aadhaar}: {otp}\n")
    
    return jsonify({
        "success": True,
        "message": "OTP sent successfully to registered mobile number.",
        "otp": otp # Returning the OTP in JSON for convenient local testing
    })

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    aadhaar = data.get('aadhaar')
    otp = data.get('otp')
    
    if not aadhaar or not otp:
        return jsonify({"success": False, "message": "Aadhaar and OTP are required."}), 400
        
    conn = get_db_connection()
    voter = conn.execute("SELECT * FROM voters WHERE aadhaar = ?", (aadhaar,)).fetchone()
    
    if not voter:
        conn.close()
        return jsonify({"success": False, "message": "Voter lookup error."}), 404
        
    if voter['otp'] != otp:
        conn.close()
        return jsonify({"success": False, "message": "Incorrect OTP entered. Please try again."}), 400
        
    # OTP verified! Seed the camera reference image dynamically
    current_dir = os.path.dirname(os.path.abspath(__file__))
    full_photo_path = os.path.join(current_dir, voter['reference_photo'])
    
    camera_instance = get_camera()
    camera_instance.set_reference_image(full_photo_path)
    
    # Set Flask session
    session['voter_id'] = voter['id']
    session['voter_name'] = voter['name']
    session['voter_aadhaar'] = voter['aadhaar']
    session['constituency'] = voter['constituency']
    
    conn.close()
    return jsonify({"success": True, "message": "OTP verified successfully. Camera feed enabled."})

@app.route('/check_face')
def check_face():
    # Return match status from the camera
    camera_instance = get_camera()
    with camera_instance.lock:
        match = camera_instance.face_match
        multiple = camera_instance.multiple_faces
        
    # Safety feature: match is only true if multiple_faces is false and face matches
    return jsonify({
        "match": match,
        "multiple_faces": multiple
    })

def gen(camera_instance):
    while True:
        frame = camera_instance.get_frame()
        if frame is not None:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')
        else:
            time.sleep(0.1)

@app.route('/video_feed')
def video_feed():
    return Response(gen(get_camera()),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/voting-page')
def voting_page():
    if 'voter_id' not in session:
        return redirect('/')
    return render_template('voting.html')

@app.route('/voter_details')
def voter_details():
    if 'voter_id' not in session:
        return jsonify({"success": False, "message": "Unauthorized access."}), 401
        
    conn = get_db_connection()
    voter = conn.execute("SELECT name, constituency, aadhaar FROM voters WHERE id = ?", (session['voter_id'],)).fetchone()
    
    if not voter:
        conn.close()
        return jsonify({"success": False, "message": "Voter profile not found."}), 404
        
    candidates = conn.execute("SELECT id, name, party, logo FROM candidates WHERE constituency = ?", (voter['constituency'],)).fetchall()
    conn.close()
    
    candidates_list = []
    for cand in candidates:
        candidates_list.append({
            "id": cand["id"],
            "name": cand["name"],
            "party": cand["party"],
            "logo": cand["logo"]
        })
        
    return jsonify({
        "success": True,
        "voter": {
            "name": voter["name"],
            "constituency": voter["constituency"],
            "aadhaar": f"XXXX-XXXX-{voter['aadhaar'][-4:]}"
        },
        "candidates": candidates_list
    })

@app.route('/cast_vote', methods=['POST'])
def cast_vote():
    if 'voter_id' not in session:
        return jsonify({"success": False, "message": "Unauthorized access."}), 401
        
    data = request.get_json()
    candidate_id = data.get('candidate_id')
    
    if not candidate_id:
        return jsonify({"success": False, "message": "No candidate selected."}), 400
        
    conn = get_db_connection()
    voter = conn.execute("SELECT has_voted, constituency, aadhaar, name FROM voters WHERE id = ?", (session['voter_id'],)).fetchone()
    
    if not voter:
        conn.close()
        return jsonify({"success": False, "message": "Voter profile error."}), 404
        
    if voter['has_voted'] == 1:
        conn.close()
        return jsonify({"success": False, "message": "Double voting error: Vote already cast."}), 400
        
    candidate = conn.execute("SELECT id, name, constituency FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
    if not candidate or candidate['constituency'] != voter['constituency']:
        conn.close()
        return jsonify({"success": False, "message": "Invalid candidate selected for your constituency."}), 400
        
    # Cast vote process
    # 1. Update candidate vote count
    conn.execute("UPDATE candidates SET votes = votes + 1 WHERE id = ?", (candidate_id,))
    
    # 2. Mark voter as voted
    timestamp = datetime.now().isoformat()
    conn.execute("UPDATE voters SET has_voted = 1, vote_timestamp = ? WHERE id = ?", (timestamp, session['voter_id']))
    
    # 3. Create cryptographically secure audit hash
    salt = "DESHGARV_CYBERSEC_SALT_2026"
    vote_string = f"{candidate['name']}_{candidate['constituency']}_{timestamp}_{salt}"
    vote_hash = hashlib.sha256(vote_string.encode('utf-8')).hexdigest()
    
    conn.execute("INSERT INTO votes_audit (encrypted_hash, constituency, timestamp) VALUES (?, ?, ?)",
                 (vote_hash, voter['constituency'], timestamp))
                 
    conn.commit()
    conn.close()
    
    # Reset camera matching reference photo to clear resources
    camera_instance = get_camera()
    camera_instance.set_reference_image("")
    
    # Clear session values
    session.clear()
    
    return jsonify({
        "success": True,
        "message": "Vote cast successfully and logged with SHA-256 integrity hash.",
        "audit_hash": vote_hash
    })

@app.route('/results')
def results():
    if not session.get('admin_logged_in'):
        return redirect('/admin')
    return render_template('results.html')

@app.route('/results_data')
def results_data():
    if not session.get('admin_logged_in'):
        return jsonify({"success": False, "message": "Unauthorized."}), 401
    conn = get_db_connection()
    candidates = conn.execute("SELECT name, party, votes, constituency FROM candidates").fetchall()
    voters = conn.execute("SELECT name, constituency, vote_timestamp, aadhaar FROM voters WHERE has_voted = 1").fetchall()
    total_registered = conn.execute("SELECT COUNT(*) FROM voters").fetchone()[0]
    conn.close()
    
    candidates_list = []
    for cand in candidates:
        candidates_list.append({
            "name": cand["name"],
            "party": cand["party"],
            "votes": cand["votes"],
            "constituency": cand["constituency"]
        })
        
    voters_list = []
    for voter in voters:
        masked_aadhaar = f"XXXX-XXXX-{voter['aadhaar'][-4:]}"
        masked_name = voter['name'][0] + "*" * (len(voter['name']) - 2) + voter['name'][-1] if len(voter['name']) > 2 else voter['name']
        voters_list.append({
            "name": masked_name,
            "aadhaar": masked_aadhaar,
            "constituency": voter["constituency"],
            "timestamp": voter["vote_timestamp"]
        })
        
    return jsonify({
        "success": True,
        "candidates": candidates_list,
        "voters": voters_list,
        "total_registered": total_registered
    })

@app.route('/stop_camera', methods=['POST'])
def stop_camera():
    global camera
    if camera is not None:
        camera.set_reference_image("")
    return jsonify({"success": True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
