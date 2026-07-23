import threading
import cv2
from deepface import DeepFace
import time
import os

class FaceRecognitionCamera:
    def __init__(self):
        self.video = cv2.VideoCapture(0)
        self.video.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        self.video.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        
        # Initialize reference image as None initially
        self.reference_img = None
        
        # Initialize face detection
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        
        # Initialize variables for face matching
        self.face_match = False
        self.lock = threading.Lock()
        self.running = True
        self.multiple_faces = False
        
        # Start face recognition thread
        self.thread = threading.Thread(target=self.check_face)
        self.thread.daemon = True
        self.thread.start()
    
    def __del__(self):
        self.running = False
        if self.video.isOpened():
            self.video.release()
    
    def set_reference_image(self, image_path):
        with self.lock:
            if os.path.exists(image_path):
                self.reference_img = cv2.imread(image_path)
                print(f"Successfully loaded reference image from {image_path}")
            else:
                self.reference_img = None
                print(f"Reference image file not found: {image_path}")
            self.face_match = False
            self.multiple_faces = False

    def check_face(self):
        while self.running:
            success, frame = self.video.read()
            if not success:
                continue
                
            # Convert frame to grayscale for face detection
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self.face_cascade.detectMultiScale(gray_frame, scaleFactor=1.1, minNeighbors=4, minSize=(30, 30))
            
            with self.lock:
                if len(faces) > 1:
                    self.multiple_faces = True
                    self.face_match = False
                else:
                    # Let the DeepFace detector handle single/no-face cases from Haar Cascade
                    self.multiple_faces = False
                    if self.reference_img is not None:
                        try:
                            # Use VGG-Face model with opencv detector backend and enforce_detection=False
                            result = DeepFace.verify(
                                frame, 
                                self.reference_img.copy(), 
                                model_name='VGG-Face',
                                detector_backend='opencv',
                                enforce_detection=False
                            )
                            # Apply a tuned threshold of 0.55 to prevent false matches with family members
                            distance = result.get('distance', 1.0)
                            self.face_match = distance <= 0.55
                        except Exception as e:
                            print(f"DeepFace verify exception: {e}")
                            self.face_match = False
                    else:
                        self.face_match = False
                    
            time.sleep(0.1)  # Slight delay to prevent overloading
    
    def get_frame(self):
        success, frame = self.video.read()
        if not success:
            return None
            
        # Add match status text to the frame
        with self.lock:
            if self.reference_img is None:
                cv2.putText(frame, "AWAITING AADHAAR LOGIN...", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 0), 2)
            elif self.multiple_faces:
                cv2.putText(frame, "NO MATCH! ONLY 1 PERSON ALLOWED", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 255), 2)
            elif self.face_match:
                cv2.putText(frame, "MATCH!", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 2, (0, 255, 0), 3)
            else:
                cv2.putText(frame, "NO MATCH!", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 2, (0, 0, 255), 3)
        
        # Encode the frame as JPEG
        ret, jpeg = cv2.imencode('.jpg', frame)
        return jpeg.tobytes()
