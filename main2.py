import threading
import cv2
from deepface import DeepFace
import time

# Initialize video capture
cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

face_match = False
lock = threading.Lock()
event = threading.Event()

# Load reference image
reference_img = cv2.imread("reference.jpg")

# Flag to stop thread on exit
running = True

# Load Haar Cascade for face detection
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")

def check_face():
    global face_match
    while running:
        ret, frame = cap.read()
        if not ret:
            continue
        
        # Convert frame to grayscale for face detection
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray_frame, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

        if len(faces) == 1:  # Only one person in the frame
            try:
                # Perform face verification
                result = DeepFace.verify(frame, reference_img.copy())['verified']
                with lock:
                    face_match = result
            except ValueError:
                with lock:
                    face_match = False
        else:
            with lock:
                face_match = False  # Reset match status if multiple faces are detected
        
        event.set()  # Notify main thread that result is ready
        time.sleep(0.1)  # Slight delay to prevent overloading

# Start continuous face checking in a background thread
threading.Thread(target=check_face, daemon=True).start()

while True:
    ret, frame = cap.read()
    if not ret:
        print("Failed to grab frame. Exiting...")
        break

    # Convert frame to grayscale for face detection
    gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray_frame, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))

    # Wait for the face check to update
    if event.wait(timeout=0.05):  # Non-blocking wait
        event.clear()
    
    # Display match status or multiple-face warning
    with lock:
        if len(faces) > 1:
            cv2.putText(frame, "NO MATCH! ONLY 1 PERSON ALLOWED", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 3)
        elif face_match:
            cv2.putText(frame, "MATCH!", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 2, (0, 255, 0), 3)
        else:
            cv2.putText(frame, "NO MATCH!", (20, 450), cv2.FONT_HERSHEY_SIMPLEX, 2, (0, 0, 255), 3)

    # Display the video feed with annotations
    cv2.imshow("video", frame)

    key = cv2.waitKey(1)
    if key == ord("q"):
        break

# Clean up on exit
running = False
cap.release()
cv2.destroyAllWindows()
