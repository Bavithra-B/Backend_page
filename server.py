from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS  # ✅ Enable Cross-Origin Requests
import joblib
import datetime
import bcrypt
import jwt
import os

app = Flask(__name__)

# ✅ Enable CORS (Frontend Requests)
CORS(app)

# Database Setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///track_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')  # ✅ Secure Secret Key
db = SQLAlchemy(app)

# Load ML Model
model = joblib.load("crack_detection_model.pkl")
scaler = joblib.load("scaler.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# User Model for Authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)  # ✅ Store as Bytes

# Track Data Model
class TrackStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    severity = db.Column(db.String(50), nullable=False)
    latitude = db.Column(db.String(20), nullable=False)
    longitude = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ✅ Default Route for Homepage
@app.route('/')
def home():
    return "Welcome to the Track Detection System!"  # Simple response for the homepage


# ✅ User Registration API
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # ✅ Store as bytes
    new_user = User(username=username, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# ✅ User Login API (Now with JWT Expiry)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode(
        {"username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, 
        app.config['SECRET_KEY'], 
        algorithm="HS256"
    )
    return jsonify({"message": "Login successful", "token": token}), 200

# ✅ Token Verification Function
def verify_token():
    token = request.headers.get("Authorization")
    if not token:
        return None

    try:
        token = token.split(" ")[1]  # Remove 'Bearer'
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded["username"]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ✅ API to Receive Data from Arduino
@app.route('/update', methods=['POST'])
def update_status():
    data = request.json  # ✅ Use JSON instead of form data
    if not data:
        return jsonify({"error": "Invalid data format"}), 400

    sensor_left = float(data.get('sensor_left', 0))
    sensor_right = float(data.get('sensor_right', 0))
    latitude = data.get('lat', "0")
    longitude = data.get('lon', "0")

    # Preprocess Data
    input_data = scaler.transform([[sensor_left, sensor_right]])

    # Predict Crack Severity
    severity_code = model.predict(input_data)[0]
    severity = label_encoder.inverse_transform([severity_code])[0]

    # Store in database
    new_entry = TrackStatus(severity=severity, latitude=latitude, longitude=longitude)
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({
        "severity": severity,
        "latitude": latitude,
        "longitude": longitude,
        "timestamp": new_entry.timestamp.isoformat(),
        "message": "Data received and analyzed"
    }), 200

# ✅ Get Live Track Condition (Latest Entry) - Now with Authentication
@app.route('/live_track_condition', methods=['GET'])
def live_track_condition():
    username = verify_token()
    if not username:
        return jsonify({"error": "Unauthorized"}), 403

    latest_entry = TrackStatus.query.order_by(TrackStatus.timestamp.desc()).first()
    if not latest_entry:
        return jsonify({"error": "No track data available"}), 404

    return jsonify({
        "severity": latest_entry.severity,
        "latitude": latest_entry.latitude,
        "longitude": latest_entry.longitude,
        "timestamp": latest_entry.timestamp.isoformat()
    }), 200

# Initialize Database
with app.app_context():
    db.create_all()

# Run Server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
