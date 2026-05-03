"""
IoT Security Platform - Main Application with Advanced Features
Features: AES-256, RSA-2048, ChaCha20-Poly1305, SQLite Database, PDF Export, TTL, Logging
"""

from flask import Flask, render_template, request, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from encryption import EncryptionAlgorithms
from risk import assess_eavesdropping_risk, assess_mitm_risk, assess_bruteforce_risk
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from datetime import datetime
import time
import random
import os

app = Flask(__name__)
app.secret_key = 'iot-security-secret-key-2026'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iot_security.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

enc = EncryptionAlgorithms()
rsa_keypair = None


# ==================== DATABASE MODEL ====================
class MessageLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    from_node = db.Column(db.String(50), default='Source')
    to_node = db.Column(db.String(50), default='Destination')
    algorithm = db.Column(db.String(50))
    original_message = db.Column(db.Text)
    encrypted_message = db.Column(db.Text)
    original_size = db.Column(db.Integer)
    encrypted_size = db.Column(db.Integer)
    network_delay = db.Column(db.Float)
    ttl_seconds = db.Column(db.Integer, default=60)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'from_node': self.from_node,
            'to_node': self.to_node,
            'algorithm': self.algorithm,
            'original_message': self.original_message[:100] if self.original_message else '',
            'encrypted_message': self.encrypted_message[:100] if self.encrypted_message else '',
            'original_size': self.original_size,
            'encrypted_size': self.encrypted_size,
            'network_delay': self.network_delay
        }


# Create database tables
with app.app_context():
    db.create_all()


# ==================== HELPER FUNCTIONS ====================
def simulate_network_delay() -> float:
    """Simulate network latency for IoT communication"""
    delay = random.uniform(0.05, 0.5)
    time.sleep(delay)
    return round(delay, 3)


def log_to_database(from_node, to_node, algorithm, original, encrypted, delay, ttl=60):
    """Save message to database"""
    try:
        log = MessageLog(
            from_node=from_node,
            to_node=to_node,
            algorithm=algorithm,
            original_message=original,
            encrypted_message=encrypted,
            original_size=len(original),
            encrypted_size=len(encrypted) if encrypted else 0,
            network_delay=delay,
            ttl_seconds=ttl
        )
        db.session.add(log)
        db.session.commit()
        return True
    except Exception as e:
        print(f"Database error: {e}")
        return False


def check_ttl():
    """Check if message has expired (TTL = 60 seconds)"""
    msg_time = session.get('message_timestamp', 0)
    ttl = session.get('ttl', 60)
    if msg_time > 0 and (time.time() - msg_time) > ttl:
        return False
    return True


# ==================== ROUTES ====================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/generate_rsa', methods=['GET'])
def generate_rsa():
    global rsa_keypair
    rsa_keypair = enc.generate_rsa_keys()
    return jsonify({
        'public_key': rsa_keypair['public_key'],
        'private_key': rsa_keypair['private_key'],
        'status': 'success'
    })


@app.route('/api/encrypt', methods=['POST'])
def encrypt_message():
    global rsa_keypair
    
    data = request.get_json()
    message = data.get('message', '')
    algorithm = data.get('algorithm', 'AES-256')
    from_node = data.get('from_node', 'Source')
    to_node = data.get('to_node', 'Destination')
    
    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    if algorithm == 'RSA-2048' and not rsa_keypair:
        return jsonify({'error': 'Generate RSA keys first using /api/generate_rsa'}), 400
    
    delay = simulate_network_delay()
    result = None
    
    try:
        if algorithm == 'AES-256':
            result = enc.aes_encrypt(message)
        elif algorithm == 'RSA-2048':
            result = enc.rsa_encrypt(message, rsa_keypair['public_key'])
        elif algorithm == 'ChaCha20':
            result = enc.chacha_encrypt(message)
        else:
            return jsonify({'error': f'Unknown algorithm: {algorithm}'}), 400
        
        # Store in session
        session['last_encrypted'] = result
        session['last_algorithm'] = algorithm
        session['last_original'] = message
        session['message_timestamp'] = time.time()
        session['ttl'] = 60
        
        # Log to database
        log_to_database(from_node, to_node, algorithm, message, result['ciphertext'], delay)
        
        # Prepare response with encryption parameters
        response_data = {
            'status': 'success',
            'encrypted_message': result['ciphertext'],
            'algorithm': algorithm,
            'network_delay_seconds': delay,
            'original_size': len(message),
            'encrypted_size': len(result['ciphertext'])
        }
        # Add algorithm-specific parameters
        if algorithm == 'AES-256':
            response_data['iv'] = result.get('iv')
            response_data['key'] = result.get('key')
        elif algorithm == 'ChaCha20':
            response_data['nonce'] = result.get('nonce')
            response_data['key'] = result.get('key')
        # For RSA, we don't send parameters (they are not needed for decryption beyond session)
        
        return jsonify(response_data)
    
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500


@app.route('/api/decrypt', methods=['POST'])
def decrypt_message():
    global rsa_keypair
    
    # Check TTL first
    if not check_ttl():
        return jsonify({'error': 'Message expired! TTL of 60 seconds exceeded. Please send again.'}), 400
    
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    algorithm = data.get('algorithm', 'AES-256')
    
    if not ciphertext:
        return jsonify({'error': 'Ciphertext cannot be empty'}), 400
    
    full_result = session.get('last_encrypted', {})
    
    try:
        if algorithm == 'AES-256':
            iv = full_result.get('iv')
            key = full_result.get('key')
            if not iv or not key:
                return jsonify({'error': 'Missing encryption parameters'}), 400
            decrypted = enc.aes_decrypt(ciphertext, iv, key)
            
        elif algorithm == 'RSA-2048':
            if not rsa_keypair:
                return jsonify({'error': 'No RSA keys available'}), 400
            decrypted = enc.rsa_decrypt(ciphertext, rsa_keypair['private_key'])
            
        elif algorithm == 'ChaCha20':
            nonce = full_result.get('nonce')
            key = full_result.get('key')
            if not nonce or not key:
                return jsonify({'error': 'Missing encryption parameters'}), 400
            decrypted = enc.chacha_decrypt(ciphertext, nonce, key)
        else:
            return jsonify({'error': f'Unknown algorithm: {algorithm}'}), 400
        
        session['last_plaintext'] = decrypted
        
        return jsonify({
            'status': 'success',
            'decrypted_message': decrypted
        })
    
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500


@app.route('/api/reencrypt', methods=['POST'])
def reencrypt_message():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    old_algorithm = data.get('old_algorithm', 'AES-256')
    new_algorithm = data.get('new_algorithm', 'ChaCha20')
    
    # Try to get parameters from request first, then fallback to session
    old_iv = data.get('old_iv')
    old_key = data.get('old_key')
    old_nonce = data.get('old_nonce')
    
    if not ciphertext:
        return jsonify({'error': 'Ciphertext cannot be empty'}), 400
    
    full_result = session.get('last_encrypted', {})
    
    try:
        decrypted = None
        # Decrypt using old algorithm
        if old_algorithm == 'AES-256':
            iv = old_iv or full_result.get('iv')
            key = old_key or full_result.get('key')
            if not iv or not key:
                return jsonify({'error': 'Missing AES parameters. Please send a new message first.'}), 400
            decrypted = enc.aes_decrypt(ciphertext, iv, key)
            
        elif old_algorithm == 'ChaCha20':
            nonce = old_nonce or full_result.get('nonce')
            key = old_key or full_result.get('key')
            if not nonce or not key:
                return jsonify({'error': 'Missing ChaCha20 parameters. Please send a new message first.'}), 400
            decrypted = enc.chacha_decrypt(ciphertext, nonce, key)
        else:
            return jsonify({'error': 'RSA cannot be used for re-encryption'}), 400
        
        # Re-encrypt with new algorithm
        if new_algorithm == 'AES-256':
            new_result = enc.aes_encrypt(decrypted)
        elif new_algorithm == 'ChaCha20':
            new_result = enc.chacha_encrypt(decrypted)
        else:
            new_result = enc.aes_encrypt(decrypted)
        
        # Update session
        session['last_encrypted'] = new_result
        session['last_algorithm'] = new_algorithm
        session['message_timestamp'] = time.time()
        session['ttl'] = 60
        
        # Prepare response
        response_data = {
            'status': 'success',
            'original_plaintext': decrypted,
            'double_encrypted_message': new_result['ciphertext'],
            'new_algorithm': new_algorithm
        }
        # Include new parameters for frontend
        if new_algorithm == 'AES-256':
            response_data['new_iv'] = new_result.get('iv')
            response_data['new_key'] = new_result.get('key')
        elif new_algorithm == 'ChaCha20':
            response_data['new_nonce'] = new_result.get('nonce')
            response_data['new_key'] = new_result.get('key')
        
        return jsonify(response_data)
    
    except Exception as e:
        return jsonify({'error': f'Re-encryption failed: {str(e)}'}), 500


# ==================== RISK ASSESSMENT ROUTES ====================
@app.route('/api/risk/eavesdropping', methods=['POST'])
def risk_eavesdropping():
    data = request.get_json()
    result = assess_eavesdropping_risk(
        encryption=data.get('encryption', False),
        network_type=data.get('network_type', 'wifi'),
        data_sensitivity=data.get('data_sensitivity', 'medium'),
        public_exposure=data.get('public_exposure', False)
    )
    return jsonify(result)


@app.route('/api/risk/mitm', methods=['POST'])
def risk_mitm():
    data = request.get_json()
    result = assess_mitm_risk(
        uses_https=data.get('uses_https', False),
        validates_certificates=data.get('validates_certificates', False),
        has_cert_pinning=data.get('has_cert_pinning', False),
        network_location=data.get('network_location', 'public')
    )
    return jsonify(result)


@app.route('/api/risk/bruteforce', methods=['POST'])
def risk_bruteforce():
    data = request.get_json()
    result = assess_bruteforce_risk(
        password_strength=data.get('password_strength', 'weak'),
        has_rate_limiting=data.get('has_rate_limiting', False),
        has_mfa=data.get('has_mfa', False),
        exposed_to_internet=data.get('exposed_to_internet', False)
    )
    return jsonify(result)


# ==================== DATABASE AND EXPORT ROUTES ====================
@app.route('/api/get_logs', methods=['GET'])
def get_logs():
    logs = MessageLog.query.order_by(MessageLog.timestamp.desc()).limit(50).all()
    return jsonify([log.to_dict() for log in logs])


@app.route('/api/get_stats', methods=['GET'])
def get_stats():
    total_messages = MessageLog.query.count()
    algorithms_count = {}
    for algo in ['AES-256', 'RSA-2048', 'ChaCha20']:
        algorithms_count[algo] = MessageLog.query.filter_by(algorithm=algo).count()
    
    avg_delay = db.session.query(db.func.avg(MessageLog.network_delay)).scalar() or 0
    
    return jsonify({
        'total_messages': total_messages,
        'algorithms_usage': algorithms_count,
        'average_delay': round(avg_delay, 3)
    })


@app.route('/api/export_pdf', methods=['GET'])
def export_pdf():
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, "IoT Security Platform - Security Report")
    
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 75, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    total = MessageLog.query.count()
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 100, "Statistics:")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 115, f"Total Messages Exchanged: {total}")
    
    y = height - 140
    c.drawString(50, y, "Algorithm Distribution:")
    y -= 15
    for algo in ['AES-256', 'RSA-2048', 'ChaCha20']:
        count = MessageLog.query.filter_by(algorithm=algo).count()
        c.drawString(70, y, f"{algo}: {count} messages")
        y -= 15
    
    y -= 15
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Recent Messages:")
    y -= 15
    
    logs = MessageLog.query.order_by(MessageLog.timestamp.desc()).limit(15).all()
    
    c.setFont("Helvetica-Bold", 8)
    c.drawString(50, y, "Time")
    c.drawString(120, y, "Algorithm")
    c.drawString(200, y, "Original Size")
    c.drawString(290, y, "Encrypted Size")
    c.drawString(380, y, "Delay(ms)")
    y -= 12
    
    c.setFont("Helvetica", 8)
    for log in logs:
        if y < 50:
            c.showPage()
            y = height - 50
        c.drawString(50, y, log.timestamp.strftime('%H:%M:%S'))
        c.drawString(120, y, log.algorithm[:10])
        c.drawString(200, y, str(log.original_size))
        c.drawString(290, y, str(log.encrypted_size))
        c.drawString(380, y, str(int(log.network_delay * 1000)) if log.network_delay else '0')
        y -= 12
    
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(50, 30, "Generated by IoT Security Platform - Advanced Encryption for Internet of Things")
    
    c.save()
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'iot_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf',
        mimetype='application/pdf'
    )


@app.route('/api/clear_logs', methods=['DELETE'])
def clear_logs():
    try:
        MessageLog.query.delete()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'All logs cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 50)
    print("IoT Security Platform Started")
    print("=" * 50)
    print(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"Server: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000)