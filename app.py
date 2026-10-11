from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
from flask_socketio import SocketIO, emit
from flask import Response
import bcrypt
import random
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)

#session time out
app.secret_key = 'h_fnd_secret_key_2026'
app.permanent_session_lifetime = timedelta(minutes=15)

# Secret key for session management
app.secret_key = 'h_fnd_secret_key_2026'

# MySQL Configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'hfnd_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# ============================================
# SOCKET.IO CONFIGURATION
# ============================================

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

DATA_FILE = 'pi_data.json'

# ============================================
# HELPER FUNCTIONS
# ============================================

def generate_admin_id():
    return "FND-" + str(random.randint(1000, 9999))

def log_audit(user_id, username, action):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO audit_logs (user_id, username, action) VALUES (%s, %s, %s)", (user_id, username, action))
    mysql.connection.commit()
    cur.close()

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user:
            if bcrypt.checkpw(password, user['password_hash'].encode('utf-8')):
                # ✅ CLEAR OLD SESSION (Prevent Session Fixation)
                session.clear()

                # ✅ SET NEW SESSION
                session['user_id'] = user['id']
                session['username'] = user['username']

                # ✅ SESSION TIMEOUT
                session.permanent = True

                log_audit(user['id'], username, "User Login")
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password. Please try again.', 'error')
        else:
            flash('Username not found.', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit(session['user_id'], session['username'], "User Logout")
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/create_admin', methods=['GET'])
def create_admin():
    username = "admin"
    password = "admin123".encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    cur = mysql.connection.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')", (username, hashed))
        mysql.connection.commit()
        return "Admin user 'admin' created successfully with password 'admin123'!"
    except:
        return "Admin user already exists!"
    finally:
        cur.close()

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        security_question = request.form['security_question']
        security_answer = request.form['security_answer'].encode('utf-8')
        role = request.form.get('role', 'admin')

        # ✅ CHECK PASSWORD LENGTH
        if len(request.form['password']) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('create_user'))

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        hashed_answer = bcrypt.hashpw(security_answer, bcrypt.gensalt())
        admin_id = generate_admin_id()

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            flash('Username already taken. Please choose another.', 'error')
            return redirect(url_for('create_user'))
        else:
            try:
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, admin_id, security_question, security_answer_hash, reset_requested) 
                    VALUES (%s, %s, %s, %s, %s, %s, 0)
                """, (username, hashed_password, role, admin_id, security_question, hashed_answer))
                mysql.connection.commit()
                flash(f'Account created successfully! Your Admin ID is {admin_id}', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                mysql.connection.rollback()
                flash(f'Error creating account: {str(e)}', 'error')
            finally:
                cur.close()

    return render_template('create_user.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if user:
            cur.execute("UPDATE users SET reset_requested = 1 WHERE username = %s", (username,))
            mysql.connection.commit()
            flash(f'Password reset request for {username} has been sent. Please contact Admin.', 'info')
        else:
            flash('Username not found.', 'error')
        cur.close()
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))
    
    # Get current user role
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    current_user = cur.fetchone()
    user_role = current_user['role'] if current_user else 'admin'
    
    # Get target user role
    cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    target_user = cur.fetchone()
    if not target_user:
        flash('User not found.', 'error')
        cur.close()
        return redirect(url_for('manage_users'))
    target_role = target_user['role'] if target_user else 'admin'
    
    # ============================================
    # ROLE-BASED PERMISSION CHECK
    # ============================================
    
    # Technician: No reset permission at all
    if user_role == 'technician':
        flash('You do not have permission to reset passwords.', 'error')
        cur.close()
        return redirect(url_for('manage_users'))
    
    # Admin: Cannot reset Super Admin
    if user_role == 'admin' and target_role == 'super_admin':
        flash('You cannot reset a Super Admin password.', 'error')
        cur.close()
        return redirect(url_for('manage_users'))
    
    # Super Admin: Can reset anyone (no restriction)
    
    # ============================================
    # PROCESS RESET
    # ============================================
    
    if request.method == 'POST':
        new_password = request.form['new_password'].encode('utf-8')
        
        # ✅ CHECK PASSWORD LENGTH
        if len(request.form['new_password']) < 8:
            flash('Password must be at least 8 characters.', 'error')
            cur.close()
            return redirect(url_for('reset_password', user_id=user_id))
        
        hashed = bcrypt.hashpw(new_password, bcrypt.gensalt())
        
        cur.execute("UPDATE users SET password_hash = %s, reset_requested = 0 WHERE id = %s", (hashed, user_id))
        mysql.connection.commit()
        cur.close()
        
        flash('Password successfully reset!', 'success')
        return redirect(url_for('manage_users'))
    
    cur.close()
    return render_template('reset_password.html', user_id=user_id)

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cur.fetchone()
    cur.execute("SELECT * FROM audit_logs WHERE user_id = %s ORDER BY timestamp DESC", (session['user_id'],))
    logs = cur.fetchall()
    cur.close()
    return render_template('settings.html', user=user, logs=logs)

# ============================================
# DASHBOARD ROUTES
# ============================================

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard_hfnd.html')

@app.route('/cyber-monitoring')
def cyber_monitoring():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('cyberm_hfnd.html')

@app.route('/network-monitoring')
def network_monitoring():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('networkm_hfnd.html')

@app.route('/system-status')
def system_status():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    return render_template('systemstat_hfnd.html')

@app.route('/alert-logs')
def alert_logs():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
    alerts = cur.fetchall()
    cur.close()
    return render_template('alert_hfnd.html', alerts=alerts)

# ============================================
# API ROUTES (Receive Data from Pi)
# ============================================

@app.route('/api/pi-data', methods=['POST'])
def receive_pi_data():
    try:
        data = request.json
        data['received_at'] = datetime.now().isoformat()
        
        # Save to file
        existing = []
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as f:
                try:
                    existing = json.load(f)
                except:
                    existing = []
        
        existing.append(data)
        if len(existing) > 100:
            existing = existing[-100:]
        
        with open(DATA_FILE, 'w') as f:
            json.dump(existing, f, indent=2, default=str)
        
        # Insert alerts into MySQL
        alerts = data.get('alerts', [])
        for alert in alerts:
            try:
                cur = mysql.connection.cursor()
                cur.execute("""
                    INSERT INTO alerts (timestamp, severity, alert_type, source_ip, destination_ip, status)
                    VALUES (%s, %s, %s, %s, %s, 'new')
                """, (
                    alert.get('timestamp', datetime.now().isoformat()),
                    alert.get('severity', 'medium'),
                    alert.get('alert_type', 'Unknown'),
                    alert.get('source_ip', 'Unknown'),
                    alert.get('destination_ip', 'Unknown')
                ))
                mysql.connection.commit()
                cur.close()
            except Exception as e:
                print(f"Error inserting alert: {e}")
        
        # ============================================
        # INSERT NETWORK METRICS INTO DATABASE
        # ============================================
        metrics = data.get('metrics', {})
        usb_status = metrics.get('usb_status', {})
        
        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO network_logs 
                (usb1_status, usb2_status, usb3_status, usb4_status, 
                 cpu_usage, memory_usage, temperature, network_status, packets_per_sec)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                usb_status.get('usb1', 'DISCONNECTED'),
                usb_status.get('usb2', 'DISCONNECTED'),
                usb_status.get('usb3', 'DISCONNECTED'),
                usb_status.get('usb4', 'DISCONNECTED'),
                metrics.get('cpu', 0),
                metrics.get('memory', {}).get('percent', 0),
                metrics.get('temperature', 0),
                metrics.get('network_status', 'UNKNOWN'),
                metrics.get('packets_per_sec', 0)
            ))
            mysql.connection.commit()
            cur.close()
        except Exception as e:
            print(f"Error inserting network logs: {e}")
        
        # Broadcast via WebSocket
        socketio.emit('pi_update', data, namespace='/')
        
        print(f"✅ Data from Pi: CPU={data.get('metrics',{}).get('cpu',0)}% | Temp={data.get('metrics',{}).get('temperature',0)}°C | Alerts={len(alerts)}")
        return jsonify({'message': 'Data received', 'status': 'success'}), 200
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/pi-data', methods=['GET'])
def get_pi_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    return jsonify([])

@app.route('/api/latest')
def get_latest():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        if data:
            return jsonify(data[-1])
    return jsonify({'error': 'No data'}), 404

# ============================================
# SOCKET.IO EVENTS
# ============================================

@socketio.on('connect')
def handle_connect():
    print(f"🔗 Client connected: {request.sid}")
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        if data:
            emit('pi_update', data[-1])

@socketio.on('disconnect')
def handle_disconnect():
    print(f"🔌 Client disconnected: {request.sid}")

@socketio.on('request_data')
def handle_request_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        if data:
            emit('pi_update', data[-1])

# ============================================
# MAIN
# ============================================

@app.route('/api/cyber-stats')
def cyber_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    cur = mysql.connection.cursor()
    
    # Total alerts today
    cur.execute("SELECT COUNT(*) as total FROM alerts WHERE DATE(timestamp) = CURDATE()")
    total = cur.fetchone()['total']
    
    # By severity
    cur.execute("""
        SELECT severity, COUNT(*) as count 
        FROM alerts 
        WHERE DATE(timestamp) = CURDATE() 
        GROUP BY severity
    """)
    severity_data = cur.fetchall()
    
    # By attack type
    cur.execute("""
        SELECT alert_type, COUNT(*) as count 
        FROM alerts 
        WHERE DATE(timestamp) = CURDATE() 
        GROUP BY alert_type
    """)
    attack_data = cur.fetchall()
    
    # Recent alerts (last 10)
    cur.execute("""
        SELECT id, timestamp, severity, alert_type, source_ip, status 
        FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT 10
    """)
    recent = cur.fetchall()
    cur.close()
    
    # Format severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for row in severity_data:
        if row['severity'] in severity_counts:
            severity_counts[row['severity']] = row['count']
    
    # Format attack types
    attack_counts = {'DDoS': 0, 'DoS': 0, 'DNS Flood': 0, 'Other': 0}
    for row in attack_data:
        atype = row['alert_type']
        if 'ddos' in atype.lower():
            attack_counts['DDoS'] += row['count']
        elif 'dos' in atype.lower():
            attack_counts['DoS'] += row['count']
        elif 'dns' in atype.lower() or 'flood' in atype.lower():
            attack_counts['DNS Flood'] += row['count']
        else:
            attack_counts['Other'] += row['count']
    
    # Format recent alerts
    for alert in recent:
        alert['timestamp'] = alert['timestamp'].strftime('%H:%M:%S')
    
    return jsonify({
        'total': total,
        'severity': severity_counts,
        'attack_types': attack_counts,
        'recent': recent
    })

@app.route('/api/export-alerts')
def export_alerts():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT timestamp, alert_type, severity, source_ip, destination_ip, status 
        FROM alerts 
        ORDER BY timestamp DESC
    """)
    alerts = cur.fetchall()
    cur.close()
    
    # Create CSV
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Alert Type', 'Severity', 'Source IP', 'Destination IP', 'Status'])
    
    for alert in alerts:
        writer.writerow([
            alert['timestamp'],
            alert['alert_type'],
            alert['severity'],
            alert['source_ip'],
            alert['destination_ip'],
            alert['status']
        ])
    
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers.set('Content-Disposition', 'attachment', filename='h-fnd_alerts.csv')
    return response

@app.route('/api/alert-action', methods=['POST'])
def alert_action():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    alert_id = data.get('id')
    action = data.get('action')
    
    if not alert_id or not action:
        return jsonify({'error': 'Missing parameters'}), 400
    
    cur = mysql.connection.cursor()
    
    if action == 'acknowledge':
        cur.execute("UPDATE alerts SET status = 'investigating' WHERE id = %s", (alert_id,))
    elif action == 'resolve':
        cur.execute("UPDATE alerts SET status = 'resolved' WHERE id = %s", (alert_id,))
    elif action == 'block':
        # Log the block action (simulate)
        cur.execute("UPDATE alerts SET status = 'investigating', details = CONCAT(details, ' [IP Blocked]') WHERE id = %s", (alert_id,))
    else:
        return jsonify({'error': 'Invalid action'}), 400
    
    mysql.connection.commit()
    cur.close()
    
    return jsonify({'success': True})

@app.route('/manage_users')
def manage_users():
    if 'user_id' not in session:
        flash('Please login to access this page.', 'error')
        return redirect(url_for('login'))
    
    # Check user role
    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
    user_role = cur.fetchone()['role']
    
    cur.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.close()
    
    return render_template('manage_users.html', users=users, user_role=user_role)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password'].encode('utf-8')
        new_password = request.form['new_password'].encode('utf-8')
        confirm_password = request.form['confirm_password'].encode('utf-8')
        
        # ✅ CHECK PASSWORD LENGTH
        if len(request.form['new_password']) < 8:
            flash('New password must be at least 8 characters.', 'error')
            return redirect(url_for('change_password'))
        
        # Check new password match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))
        
        # Check current password
        cur = mysql.connection.cursor()
        cur.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],))
        user = cur.fetchone()
        
        if not bcrypt.checkpw(current_password, user['password_hash'].encode('utf-8')):
            flash('Current password is incorrect.', 'error')
            cur.close()
            return redirect(url_for('change_password'))
        
        # Update password
        hashed = bcrypt.hashpw(new_password, bcrypt.gensalt())
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed, session['user_id']))
        mysql.connection.commit()
        
        # Log audit
        log_audit(session['user_id'], session['username'], "Changed Password")
        
        cur.close()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('settings'))
    
    return render_template('change_password.html')

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 H-FND App with WebSocket")
    print("📍 Waiting for data from Raspberry Pi...")
    print("🔗 WebSocket: ws://localhost:5000")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)