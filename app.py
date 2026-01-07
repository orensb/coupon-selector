from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import sqlite3
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a secret key for sessions
FAMILIES_DB = 'families.db'  # Registry of all families

def init_families_db():
    """Initialize the families registry database"""
    conn = sqlite3.connect(FAMILIES_DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS families (
            family_code TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def sanitize_family_code(family_code):
    """Sanitize family code to prevent path traversal attacks"""
    # Remove any path separators and dangerous characters
    sanitized = ''.join(c for c in family_code if c.isalnum() or c in ['-', '_'])
    return sanitized[:50]  # Limit length

def init_family_db(family_code):
    """Initialize a family-specific database"""
    family_code = sanitize_family_code(family_code)
    db_path = f'family_{family_code}.db'
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            amount REAL NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add 'used' column if it doesn't exist (for existing databases)
    try:
        c.execute('ALTER TABLE urls ADD COLUMN used INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        # Column already exists, ignore
        pass
    
    conn.commit()
    conn.close()

def get_family_db(family_code):
    """Get database connection for a specific family"""
    family_code = sanitize_family_code(family_code)
    db_path = f'family_{family_code}.db'
    init_family_db(family_code)  # Ensure database exists
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def register_family(family_code):
    """Register a new family code"""
    family_code = sanitize_family_code(family_code)
    conn = sqlite3.connect(FAMILIES_DB)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO families (family_code) VALUES (?)', (family_code,))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Family already exists
        return False
    finally:
        conn.close()

def family_exists(family_code):
    """Check if a family code exists"""
    family_code = sanitize_family_code(family_code)
    conn = sqlite3.connect(FAMILIES_DB)
    c = conn.cursor()
    c.execute('SELECT 1 FROM families WHERE family_code = ?', (family_code,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'family_code' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Main page - redirect to login if not authenticated"""
    if 'family_code' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', family_code=session.get('family_code'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        family_code = request.form.get('family_code', '').strip()
        
        if not family_code:
            return render_template('login.html', error='Please enter a family code')
        
        # Sanitize family code
        family_code = sanitize_family_code(family_code)
        
        if not family_code:
            return render_template('login.html', error='Invalid family code. Use only letters, numbers, hyphens, and underscores.')
        
        # Auto-register family if it doesn't exist
        if not family_exists(family_code):
            register_family(family_code)
            init_family_db(family_code)
        
        # Set session
        session['family_code'] = family_code
        return redirect(url_for('index'))
    
    # If already logged in, redirect to index
    if 'family_code' in session:
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    """Logout"""
    session.pop('family_code', None)
    return redirect(url_for('login'))

@app.route('/api/urls', methods=['GET'])
@require_auth
def get_urls():
    """Get all URLs that are not used"""
    family_code = session['family_code']
    conn = get_family_db(family_code)
    c = conn.cursor()
    c.execute('SELECT * FROM urls WHERE used = 0 ORDER BY amount DESC')
    urls = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(urls)

@app.route('/api/allurls', methods=['GET'])
@require_auth
def get_all_urls():
    """Get all URLs including used ones"""
    family_code = session['family_code']
    conn = get_family_db(family_code)
    c = conn.cursor()
    c.execute('SELECT * FROM urls ORDER BY amount DESC')
    urls = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(urls)

@app.route('/api/upload', methods=['POST'])
@require_auth
def upload_file():
    """Upload and parse text file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        family_code = session['family_code']
        content = file.read().decode('utf-8')
        lines = content.strip().split('\n')
        
        conn = get_family_db(family_code)
        c = conn.cursor()
        added_count = 0
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Try to parse: amount URL or amount,URL or amount\tURL
            parts = line.replace(',', ' ').replace('\t', ' ').split()
            if len(parts) >= 2:
                try:
                    amount = float(parts[0])
                    url = ' '.join(parts[1:])
                    
                    # Add to database (used defaults to 0)
                    c.execute('INSERT INTO urls (url, amount, used) VALUES (?, ?, 0)', (url, amount))
                    added_count += 1
                except ValueError:
                    continue
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Successfully added {added_count} URLs', 'count': added_count})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/use-amount', methods=['POST'])
@require_auth
def use_amount():
    """Use amount - find and use URLs"""
    try:
        family_code = session['family_code']
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        amount_needed = float(data.get('amount', 0))
        
        if amount_needed <= 0:
            return jsonify({'error': 'Amount must be greater than 0'}), 400
        
        conn = get_family_db(family_code)
        c = conn.cursor()
        
        # Get all unused URLs sorted by amount (descending) for greedy algorithm
        c.execute('SELECT * FROM urls WHERE used = 0 AND amount > 0 ORDER BY amount DESC')
        urls = [dict(row) for row in c.fetchall()]
        
        remaining = amount_needed
        used_urls = []
        to_mark_used = []  # URLs to mark as used (fully used)
        to_update = []  # URLs to update (partially used)
        
        # Greedy algorithm: use largest amounts first
        for url in urls:
            if remaining <= 0:
                break
            
            if url['amount'] <= remaining:
                # Use entire amount - mark as used
                used_urls.append({
                    'id': url['id'],
                    'url': url['url'],
                    'amount': url['amount'],
                    'remaining': 0
                })
                remaining -= url['amount']
                to_mark_used.append(url['id'])
            else:
                # Use partial amount - update amount, keep as unused
                used_amount = remaining
                new_amount = url['amount'] - remaining
                used_urls.append({
                    'id': url['id'],
                    'url': url['url'],
                    'amount': used_amount,
                    'remaining': new_amount
                })
                to_update.append((new_amount, url['id']))
                remaining = 0
        
        # Update database - mark fully used URLs
        for url_id in to_mark_used:
            c.execute('UPDATE urls SET used = 1 WHERE id = ?', (url_id,))
        
        # Update database - update partially used URLs
        for new_amount, url_id in to_update:
            c.execute('UPDATE urls SET amount = ? WHERE id = ?', (new_amount, url_id))
        
        conn.commit()
        conn.close()
        
        if remaining > 0:
            return jsonify({
                'message': f'Only {amount_needed - remaining:.2f} shekel available. {remaining:.2f} shekel still needed.',
                'used_urls': used_urls,
                'remaining_needed': remaining
            }), 200
        
        return jsonify({
            'message': f'Successfully used {amount_needed:.2f} shekel',
            'used_urls': used_urls
        })
    
    except ValueError as e:
        return jsonify({'error': f'Invalid amount: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/remove', methods=['POST'])
@require_auth
def remove_url():
    """Remove a URL by ID"""
    family_code = session['family_code']
    data = request.json
    url_id = data.get('id')
    
    if not url_id:
        return jsonify({'error': 'ID required'}), 400
    
    conn = get_family_db(family_code)
    c = conn.cursor()
    c.execute('DELETE FROM urls WHERE id = ?', (url_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'URL removed successfully'})

@app.route('/api/add', methods=['POST'])
@require_auth
def add_url():
    """Manually add a URL"""
    family_code = session['family_code']
    data = request.json
    url = data.get('url', '').strip()
    amount = float(data.get('amount', 0))
    
    if not url or amount <= 0:
        return jsonify({'error': 'Valid URL and amount required'}), 400
    
    conn = get_family_db(family_code)
    c = conn.cursor()
    c.execute('INSERT INTO urls (url, amount, used) VALUES (?, ?, 0)', (url, amount))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'URL added successfully'})

if __name__ == '__main__':
    init_families_db()
    app.run(debug=True, host='0.0.0.0', port=5000)

