import os
import psycopg2
import psycopg2.extras
import secrets
from functools import wraps
from flask import Flask, session, jsonify, request, redirect, url_for, render_template
from dotenv import load_dotenv
load_dotenv()  # This loads the .env file



import os
import psycopg2
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a secret key for sessions


# Use the Session pooler connection string with your actual password
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

print(f"DATABASE_URL is set: {DATABASE_URL}")  # Don't print the actual URL


def get_db_connection():
    result = urlparse(DATABASE_URL)
    return psycopg2.connect(
        database=result.path[1:],
        user=result.username,
        password=result.password,
        host=result.hostname,
        port=result.port,
        sslmode="require"
    )


def init_families_db():
    """Initialize the families registry database"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS families (
            id SERIAL PRIMARY KEY,
            family_code TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)
    conn.commit()
    c.close()
    conn.close()

def init_urls_table():
    """Initialize the URLs table for all families"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS urls (
            id SERIAL PRIMARY KEY,
            family_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            amount REAL NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_family
                FOREIGN KEY(family_id)
                REFERENCES families(id)
                ON DELETE CASCADE
        )
    """)
    conn.commit()
    c.close()
    conn.close()


def sanitize_family_code(family_code):
    """Sanitize family code to prevent path traversal attacks"""
    # Remove any path separators and dangerous characters
    sanitized = ''.join(c for c in family_code if c.isalnum() or c in ['-', '_'])
    return sanitized[:50]  # Limit length


def register_family(family_code):
    """Register a new family code"""
    family_code = sanitize_family_code(family_code)
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO families (family_code) VALUES (%s)', (family_code,))
        conn.commit()
        return True
    except psycopg2.errors.UniqueViolation:
        # Family already exists
        conn.rollback()
        return False
    finally:
        c.close()
        conn.close()

def family_exists(family_code):
    """Check if a family code exists"""
    family_code = sanitize_family_code(family_code)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT id FROM families WHERE family_code = %s', (family_code,))
    row = c.fetchone()
    c.close()
    conn.close()
    return row[0] if row else None

def get_family_id(family_code):
    """Get family_id from family_code"""
    return family_exists(family_code)

def get_urls_cursor():
    """Return connection and "RealDictCursor"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    return conn, cur


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
    family_id = get_family_id(family_code)
    conn, c = get_urls_cursor()
    c.execute('SELECT * FROM urls WHERE family_id = %s AND used = FALSE ORDER BY amount DESC' , (family_id,))
    urls = c.fetchall()
    conn.close()
    return jsonify(urls)

@app.route('/api/total', methods=['GET'])
@require_auth
def get_total_amount():
    family_code = session['family_code']

    family_id = get_family_id(family_code)
    conn, c = get_urls_cursor()

    c.execute('SELECT SUM(amount) FROM urls WHERE family_id = %s AND used = FALSE' , (family_id,))
    total = c.fetchone()['sum'] or 0

    conn.close()

    return jsonify({"total_amount": total})



@app.route('/api/allurls', methods=['GET'])
@require_auth
def get_all_urls():
    """Get all URLs including used ones"""
    family_code = session['family_code']
    family_id = get_family_id(family_code)
    conn, c = get_urls_cursor()
    c.execute('SELECT * FROM urls WHERE family_id = %s ORDER BY created_at DESC' , (family_id,))
    urls = c.fetchall()
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
        family_id = get_family_id(family_code)
        conn , c = get_urls_cursor()
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
                    c.execute('INSERT INTO urls (url, amount, used, family_id) VALUES (%s, %s, FALSE, %s)',
                              (url, amount, family_id))                    
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
        family_id = get_family_id(family_code)
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        amount_needed = float(data.get('amount', 0))
        
        if amount_needed <= 0:
            return jsonify({'error': 'Amount must be greater than 0'}), 400
        
        conn , c = get_urls_cursor()
        
        # Get all unused URLs sorted by amount (descending) for greedy algorithm
        c.execute('SELECT * FROM urls WHERE family_id = %s AND used = FALSE AND amount > 0 ORDER BY amount DESC' , (family_id,))
        urls = c.fetchall()
        
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
        # for url_id in to_mark_used:
        #     c.execute('UPDATE urls SET used = 1 WHERE id = %S', (url_id,))
        
        # # Update database - update partially used URLs
        # for new_amount, url_id in to_update:
        #     c.execute('UPDATE urls SET amount = %S WHERE id = %S', (new_amount, url_id))
        
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
    
    family_id = get_family_id(family_code)
    conn , c = get_urls_cursor()
    c.execute('UPDATE urls SET used = True WHERE id = %s AND family_id = %s', (url_id,family_id))
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
    
    family_id = get_family_id(family_code)
    conn , c = get_urls_cursor()
    c.execute('INSERT INTO urls (url, amount, used, family_id) VALUES (%s, %s, False, %s)', (url, amount,family_id))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'URL added successfully'})

if __name__ == '__main__':
    init_families_db()
    init_urls_table()
    app.run(debug=True, host='0.0.0.0', port=5000)