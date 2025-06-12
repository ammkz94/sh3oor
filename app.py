# app.py - Main Flask Application
from flask import Flask, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import jwt
import datetime
import os
import secrets
import re
from functools import wraps

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///sh3oor.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration (Gmail SMTP)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Your Gmail
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # App password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

# OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
app.config['MICROSOFT_CLIENT_ID'] = os.environ.get('MICROSOFT_CLIENT_ID')
app.config['MICROSOFT_CLIENT_SECRET'] = os.environ.get('MICROSOFT_CLIENT_SECRET')

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
oauth = OAuth(app)
CORS(app, origins=['https://your-frontend-domain.vercel.app'])

# OAuth providers setup
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

microsoft = oauth.register(
    name='microsoft',
    client_id=app.config['MICROSOFT_CLIENT_ID'],
    client_secret=app.config['MICROSOFT_CLIENT_SECRET'],
    server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid_configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)  # Nullable for OAuth users
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    oauth_provider = db.Column(db.String(50), nullable=True)  # 'google', 'microsoft', or None
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'is_verified': self.is_verified,
            'oauth_provider': self.oauth_provider,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Utility Functions
def generate_token():
    return secrets.token_urlsafe(32)

def generate_jwt_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    if len(password) < 8:
        return False, "كلمة المرور يجب أن تحتوي على 8 أحرف على الأقل"
    if not re.search(r'[A-Z]', password):
        return False, "كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل"
    if not re.search(r'[a-z]', password):
        return False, "كلمة المرور يجب أن تحتوي على حرف صغير واحد على الأقل"
    if not re.search(r'[0-9]', password):
        return False, "كلمة المرور يجب أن تحتوي على رقم واحد على الأقل"
    return True, ""

def send_verification_email(user):
    try:
        msg = Message(
            'تفعيل حساب شعور - Sh3oor Account Verification',
            recipients=[user.email]
        )
        
        verification_link = f"https://your-frontend-domain.vercel.app/verify?token={user.verification_token}"
        
        msg.html = f"""
        <div style="direction: rtl; text-align: right; font-family: Arial, sans-serif;">
            <h2 style="color: #667eea;">مرحباً {user.name}! 💙</h2>
            <p>شكراً لانضمامك إلى تطبيق شعور!</p>
            <p>لتفعيل حسابك، يرجى الضغط على الرابط أدناه:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_link}" 
                   style="background: linear-gradient(135deg, #667eea, #764ba2); 
                          color: white; 
                          padding: 15px 30px; 
                          text-decoration: none; 
                          border-radius: 10px; 
                          display: inline-block;
                          font-weight: bold;">
                    تفعيل الحساب
                </a>
            </div>
            <p>أو انسخ هذا الرابط والصقه في المتصفح:</p>
            <p style="color: #667eea; word-break: break-all;">{verification_link}</p>
            <p>هذا الرابط صالح لمدة 24 ساعة فقط.</p>
            <hr style="margin: 30px 0;">
            <p style="color: #666; font-size: 14px;">
                إذا لم تقم بإنشاء هذا الحساب، يرجى تجاهل هذا البريد.
            </p>
        </div>
        """
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_password_reset_email(user):
    try:
        msg = Message(
            'إعادة تعيين كلمة المرور - Sh3oor Password Reset',
            recipients=[user.email]
        )
        
        reset_link = f"https://your-frontend-domain.vercel.app/reset-password?token={user.reset_token}"
        
        msg.html = f"""
        <div style="direction: rtl; text-align: right; font-family: Arial, sans-serif;">
            <h2 style="color: #667eea;">إعادة تعيين كلمة المرور</h2>
            <p>مرحباً {user.name},</p>
            <p>تلقينا طلباً لإعادة تعيين كلمة المرور لحسابك في تطبيق شعور.</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_link}" 
                   style="background: linear-gradient(135deg, #667eea, #764ba2); 
                          color: white; 
                          padding: 15px 30px; 
                          text-decoration: none; 
                          border-radius: 10px; 
                          display: inline-block;
                          font-weight: bold;">
                    إعادة تعيين كلمة المرور
                </a>
            </div>
            <p>أو انسخ هذا الرابط والصقه في المتصفح:</p>
            <p style="color: #667eea; word-break: break-all;">{reset_link}</p>
            <p>هذا الرابط صالح لمدة ساعة واحدة فقط.</p>
            <hr style="margin: 30px 0;">
            <p style="color: #666; font-size: 14px;">
                إذا لم تطلب إعادة تعيين كلمة المرور، يرجى تجاهل هذا البريد.
            </p>
        </div>
        """
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending reset email: {e}")
        return False

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'يرجى تسجيل الدخول للوصول إلى هذه الصفحة'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            user_id = verify_jwt_token(token)
            if not user_id:
                return jsonify({'message': 'رمز التوثيق غير صالح'}), 401
            
            current_user = User.query.get(user_id)
            if not current_user:
                return jsonify({'message': 'المستخدم غير موجود'}), 401
                
        except Exception as e:
            return jsonify({'message': 'رمز التوثيق غير صالح'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# API Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'لا توجد بيانات'}), 400
        
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validation
        if len(name) < 2:
            return jsonify({
                'message': 'يرجى إدخال اسم صحيح (حرفين على الأقل)',
                'field': 'name'
            }), 400
        
        if not validate_email(email):
            return jsonify({
                'message': 'يرجى إدخال بريد إلكتروني صحيح',
                'field': 'email'
            }), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({
                'message': 'هذا البريد الإلكتروني مسجل مسبقاً',
                'field': 'email'
            }), 400
        
        # Validate password
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return jsonify({
                'message': error_msg,
                'field': 'password'
            }), 400
        
        # Create new user
        verification_token = generate_token()
        new_user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            verification_token=verification_token
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Send verification email
        if send_verification_email(new_user):
            return jsonify({
                'message': 'تم إنشاء الحساب بنجاح! يرجى التحقق من بريدك الإلكتروني لتفعيل الحساب.'
            }), 201
        else:
            return jsonify({
                'message': 'تم إنشاء الحساب ولكن فشل في إرسال بريد التفعيل. يرجى المحاولة مرة أخرى.'
            }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {e}")
        return jsonify({'message': 'حدث خطأ في الخادم'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'لا توجد بيانات'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'message': 'يرجى إدخال البريد الإلكتروني وكلمة المرور'}), 400
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({
                'message': 'البريد الإلكتروني غير مسجل',
                'field': 'email'
            }), 401
        
        # Check if OAuth user
        if user.oauth_provider and not user.password_hash:
            return jsonify({
                'message': f'هذا الحساب مسجل عبر {user.oauth_provider}. يرجى استخدام نفس الطريقة لتسجيل الدخول.',
                'field': 'email'
            }), 401
        
        # Verify password
        if not check_password_hash(user.password_hash, password):
            return jsonify({
                'message': 'كلمة المرور غير صحيحة',
                'field': 'password'
            }), 401
        
        # Check if account is verified
        if not user.is_verified:
            return jsonify({
                'message': 'يرجى تفعيل حسابك عبر البريد الإلكتروني أولاً'
            }), 401
        
        # Update last login
        user.last_login = datetime.datetime.utcnow()
        db.session.commit()
        
        # Generate token
        token = generate_jwt_token(user.id)
        
        return jsonify({
            'message': 'تم تسجيل الدخول بنجاح',
            'token': token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'message': 'حدث خطأ في الخادم'}), 500

@app.route('/api/auth/verify', methods=['POST'])
def verify_email():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'message': 'رمز التفعيل مطلوب'}), 400
        
        user = User.query.filter_by(verification_token=token).first()
        
        if not user:
            return jsonify({'message': 'رمز التفعيل غير صالح أو منتهي الصلاحية'}), 400
        
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        
        return jsonify({'message': 'تم تفعيل الحساب بنجاح! يمكنك الآن تسجيل الدخول.'}), 200
        
    except Exception as e:
        print(f"Verification error: {e}")
        return jsonify({'message': 'حدث خطأ في الخادم'}), 500

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not validate_email(email):
            return jsonify({'message': 'يرجى إدخال بريد إلكتروني صحيح'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Don't reveal if email exists or not
            return jsonify({'message': 'إذا كان البريد الإلكتروني مسجلاً، ستتلقى رابط إعادة تعيين كلمة المرور.'}), 200
        
        # Generate reset token
        user.reset_token = generate_token()
        db.session.commit()
        
        # Send reset email
        send_password_reset_email(user)
        
        return jsonify({'message': 'تم إرسال رابط إعادة تعيين كلمة المرور إلى بريدك الإلكتروني.'}), 200
        
    except Exception as e:
        print(f"Forgot password error: {e}")
        return jsonify({'message': 'حدث خطأ في الخادم'}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('password')
        
        if not token or not new_password:
            return jsonify({'message': 'الرمز وكلمة المرور الجديدة مطلوبان'}), 400
        
        user = User.query.filter_by(reset_token=token).first()
        
        if not user:
            return jsonify({'message': 'رمز إعادة التعيين غير صالح أو منتهي الصلاحية'}), 400
        
        # Validate new password
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            return jsonify({'message': error_msg}), 400
        
        # Update password
        user.password_hash = generate_password_hash(new_password)
        user.reset_token = None
        db.session.commit()
        
        return jsonify({'message': 'تم تغيير كلمة المرور بنجاح!'}), 200
        
    except Exception as e:
        print(f"Reset password error: {e}")
        return jsonify({'message': 'حدث خطأ في الخادم'}), 500

# OAuth Routes
@app.route('/auth/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            return redirect('https://your-frontend-domain.vercel.app/login?error=oauth_failed')
        
        email = user_info.get('email')
        name = user_info.get('name')
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Update OAuth info if needed
            if not user.oauth_provider:
                user.oauth_provider = 'google'
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
        else:
            # Create new user
            user = User(
                name=name,
                email=email,
                is_verified=True,  # OAuth users are auto-verified
                oauth_provider='google'
            )
            db.session.add(user)
            db.session.commit()
        
        # Generate JWT token
        token = generate_jwt_token(user.id)
        
        # Redirect to frontend with token
        return redirect(f'https://your-frontend-domain.vercel.app/login?token={token}')
        
    except Exception as e:
        print(f"Google OAuth error: {e}")
        return redirect('https://your-frontend-domain.vercel.app/login?error=oauth_failed')

@app.route('/auth/microsoft')
def microsoft_login():
    redirect_uri = url_for('microsoft_callback', _external=True)
    return microsoft.authorize_redirect(redirect_uri)

@app.route('/auth/microsoft/callback')
def microsoft_callback():
    try:
        token = microsoft.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            return redirect('https://your-frontend-domain.vercel.app/login?error=oauth_failed')
        
        email = user_info.get('email')
        name = user_info.get('name')
        
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Update OAuth info if needed
            if not user.oauth_provider:
                user.oauth_provider = 'microsoft'
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
        else:
            # Create new user
            user = User(
                name=name,
                email=email,
                is_verified=True,  # OAuth users are auto-verified
                oauth_provider='microsoft'
            )
            db.session.add(user)
            db.session.commit()
        
        # Generate JWT token
        token = generate_jwt_token(user.id)
        
        # Redirect to frontend with token
        return redirect(f'https://your-frontend-domain.vercel.app/login?token={token}')
        
    except Exception as e:
        print(f"Microsoft OAuth error: {e}")
        return redirect('https://your-frontend-domain.vercel.app/login?error=oauth_failed')

# Protected Routes
@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({'user': current_user.to_dict()}), 200

@app.route('/api/user/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        
        if len(name) < 2:
            return jsonify({'message': 'يرجى إدخال اسم صحيح'}), 400
        
        current_user.name = name
        db.session.commit()
        
        return jsonify({
            'message': 'تم تحديث الملف الشخصي بنجاح',
            'user': current_user.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Profile update error: {e}")
        return jsonify({'message': 'حدث خطأ في الخادم'}), 500

@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password(current_user):
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        # Check if user has a password (not OAuth only)
        if not current_user.password_hash:
            return jsonify({'message': 'هذا الحساب مسجل عبر وسائل التواصل الاجتماعي ولا يمكن تغيير كلمة المرور'}), 400
        
        # Verify current password
        if not check_password_hash(current_user.password_hash, current_password):
            return jsonify({'message': 'كلمة المرور الحالية غير صحيحة'}), 400
        
        # Validate new password
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            return jsonify({'message': error_msg}), 400
        
        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({'message': 'تم تغيير كلمة المرور بنجاح'}), 200
        
    except Exception as e:
        print(f"Change password error: {e}")
        return jsonify({'message': 'حدث خطأ في الخادم'}), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.datetime.utcnow().isoformat()}), 200

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'message': 'الصفحة غير موجودة'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'message': 'حدث خطأ في الخادم'}), 500

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)