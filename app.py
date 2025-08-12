# Import necessary modules
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlencode
import os
from config import Config
from sqlalchemy import func, extract
from collections import defaultdict

# Initialize Flask application
app = Flask(__name__)

# Load configuration from Config class
app.config.from_object(Config)

# Configure application
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-dev-key')
app.config.from_object(Config)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.login_view = 'login'  # Set the login view
login_manager.init_app(app)

mail = Mail(app)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'images')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize database
db = SQLAlchemy(app)

# Database Models
class User(UserMixin, db.Model):
    """User model for database"""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    license_number = db.Column(db.String(50))  
    license_expiry = db.Column(db.Date)  
    phone_number = db.Column(db.String(20))  
    address = db.Column(db.Text)  
    date_of_birth = db.Column(db.Date) 
    verified = db.Column(db.Boolean, default=False)  
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bookings = db.relationship('Booking', backref='user', lazy=True)

class Car(db.Model):
    """Car model for database"""
    __tablename__ = 'cars'
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(80), nullable=False)
    model = db.Column(db.String(80), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    registration_number = db.Column(db.String(20), unique=True, nullable=False)  
    engine_capacity = db.Column(db.Float)  
    seating_capacity = db.Column(db.Integer, nullable=False)  
    transmission = db.Column(db.String(20))  
    fuel_type = db.Column(db.String(20)) 
    availability = db.Column(db.Boolean, nullable=False, default=True)
    price_per_day = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(200))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bookings = db.relationship('Booking', backref='car', lazy=True)

class Booking(db.Model):
    """Booking model for database"""
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    car_id = db.Column(db.Integer, db.ForeignKey('cars.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    total_cost = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def is_car_available(car_id, start_date, end_date):
    """Check if car is available for given dates"""
    overlapping_bookings = Booking.query.filter(
        Booking.car_id == car_id,
        Booking.status == 'confirmed',
        db.and_(
            Booking.start_date <= end_date,
            Booking.end_date >= start_date
        )
    ).count()
    return overlapping_bookings == 0

def calculate_total_cost(car_id, start_date, end_date):
    """Calculate total cost for a booking"""
    car = Car.query.get(car_id)
    if not car:
        return 0
    days = (end_date - start_date).days + 1
    return car.price_per_day * days

def generate_token(email):
    """Generate password reset token"""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

def verify_token(token, expiration=3600):
    """Verify password reset token"""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
    except Exception as e:
        print(f"Token error: {e}")
        return False
    return email

def time_ago(dt):
    """Convert datetime to relative time string"""
    now = datetime.utcnow()
    diff = now - dt
    
    seconds = diff.total_seconds()
    days = divmod(seconds, 86400)  
    hours = divmod(days[1], 3600) 
    minutes = divmod(hours[1], 60) 
    if days[0] > 0:
        return f"{int(days[0])} days ago"
    elif hours[0] > 0:
        return f"{int(hours[0])} hours ago"
    elif minutes[0] > 0:
        return f"{int(minutes[0])} minutes ago"
    else:
        return "just now"

# Register time_ago as a Jinja2 filter
app.jinja_env.filters['time_ago'] = time_ago

# Context processors to make variables available in all templates
@app.context_processor
def inject_user():
    """Make current_user available in all templates"""
    return dict(current_user=current_user)

@app.context_processor
def inject_datetime():
    """Make datetime module available in all templates"""
    from datetime import datetime
    return dict(datetime=datetime)

@app.context_processor
def inject_today():
    """Make today's date available in all templates"""
    return {'today': datetime.now().date()}

@app.context_processor
def utility_processor():
    """URL utility function for search pagination"""
    def updated_url(**kwargs):
        args = request.args.copy().to_dict()
        args.update(kwargs) 
        return f"{url_for('search_cars')}?{urlencode(args)}"
    return dict(updated_url=updated_url)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    return User.query.get(int(user_id))

# Debug route for authentication testing
@app.route("/debug-auth")
def debug_auth():
    return f"Authenticated: {current_user.is_authenticated}, User: {current_user.get_id() if current_user.is_authenticated else 'None'}"

# Password reset routes
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset requests (simulated)"""
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = generate_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)
            flash(f'Password reset link (simulated): {reset_url}', 'info')
            return redirect(url_for('login'))
        
        flash('If that email exists, we would have sent a reset link', 'info')
        return redirect(url_for('login'))
    
    return render_template('auth/forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handle password reset form"""
    email = verify_token(token)
    if not email:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
        else:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Password updated successfully!', 'success')
            return redirect(url_for('login'))
    
    return render_template('auth/reset_password.html', token=token)

# Authentication decorators
def login_required(f):
    """Decorator to ensure user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to ensure user is admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Main application routes
@app.route('/')
def index():
    """Main landing page"""
    if current_user.is_authenticated:
        return render_template('user_dashboard.html')
    else:
        cars = Car.query.all()
        cars_data = [{
            'id': car.id,
            'make': car.make,
            'model': car.model,
            'year': car.year,
            'price_per_day': float(car.price_per_day), 
            'image_url': car.image_url,
            'seats' : car.seating_capacity,
            'description': car.description
        } for car in cars]
        return render_template('index.html', cars=cars_data)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash('Login successful!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout route"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        license_number = request.form['license_number']
        license_expiry = request.form['license_expiry']
        phone_number = request.form['phone_number']
        date_of_birth = request.form['date_of_birth']
        address = request.form['address']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please use a different email or login.', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        try:
            license_expiry_date = datetime.strptime(license_expiry, '%Y-%m-%d').date()
            dob = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('register'))
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            license_number=license_number,
            license_expiry=license_expiry_date,
            phone_number=phone_number,
            date_of_birth=dob,
            address=address
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while registering. Please try again.', 'danger')
            app.logger.error(f"Registration error: {str(e)}")

    return render_template('auth/register.html')

# Admin routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard with statistics"""
    total_cars = Car.query.count()
    total_users = User.query.count()
    total_bookings = Booking.query.count()
    recent_bookings = Booking.query.order_by(Booking.created_at.desc()).limit(5).all()
    total_revenue = db.session.query(func.sum(Booking.total_cost)).filter(
        Booking.status == 'confirmed'
    ).scalar() or 0
    bookings = Booking.query.all()

    bookings_per_month = [0] * 12
    for booking in bookings:
        month = booking.start_date.month
        bookings_per_month[month - 1] += 1

    status_counts = defaultdict(int)
    for booking in bookings:
        status_counts[booking.status] += 1

    return render_template(
        'admin/dashboard.html',
        total_cars=total_cars,
        total_users=total_users,
        total_bookings=total_bookings,
        total_revenue=total_revenue,
        recent_bookings=recent_bookings,
        bookings_per_month=bookings_per_month,
        status_counts=dict(status_counts)
    )

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin user management page"""
    search = request.args.get('search', '')
    role = request.args.get('role', '')
    status = request.args.get('status', '')
    new_users = request.args.get('new', '')
    page = request.args.get('page', 1, type=int)
   
    query = User.query
    
    if search:
        query = query.filter(
            db.or_(
                User.username.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )
    
    if role:
        query = query.filter_by(role=role)

    if new_users:
        thirty_days_ago = datetime.utcnow() - timedelta(days=int(new_users))
        query = query.filter(User.created_at >= thirty_days_ago)

    total_users_count = User.query.count()
    admin_users_count = User.query.filter_by(role='admin').count()
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    new_users_count = User.query.filter(User.created_at >= thirty_days_ago).count()
    users_pagination = query.order_by(User.created_at.desc()).paginate(page=page, per_page=10)
    
    return render_template(
        'admin/users.html',
        users=users_pagination.items,
        pagination=users_pagination,
        total_users_count=total_users_count,
        admin_users_count=admin_users_count,
        new_users_count=new_users_count,
        search=search,
        role_filter=role,
        status_filter=status,
        new_filter=new_users
    )

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user"""
    if 'user_id' not in session:
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('login'))
    
    if session['user_id'] == user_id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    if user.bookings and len(user.bookings) > 0:
        flash('Cannot delete user. The user has existing bookings.', 'warning')
        return redirect(url_for('admin_users'))

    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    """Toggle user verification status"""
    if 'user_id' not in session:
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('login'))
    if session['user_id'] == user_id:
        flash("You cannot change your own status", "danger")
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    user.verified = not user.verified
    
    try:
        db.session.commit()
        status = "verified" if user.verified else "unverified"
        flash(f"User {user.username} is now {status}", "success")
    except Exception as e:
        db.session.rollback()
        flash("Failed to update user status", "danger")
        app.logger.error(f"Error toggling user status: {str(e)}")
    
    return redirect(url_for('admin_users'))
    
@app.route('/admin/cars')
@admin_required
def admin_cars():
    """Admin car management page"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    cars = Car.query.paginate(page=page, per_page=per_page)
    return render_template('admin/cars.html', cars=cars.items, pagination=cars)

@app.route('/admin/cars/add', methods=['GET', 'POST'])
@admin_required
def add_car():
    """Add a new car"""
    if request.method == 'POST':
        make = request.form['make']
        model = request.form['model']
        price_per_day = float(request.form['price_per_day'])
        year = int(request.form['year'])
        registration_number = request.form['registration_number']  
        availability = 'availability' in request.form
        engine_capacity = request.form.get('engine_capacity')
        seating_capacity = request.form.get('seating_capacity')
        transmission = request.form.get('transmission')
        fuel_type = request.form.get('fuel_type')
        
        if 'image' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['image']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_url = url_for('static', filename=f'images/{filename}')
        else:
            flash('Allowed file types are png, jpg, jpeg, gif', 'danger')
            return redirect(request.url)
        
        new_car = Car(
            make=make,
            model=model,
            year=year,
            registration_number=registration_number,  
            price_per_day=price_per_day,
            availability=availability,
            image_url=image_url,
            description=request.form['description'],
            engine_capacity=engine_capacity,
            seating_capacity=seating_capacity,
            transmission=transmission,
            fuel_type=fuel_type
        )
        
        db.session.add(new_car)
        db.session.commit()
        
        flash('Car added successfully!', 'success')
        return redirect(url_for('admin_cars'))
    
    return render_template('admin/add_car.html', datetime=datetime)

@app.route('/admin/cars/toggle/<int:car_id>', methods=['POST'])
@admin_required
def toggle_car_availability(car_id):
    """Toggle car availability"""
    try:
        car = Car.query.get_or_404(car_id)
        car.availability = not car.availability
        db.session.commit()
        flash(f'Car availability updated', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to update availability', 'danger')
        app.logger.error(f"Error toggling availability: {str(e)}")
    return redirect(url_for('admin_cars'))

@app.route('/admin/cars/edit/<int:car_id>', methods=['GET', 'POST'])
@admin_required
def edit_car(car_id):
    """Edit car details"""
    car = Car.query.get_or_404(car_id)
    
    if request.method == 'POST':
        car.make = request.form['make']
        car.model = request.form['model']
        car.year = int(request.form['year'])
        car.registration_number = request.form['registration_number']
        car.price_per_day = float(request.form['price_per_day'])
        car.availability = 'availability' in request.form
        car.description = request.form['description']
        car.engine_capacity = request.form.get('engine_capacity')
        car.seating_capacity = request.form.get('seating_capacity')
        car.transmission = request.form.get('transmission')
        car.fuel_type = request.form.get('fuel_type')
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                car.image_url = url_for('static', filename=f'images/{filename}')
        
        db.session.commit()
        flash('Car updated successfully!', 'success')
        return redirect(url_for('admin_cars'))
    
    return render_template('admin/edit_car.html', car=car, datetime=datetime)

@app.route('/admin/cars/delete/<int:car_id>', methods=['POST'])
@admin_required
def delete_car(car_id):
    """Delete a car"""
    car = Car.query.get_or_404(car_id)
    
    Booking.query.filter_by(car_id=car_id).delete()

    db.session.delete(car)
    db.session.commit()
    
    flash('Car and its bookings have been deleted!', 'success')
    return redirect(url_for('admin_cars'))

@app.route('/admin/bookings')
@admin_required
def admin_bookings():
    """Admin booking management page with status filtering"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    status_filter = request.args.get('status', 'all')
    query = Booking.query
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    bookings_pagination = query.order_by(Booking.created_at.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    
    return render_template(
        'admin/bookings.html',
        bookings=bookings_pagination.items,
        pagination=bookings_pagination,
        status_filter=status_filter
    )

@app.route('/admin/bookings/update_status/<int:booking_id>', methods=['POST'])
@admin_required
def update_booking_status(booking_id):
    """Update booking status"""
    booking = Booking.query.get_or_404(booking_id)
    new_status = request.form['status']
    
    booking.status = new_status
    db.session.commit()
    
    flash('Booking status updated!', 'success')
    return redirect(url_for('admin_bookings'))

# User routes
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    """User dashboard page"""
    user = User.query.get(session['user_id'])
    
    bookings_count = Booking.query.filter_by(user_id=user.id).count()
    
    active_bookings_count = Booking.query.filter_by(
        user_id=user.id,
        status='confirmed'
    ).count()

    total_spent = db.session.query(
        func.sum(Booking.total_cost)
    ).filter(
        Booking.user_id == user.id,
        Booking.status == 'confirmed'
    ).scalar() or 0 

    recent_bookings = Booking.query.filter_by(
        user_id=user.id
    ).order_by(
        Booking.created_at.desc()
    ).limit(5).all()
    
    return render_template(
        'user/dashboard.html',
        user=user,
        bookings_count=bookings_count,
        active_bookings_count=active_bookings_count,
        total_spent=total_spent,
        recent_bookings=recent_bookings
    )

@app.route('/user/cars')
def search_cars():
    """Car search page"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search_query = request.args.get('search_query', '')
    min_price = request.args.get('min_price', None)
    max_price = request.args.get('max_price', None)
    
    try:
        min_price = float(min_price) if min_price not in [None, ''] else None
    except (ValueError, TypeError):
        min_price = None
        
    try:
        max_price = float(max_price) if max_price not in [None, ''] else None
    except (ValueError, TypeError):
        max_price = None
    min_year = request.args.get('min_year', 0, type=int)
    available_only = request.args.get('available_only', 'false') == 'true'
    transmission = request.args.get('transmission', '')
    fuel_type = request.args.get('fuel_type', '')
    sort = request.args.get('sort', '')

    query = Car.query
    if search_query:
        query = query.filter(
            db.or_(
                Car.make.ilike(f'%{search_query}%'),
                Car.model.ilike(f'%{search_query}%')
            )
        )
    if min_price is not None:
        query = query.filter(Car.price_per_day >= min_price)
    if max_price is not None:
        query = query.filter(Car.price_per_day <= max_price)
    if min_year > 0:
        query = query.filter(Car.year >= min_year)
    if available_only:
        query = query.filter(Car.availability == True)
    if transmission:
        query = query.filter(Car.transmission == transmission)
    if fuel_type:
        query = query.filter(Car.fuel_type == fuel_type)
    if sort == 'price_asc':
        query = query.order_by(Car.price_per_day.asc())
    elif sort == 'price_desc':
        query = query.order_by(Car.price_per_day.desc())
    elif sort == 'year_desc':
        query = query.order_by(Car.year.desc())
    elif sort == 'year_asc':
        query = query.order_by(Car.year.asc())
    else:
        query = query.order_by(Car.created_at.desc())
    cars_pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    current_year = datetime.now().year
    years = list(range(current_year, current_year - 20, -1))

    return render_template(
        'user/search.html',
        cars=cars_pagination.items,
        pagination=cars_pagination,
        current_year=current_year,
        search_params=request.args,
        total_cars=query.count()
    )

@app.route('/user/cars/<int:car_id>')
def car_details(car_id):
    """Car details page"""
    car = Car.query.get_or_404(car_id)
    return render_template('user/car_details.html', car=car)

@app.route('/user/bookings')
@login_required
def user_bookings():
    """User bookings page with status filtering"""
    user = User.query.get(session['user_id'])
    page = request.args.get('page', 1, type=int)
    per_page = 10
    status_filter = request.args.get('status', 'all') 
    query = Booking.query.filter_by(user_id=user.id)
    
    if status_filter and status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    bookings_pagination = query.order_by(Booking.created_at.desc()).paginate(
        page=page, 
        per_page=per_page,
        error_out=False
    )
    
    today = datetime.now().date()
    return render_template(
        'user/bookings.html',
        bookings=bookings_pagination.items,
        pagination=bookings_pagination,
        today=today,
        status_filter=status_filter
    )

@app.route('/user/bookings/new/<int:car_id>', methods=['GET', 'POST'])
def new_booking(car_id):
    """Create new booking"""
    car = Car.query.get_or_404(car_id)
    
    if request.method == 'POST':
        start_date_str = request.form['start_date']
        end_date_str = request.form['end_date']
        
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        
        if start_date > end_date:
            flash('End date must be after start date.', 'danger')
            return redirect(url_for('new_booking', car_id=car_id))
        
        if not is_car_available(car_id, start_date, end_date):
            flash('This car is not available for the selected dates.', 'danger')
            return redirect(url_for('new_booking', car_id=car_id))
        
        total_cost = calculate_total_cost(car_id, start_date, end_date)
        
        new_booking = Booking(
            user_id=session['user_id'],
            car_id=car_id,
            start_date=start_date,
            end_date=end_date,
            total_cost=total_cost,
            status='pending'
        )
        
        db.session.add(new_booking)
        db.session.commit()
        
        flash('Booking confirmed!', 'success')
        return redirect(url_for('user_bookings'))

    today = datetime.now().date()
    tomorrow = today + timedelta(days=1)
    
    return render_template('user/booking.html', car=car, today=today, tomorrow=tomorrow)

@app.route('/user/bookings/cancel/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    """Cancel a booking"""
    booking = Booking.query.get_or_404(booking_id)
 
    if booking.user_id != session['user_id']:
        flash('You can only cancel your own bookings.', 'danger')
        return redirect(url_for('user_bookings'))

    if booking.start_date < datetime.now().date():
        flash('You can only cancel future bookings.', 'danger')
        return redirect(url_for('user_bookings'))
    
    booking.status = 'cancelled'
    db.session.commit()
    
    flash('Booking cancelled!', 'success')
    return redirect(url_for('user_bookings'))

# API routes
@app.route('/api/check_availability/<int:car_id>')
def check_availability(car_id):
    """API endpoint to check car availability"""
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    
    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid date format'}), 400
    
    if start_date > end_date:
        return jsonify({'error': 'End date must be after start date'}), 400
    
    available = is_car_available(car_id, start_date, end_date)
    total_cost = calculate_total_cost(car_id, start_date, end_date) if available else 0
    
    return jsonify({
        'available': available,
        'total_cost': total_cost
    })

# Main application entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)

