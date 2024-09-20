from sqlite3 import IntegrityError
from flask import Flask, request,send_file, render_template, redirect, session, url_for, jsonify,flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
from sqlalchemy import create_engine, inspect
import logging
import json
import os
import qrcode  # Import QR code library
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import LargeBinary
import urllib.parse
from sqlalchemy import create_engine, inspect, Table, MetaData
import requests
from io import BytesIO
from flask_login import login_required
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy import and_
from datetime import datetime
import pyodbc
import traceback 
from flask_migrate import Migrate
from flask_login import LoginManager
import random
import threading
import time

from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user
# Load environment variables from .env file


from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, Float, Date
from utils import hash_password



# Instantiate Flask application
app = Flask(__name__)

# Initialize the LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# Set the login view (this will redirect users to the login page if they try to access a protected route)
login_manager.login_view = 'login'  # This should match your login route

# Optionally, set a custom login message if a user is redirected
login_manager.login_message = "Please log in to access this page."

@login_manager.user_loader
def load_user(user_id):
    # Assuming you are using SQLAlchemy to retrieve the user by their ID
    return User.query.get(int(user_id))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

api_logger = logging.getLogger(__name__)

Base = declarative_base()
# Define conversion table
conversion_table = {
    240: 8.875,
    234: 8.625,
    228: 8.375,
    222: 8.125,
    215: 7.875,
    209: 7.625,
    203: 7.375,
    197: 7.125,
    196: 7.125,
    190: 6.875,
    183: 6.625,
    177: 6.375,
    170: 6.125,
    164: 5.875,
    158: 5.625,
    151: 5.375,
    152: 5.375,
    144: 5.125,
    138: 4.875,
    131: 4.625,
    125: 4.375,
    118: 4.125,
    111: 3.875,
    105: 3.625,
    98: 3.375,
    91: 3.125,
    85: 2.875,
    78: 2.625,
    71: 2.375,
    70: 2.225,
    64: 2.125,
    57: 1.875,
    50: 1.625,
    51: 1.625,
    42: 1.375,
    35: 1.125,
    28: 0.875,
    21: 0.625,
    19: 0.696,
    14: 0.375,
    6: 0.125,
    0: 0,
    "Sensor Dead Band": 0,
}








class AdminDashboard(db.Model):
    __tablename__ = 'admin_dashboards'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dashboard_data = db.Column(db.Text, nullable=True, default='{}')  # JSON data for the dashboard
    admin = db.relationship('User', backref=db.backref('dashboard', uselist=False))






def reset_dashboard_data(admin_id):
    super_admin_email = 'admin@gmail.com'
    super_admin = User.query.filter_by(email=super_admin_email).first()
    
    if super_admin and super_admin.id == admin_id:
        return  # Skip resetting data for the super admin

    dashboard = AdminDashboard.query.filter_by(admin_id=admin_id).first()
    
    if not dashboard:
        # Create a new dashboard if it doesn't exist
        dashboard = AdminDashboard(admin_id=admin_id, dashboard_data=json.dumps({
            "cards": [],
            "tables": [],
            "charts": []
        }))
        db.session.add(dashboard)
    else:
        # Reset the existing dashboard for regular admins
        dashboard.dashboard_data = json.dumps({
            "cards": [],
            "tables": [],
            "charts": []
        })
    
    db.session.commit()

    # Clear LevelSensorData only for non-super admins
    if not super_admin or super_admin.id != admin_id:
        table_name = f'level_sensor_data_{admin_id}'
        
        # Drop existing table if it exists
        LevelSensorData = get_or_create_level_sensor_data_class(table_name)
        LevelSensorData.__table__.drop(db.engine, checkfirst=True)  # Drop the table
        
        # Recreate the table
        LevelSensorData.__table__.create(db.engine, checkfirst=True)
        
        db.session.commit()
# Function to get or create the dynamic table
def get_or_create_level_sensor_data_class(table_name):
    engine = db.engine
    metadata = MetaData(bind=engine)
    
    # Check if the table is already defined in metadata
    if table_name not in Base.metadata.tables:
        # Define the dynamic class for the given table name
        class LevelSensorData(Base):
            __tablename__ = table_name
            __table_args__ = {'extend_existing': True}

            id = db.Column(db.Integer, primary_key=True)
            date = db.Column(db.DateTime)
            full_addr = db.Column(db.Integer)
            sensor_data = db.Column(db.Float)
            vehicleno = db.Column(db.String(50))
            volume_liters = db.Column(db.Float)
            qrcode = db.Column(db.LargeBinary)
            pdf = db.Column(db.LargeBinary)

            def __init__(self, date, full_addr, sensor_data, vehicleno, volume_liters):
                self.date = date
                self.full_addr = full_addr
                self.sensor_data = sensor_data
                self.vehicleno = vehicleno
                self.volume_liters = volume_liters
                self.qrcode = self.generate_qr_code(self.vehicleno)
                self.pdf = self.generate_pdf()

            def generate_qr_code(self, id):
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=4,
                    border=4,
                )
                url = url_for('generate_pdf', id=id, _external=True)
                qr.add_data(url)
                qr.make(fit=True)

                img = qr.make_image(fill='black', back_color='white')
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                return buf.getvalue()

            def generate_pdf(self):
                buffer = io.BytesIO()
                c = canvas.Canvas(buffer, pagesize=letter)
                c.drawString(100, 750, f"Date: {self.date}")
                c.drawString(100, 730, f"Full Address: {self.full_addr}")
                c.drawString(100, 710, f"Sensor Data: {self.sensor_data}")
                c.drawString(100, 690, f"Vehicle no: {self.vehicleno}")
                c.drawString(100, 670, f"Volume (liters): {self.volume_liters}")
                c.showPage()
                c.save()

                buffer.seek(0)
                return buffer.getvalue()

        # Bind the new class to the Base's metadata
        Base.metadata.create_all(engine, tables=[LevelSensorData.__table__])
        return LevelSensorData
    else:
        # Reflect the existing table into the model class
        class LevelSensorData(Base):
            __tablename__ = table_name
            __table_args__ = {'autoload_with': engine}

        return LevelSensorData

    
class UserAccount(db.Model):
    __tablename__ = 'user_accounts'

    id = db.Column(db.Integer, primary_key=True)
    accountname = db.Column(db.String(100), nullable=False)
    accountemail = db.Column(db.String(100), unique=True, nullable=False)
    accountpassword = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    status = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


    # Method to set the hashed password
    def set_password(self, password):
        self.accountpassword = generate_password_hash(password)

    # Method to check the hashed password
    def check_password(self, password):
        return check_password_hash(self.accountpassword, password)
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hashed_password = db.Column(db.String(200), nullable=False)  # Ensure this length is appropriate
    name = db.Column(db.String(50))
    is_admin = db.Column(db.Boolean, default=False)
    status = db.Column(db.Boolean, default=True)
    is_super_admin = db.Column(db.Boolean, default=False)

    def __init__(self, email, password, name, is_admin, status, is_super_admin):
        self.email = email
        self.name = name
        self.is_admin = is_admin
        self.status = status
        self.is_super_admin = is_super_admin
        self.hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
 
    def hash_password(password):
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed.decode('utf-8')

    def check_password(stored_password_hash, provided_password):
        try:
            return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password_hash.encode('utf-8'))
        except ValueError as e:
            print(f"Error checking password: {e}")
            return False

    
class UserMixin:
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    
class LevelSensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    date = db.Column(db.DateTime)
    full_addr = db.Column(db.Integer)
    sensor_data = db.Column(db.Float)
    vehicleno = db.Column(db.String(50))
    volume_liters = db.Column(db.Float)  # New column for converted volumes
    qrcode = db.Column(LargeBinary)
    pdf = db.Column(LargeBinary)
   
    def __init__(self, date, full_addr, sensor_data, vehicleno, volume_liters):
        self.date = datetime.strptime(date, '%d/%m/%Y %H:%M:%S')  # Parse date string into datetime object with time
        self.full_addr = full_addr
        self.sensor_data = sensor_data
        self.vehicleno = vehicleno
        self.volume_liters = volume_liters
        


    def generate_qr_code(self):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=4,
            border=4,
        )
        url = url_for('generate_pdf', id=self.id, _external=True)
        qr.add_data(url)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        self.qrcode = buf.getvalue()

    def generate_pdf(self):
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.drawString(100, 750, f"Date: {self.date}")
        c.drawString(100, 730, f"Full Address: {self.full_addr}")
        c.drawString(100, 710, f"Sensor Data: {self.sensor_data}")
        c.drawString(100, 690, f"vehicleno: {self.vehicleno}")
        c.drawString(100, 670, f"Volume (liters): {self.volume_liters}")
        c.showPage()
        c.save()

        buffer.seek(0)
        self.pdf = buffer.getvalue()
    
    def __repr__(self):
        return (f"<LevelSensorData(date='{self.date}', full_addr='{self.full_addr}', "
                f"sensor_data={self.sensor_data}, vehicleno='{self.vehicleno}', "
                f"volume_liters={self.volume_liters})>")

def create_admin_user():
    admin_email = 'admin@gmail.com'
    admin_password = 'securepassword'  # Replace with a real password
    admin_name = 'Admin'
    status = True  # Adjust as needed

    # Check if the admin user already exists
    existing_admin = User.query.filter_by(email=admin_email).first()

    if existing_admin:
        print("Admin user already exists")
        return

    # Hash the password
    hashed_password = hash_password(admin_password)
    print(f"Hashed Password: {hashed_password}")

    # Create a new admin user
    admin_user = User(
        email=admin_email,
        password=hashed_password,  # Pass the password here
        name=admin_name,
        is_admin=True,
        status=status,
        is_super_admin=True
    )

    # Debugging
    print(f"Admin User: {admin_user}")

    # Add and commit the new user to the database
    db.session.add(admin_user)
    try:
        db.session.commit()
        print("Admin user created successfully")
    except Exception as e:
        print(f"Error creating admin user: {e}")













with app.app_context():
    db.create_all()
    create_admin_user()  # Call the function to create the admin user
    

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        is_admin = request.form.get('is_admin') == 'on'
        is_super_admin = False
        status = True

        new_user = User(name=name, email=email, password=password, is_admin=is_admin, status=status, is_super_admin=is_super_admin)
        db.session.add(new_user)
        db.session.commit()

        if is_admin:
            reset_dashboard_data(new_user.id)  # Reset dashboard for new admin

        flash('Signup successful!')
        return redirect(url_for('index'))
    
    return render_template('signup.html')




@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin')

    if not name or not email or not password:
        return jsonify({"message": "Please provide name, email, isAdmin and password"}), 400

    try:
        if User.query.filter_by(email=email).first():
            return jsonify({"message": "Email already registered"}), 400

        new_user = User(name=name, email=email, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        if is_admin:
            # Create a blank dashboard for the new admin
            new_dashboard = AdminDashboard(admin_id=new_user.id)
            db.session.add(new_dashboard)
            db.session.commit()

        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500
        
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            session['is_admin'] = user.is_admin

            if user.is_admin and not is_super_admin(user):
                reset_dashboard_data(user.id)

            return redirect(url_for('admin_dashboard', adminname=user.name))  # Redirect to dynamic dashboard
        else:
            error = 'Invalid credentials. Please try again.'

    return render_template('login.html', error=error)









@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data['email']
    password = data['password']
    is_admin = data['is_admin']

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['email'] = user.email
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401



@app.route('/dashboard/<adminname>')
def admin_dashboard(adminname):
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()

        if user is None:
            return redirect('/login')

        if user.name != adminname:
            return redirect(url_for('admin_dashboard', adminname=user.name))

        # Load or reset the admin's dashboard data
        dashboard_data = AdminDashboard.query.filter_by(admin_id=user.id).first()
        if dashboard_data:
            dashboard_content = json.loads(dashboard_data.dashboard_data)
        else:
            dashboard_content = {
                "cards": [],
                "tables": [],
                "charts": []
            }
            new_dashboard_data = AdminDashboard(
                admin_id=user.id,
                dashboard_data=json.dumps(dashboard_content)
            )
            db.session.add(new_dashboard_data)
            db.session.commit()

        # Fetch data from the /api/level_sensor_data/<admin_name> endpoint
        api_url = url_for('level_sensor_data', admin_name=adminname, _external=True)
        response = requests.get(api_url)
        api_data = response.json()

        if response.status_code == 200 and isinstance(api_data, list):
            sense_data = []
            for data_point in api_data:
                # Convert date string to a datetime object using the custom format
                try:
                    data_point['date'] = datetime.strptime(data_point['date'], '%d/%m/%Y %H:%M:%S')
                    data_point['volume_liters'] = get_volume(data_point['sensor_data'])
                    sense_data.append(data_point)
                except (ValueError, KeyError) as e:
                    print(f"Error processing data point: {e}")
                    continue
        else:
            sense_data = []

        filter_option = request.args.get('filter', 'latest')
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('query', '')

        # Use the dynamic table class for this admin
        table_name = f'level_sensor_data_{adminname}'
        LevelSensorData = get_or_create_level_sensor_data_class(table_name)

        query = db.session.query(LevelSensorData)

        if search_query:
            try:
                search_id = int(search_query)
                query = query.filter(
                    (LevelSensorData.id == search_id) |
                    (LevelSensorData.date.like(f'%{search_query}%')) |
                    (LevelSensorData.full_addr.like(f'%{search_query}%')) |
                    (LevelSensorData.sensor_data.like(f'%{search_query}%')) |
                    (LevelSensorData.vehicleno.like(f'%{search_query}%'))
                )
            except ValueError:
                query = query.filter(
                    (LevelSensorData.date.like(f'%{search_query}%')) |
                    (LevelSensorData.full_addr.like(f'%{search_query}%')) |
                    (LevelSensorData.sensor_data.like(f'%{search_query}%')) |
                    (LevelSensorData.vehicleno.like(f'%{search_query}%'))
                )

        if filter_option == 'oldest':
            query = query.order_by(LevelSensorData.date.asc())
        else:
            query = query.order_by(LevelSensorData.date.desc())

        sense_data_pagination = query.paginate(page=page, per_page=10)
        sense_data = sense_data_pagination.items

        # Prepare data for the chart
        labels = [data_point.date.strftime('%d/%m/%Y %H:%M:%S') for data_point in sense_data]
        volume_liters = [data_point.volume_liters for data_point in sense_data]

        return render_template(
            'dashboard.html',
            user=user,
            sense_data=sense_data,
            filter_option=filter_option,
            pagination=sense_data_pagination,
            search_query=search_query,
            dashboard_content=dashboard_content,
            labels=labels,
            volume_liters=volume_liters
        )
    return redirect('/login')









@app.route('/dashboard')
@login_required
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()

        if user is None:
            user = UserAccount.query.filter_by(accountemail=session['email']).first()

            if current_user.is_authenticated:
                return render_template('dashboard.html')
            else:
                return redirect(url_for('login'))
        if user is None:
            # User not found, redirect to login or show an error message
            return redirect('/login')

        # Load the admin's dashboard data and reset if necessary
        if user.is_admin:
            dashboard_data = AdminDashboard.query.filter_by(admin_id=user.id).first()
            if dashboard_data:
                dashboard_content = json.loads(dashboard_data.dashboard_data)
            else:
                # Reset the dashboard for new admin
                dashboard_content = {
                    "cards": [],  # Reset cards to empty list
                    "tables": [],  # Reset tables to empty list
                    "charts": []   # Reset charts to empty list
                }
                # Save the reset state to the database
                new_dashboard_data = AdminDashboard(
                    admin_id=user.id,
                    dashboard_data=json.dumps(dashboard_content)
                )
                db.session.add(new_dashboard_data)
                db.session.commit()

        filter_option = request.args.get('filter', 'latest')
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('query', '')

        query = LevelSensorData.query

        if search_query:
            # Split search_query to handle numerical and textual searches
            try:
                search_id = int(search_query)
                query = query.filter(
                    (LevelSensorData.id == search_id) |
                    (LevelSensorData.date.like(f'%{search_query}%')) |
                    (LevelSensorData.full_addr.like(f'%{search_query}%')) |
                    (LevelSensorData.sensor_data.like(f'%{search_query}%')) |
                    (LevelSensorData.vehicleno.like(f'%{search_query}%'))
                )
            except ValueError:
                query = query.filter(
                    (LevelSensorData.date.like(f'%{search_query}%')) |
                    (LevelSensorData.full_addr.like(f'%{search_query}%')) |
                    (LevelSensorData.sensor_data.like(f'%{search_query}%')) |
                    (LevelSensorData.vehicleno.like(f'%{search_query}%'))
                )

        if filter_option == 'oldest':
            query = query.order_by(LevelSensorData.date.asc())
        else:
            query = query.order_by(LevelSensorData.date.desc())

        sense_data_pagination = query.paginate(page=page, per_page=10)
        sense_data = sense_data_pagination.items

        for data_point in sense_data:
            data_point.volume_liters = get_volume(data_point.sensor_data)

        # Check if the user is an instance of UserAccount and pass the appropriate role
        user_role = user.is_admin if isinstance(user, UserAccount) else user.is_super_admin

        return render_template(
            'dashboard.html',
            user_role=user_role,  # Pass user role to template
            sense_data=sense_data,
            filter_option=filter_option,
            pagination=sense_data_pagination,
            search_query=search_query,
            dashboard_content=dashboard_content, # Pass the reset or existing dashboard content
            user=current_user
        )
    return redirect('/login')





@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('email', None)
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    else:
        return jsonify({"message": "User not found"}), 404

logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

api_logger = logging.getLogger('api_logger')
api_handler = logging.FileHandler('apilog.txt')
api_handler.setLevel(logging.INFO)
api_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
api_logger.addHandler(api_handler)


@app.route('/level_sensor_data', methods=['POST'])
def receive_level_sensor_data():
    if request.method == 'POST':
        try:
            if not request.is_json:
                api_logger.error("Request content type is not JSON")
                return jsonify({'status': 'failure', 'message': 'Request content type is not JSON'}), 400
            request_data = request.get_json()
            modbus_test_data = request_data.get('level_sensor_data', '{}')
            try:
                sense_data = json.loads(modbus_test_data)
            except json.JSONDecodeError:
                api_logger.error("Invalid JSON format in modbus_TEST")
                return jsonify({'status': 'failure', 'message': 'Invalid JSON format in modbus_TEST'}), 400

            api_logger.info("API called with data: %s", sense_data)

            # Extracting data from JSON
            date = sense_data.get('D', '')
            full_addr = sense_data.get('address', 0)
            sensor_data = sense_data.get('data', [])
            vehicleno = sense_data.get('Vehicle no', '')

            if not all([date, full_addr, sensor_data, vehicleno]):
                api_logger.error("Missing required data fields")
                return jsonify({'status': 'failure', 'message': 'Missing required data fields'}), 400

            # Ensure sensor_data is a list and extract the first element
            if isinstance(sensor_data, list) and sensor_data:
                sensor_data = sensor_data[0]
            else:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Convert sensor_data to float
            try:
                sensor_data = float(sensor_data)
            except ValueError:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Fetch volume from conversion table
            volume_liters = get_volume(sensor_data)
            if volume_liters is None:
                api_logger.error("Failed to convert sensor data to volume")
                return jsonify({'status': 'failure', 'message': 'Failed to convert sensor data to volume'}), 400

            # Create a new LevelSensorData object with volume_liters and add it to the database
            new_data = LevelSensorData(date=date, full_addr=full_addr, sensor_data=sensor_data, vehicleno=vehicleno, volume_liters=volume_liters)
            db.session.add(new_data)
            db.session.commit()

            # Log success
            api_logger.info("Data stored successfully: %s", json.dumps(sense_data))

            # Return a response
            response = {'status': 'success', 'message': 'Data received and stored successfully'}
            return jsonify(response), 200

        except Exception as e:
            # Log failure
            api_logger.error("Failed to store data: %s", e)
            return jsonify({'status': 'failure', 'message': 'Failed to store data'}), 500

    api_logger.info("Received non-POST request at /level_sensor_data, redirecting to /dashboard")
    return redirect('/dashboard')


@app.route('/api/device_entries_logged', methods=['GET'])
def api_device_entries_logged():
    if 'email' in session:
        count = LevelSensorData.query.count()
        return jsonify({"device_entries_logged": count}), 200
    return jsonify({"message": "Unauthorized"}), 401

@app.route('/api/no_of_devices_active', methods=['GET'])
def api_no_of_devices_active():
    if 'email' in session:
        active_devices = db.session.query(db.func.count(db.distinct(LevelSensorData.vehicleno))).scalar()
        return jsonify({"no_of_devices_active": active_devices}), 200
    return jsonify({"message": "Unauthorized"}), 401

@app.route('/search', methods=['GET'])
def search_sensor_data():
    query = request.args.get('query', '')
    page = request.args.get('page', 1, type=int)

    query_obj = LevelSensorData.query

    if query:
        # Split search_query to handle numerical and textual searches
        try:
            search_id = int(query)
            query_obj = query_obj.filter(
                (LevelSensorData.id == search_id) |
                (LevelSensorData.date.like(f'%{query}%')) |
                (LevelSensorData.full_addr.like(f'%{query}%')) |
                (LevelSensorData.sensor_data.like(f'%{query}%')) |
                (LevelSensorData.vehicleno.like(f'%{query}%'))
            )
        except ValueError:
            query_obj = query_obj.filter(
                (LevelSensorData.date.like(f'%{query}%')) |
                (LevelSensorData.full_addr.like(f'%{query}%')) |
                (LevelSensorData.sensor_data.like(f'%{query}%')) |
                (LevelSensorData.vehicleno.like(f'%{query}%'))
            )
    
    # Ensure an ORDER BY clause is applied
    query_obj = query_obj.order_by(LevelSensorData.date.desc())

    sense_data_pagination = query_obj.paginate(page=page, per_page=10)
    sense_data = sense_data_pagination.items

    user = User.query.filter_by(email=session.get('email')).first()

    return render_template(
        'dashboard.html',
        user=user,
        sense_data=sense_data,
        pagination=sense_data_pagination,
        search_query=query
    )


# Fetch the volume from the conversion table
def get_volume(sensor_data):
    if sensor_data in conversion_table:
        return conversion_table[sensor_data]
    else:
        numeric_keys = [key for key in conversion_table if isinstance(key, int)]
        lower_key = max(key for key in numeric_keys if key <= sensor_data)
        upper_keys = [key for key in numeric_keys if key > sensor_data]
        if upper_keys:
            upper_key = min(upper_keys)
            return interpolate(lower_key, conversion_table[lower_key], upper_key, conversion_table[upper_key], sensor_data)
        return None

def interpolate(x1, y1, x2, y2, x):
    return round(y1 + ((y2 - y1) / (x2 - x1)) * (x - x1), 3)


@app.route('/api/sensor_data')
def get_sensor_data():
    try:
        sensor_data = LevelSensorData.query.all()
        if not sensor_data:
            return jsonify(error='No data available'), 404

        labels = [data.date.strftime('%d/%m/%Y %H:%M:%S') for data in sensor_data]
        sensor_values = [data.sensor_data for data in sensor_data]
        volume_liters = [data.volume_liters for data in sensor_data]

        return jsonify(labels=labels, sensorData=sensor_values, volumeLiters=volume_liters)
    except Exception as e:
        print(f"Error fetching sensor data: {str(e)}")
        return jsonify(error='Internal server error'), 500
    

    #qr and pdf
# QR and PDF generation routes
@app.route('/generate_pdf/<int:id>', methods=['GET'])
def generate_pdf(id):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.drawString(100, 750, f"Record ID: {id}")
    p.showPage()
    p.save()
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"record_{id}.pdf",
        mimetype='application/pdf'
    )


@app.route('/generate_qr/<int:id>')
def generate_qr(id):
    pdf_url = url_for('generate_pdf', id=id, _external=True)  # Generate PDF route URL

    # Create QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=4,
        border=2,
    )
    qr.add_data(pdf_url)  # Encode PDF URL in the QR code
    qr.make(fit=True)
    
    img = qr.make_image(fill='black', back_color='white')
    img_io = io.BytesIO()
    img.save(img_io, format='PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')

# Create a route to handle redirection from QR code to PDF
@app.route('/scan_qr/<vehicleno>', methods=['GET'])
def scan_qr(vehicleno):
    record = LevelSensorData.query.filter_by(vehicleno=vehicleno).first_or_404()
    return redirect(url_for('generate_pdf', id=record.id))




#create a simulation button

simulation_thread = None
simulation_running = False


def run_simulation():
    global simulation_running
    while simulation_running:
        # Simulation logic: generate random data
        test_data = {
            'D': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            'address': '400001', 
            'data': [random.randint(50, 200)],  # Random data between 50 and 200
            'Vehicle no': '0448'
        }
        # Send test data to your existing endpoint
        with app.test_client() as client:
            response = client.post('/level_sensor_data', json={'level_sensor_data': json.dumps(test_data)})
            print(f'Simulation data sent: {response.json}')
        time.sleep(60)  # Adjust the interval as needed

@app.route('/start_simulation', methods=['POST'])
def start_simulation():
    global simulation_thread, simulation_running
    if simulation_running:
        return jsonify({'message': 'Simulation already running'}), 400

    simulation_running = True
    simulation_thread = threading.Thread(target=run_simulation)
    simulation_thread.start()
    return jsonify({'message': 'Simulation started successfully'}), 200

@app.route('/stop_simulation', methods=['POST'])
def stop_simulation():
    global simulation_running
    if not simulation_running:
        return jsonify({'message': 'No simulation running'}), 400

    simulation_running = False
    simulation_thread.join()
    return jsonify({'message': 'Simulation stopped successfully'}), 200


#settings butoon for column 

@app.route('/settings')
def settings():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        if user.is_admin:
            return render_template('settings.html', title="Settings")
        else:
            return redirect('/dashboard')  # Redirect to dashboard or another page
    return redirect('/login')
  

@app.route('/client-onboarding')
def client_onboarding():
    return render_template('client_onboarding.html')

@app.route('/access-onboarding')
def access_onboarding():
    return render_template('access_onboarding.html')



#to display table 
@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    result = [
        {"id": user.id, "name": user.name, "email": user.email, "is_admin": user.is_admin, "status": user.status}
        for user in users
    ]
    return jsonify(result)



@app.route('/api/counts', methods=['GET'])
def get_counts():
    total_clients = User.query.filter_by(is_admin=0).count()
    total_companies = User.query.filter_by(is_admin=1).count()  # Adjust this if necessary
    return jsonify({
        'totalClients': total_clients,
        'totalCompanies': total_companies
    })


# Route to update user status
@app.route('/api/users/<int:user_id>/status', methods=['POST'])
def update_user_status(user_id):
    user = User.query.get(user_id)
    if user:
        data = request.get_json()
        user.status = data['status']
        db.session.commit()
        return jsonify({"message": "User status updated"}), 200
    return jsonify({"message": "User not found"}), 404



    
# Route to update user role (is_admin)
@app.route('/api/users/<int:user_id>/role', methods=['POST'])
def update_user_role(user_id):
    user = User.query.get(user_id)
    if user:
        data = request.get_json()
        user.is_admin = int(data['is_admin'])
        db.session.commit()
        return jsonify({"message": "User role updated"}), 200
    return jsonify({"message": "User not found"}), 404
    
# Ensure that only logged-in admins can access the route
@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return "Unauthorized", 403

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        is_admin = request.form.get('is_admin', 0)  # Defaults to 0 if not provided

        new_user = User(name=name, email=email, password=password, is_admin=int(is_admin))
        db.session.add(new_user)
        db.session.commit()
        return redirect('/admin/add-user')

    return render_template('add_user.html')  # This should be the path to your form template


#add users from user pov

@app.route('/add_user_account', methods=['POST'])
def add_user_account():
    accountname = request.form['accountname']
    accountemail = request.form['accountemail']
    accountpassword = request.form['accountpassword']
    accountrole = request.form['accountrole']
    
    

    # Create new user account in the database
    new_account = UserAccount(
        accountname=accountname,
        accountemail=accountemail,
        accountpassword=accountpassword,  # Ensure to hash passwords in a real application
        is_admin=True if accountrole == '1' else False
    )
    
    # Set the password using the method to hash it
    new_account.set_password(accountpassword)
    
    db.session.add(new_account)
    db.session.commit()

    return jsonify({'message': 'User account added successfully'}), 201


@app.route('/api/user_accounts', methods=['GET'])
def get_user_accounts():
    users = UserAccount.query.all()
    user_list = [
        {
            'id': user.id,
            'accountname': user.accountname,
            'accountemail': user.accountemail,
            'is_admin': user.is_admin,
            'status': user.status
        }
        for user in users
    ]
    return jsonify(user_list)


@app.route('/api/user_accounts/<int:account_id>/status', methods=['POST'])
def update_user_account_status(account_id):
    user = UserAccount.query.get(account_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    status = request.json.get('status')
    user.status = status
    db.session.commit()
    return jsonify({'message': 'User status updated successfully'})

@app.route('/api/user_accounts/<int:account_id>/role', methods=['POST'])
def update_role(account_id):
    user = User.query.get(account_id)
    new_role = request.json.get('role')
    
    if user:
        user.is_admin = new_role == 'admin'
        user.is_super_admin = user.email == 'admin@gmail.com'
        
        if user.is_admin:
            get_or_create_level_sensor_data_class(f'level_sensor_data_{user.name}')
        
        try:
            db.session.commit()
            return jsonify({'message': 'Role updated successfully!'}), 200
        except IntegrityError:
            db.session.rollback()
            return jsonify({'message': 'Error updating role.'}), 500
    else:
        return jsonify({'message': 'User not found.'}), 404

@app.route('/api/account_counts', methods=['GET'])
def get_account_counts():
    total_accounts = UserAccount.query.filter_by(is_admin=False).count()
    active_accounts = UserAccount.query.filter_by(status=True).count()
    return jsonify({
        'totalAccounts': total_accounts,
        'activeAccounts': active_accounts
    })

@app.route('/api/level_sensor_data/<admin_name>', methods=['GET', 'POST'])
def level_sensor_data(admin_name):
    table_name = f'level_sensor_data_{admin_name}'
    LevelSensorData = get_or_create_level_sensor_data_class(table_name)

    if request.method == 'POST':
        try:
            data = request.json
            if not data:
                return jsonify({'message': 'No data provided'}), 400

            level_sensor_data_str = data.get('level_sensor_data', '')
            if not level_sensor_data_str:
                return jsonify({'message': 'No level_sensor_data field in JSON'}), 400

            try:
                level_sensor_data = json.loads(level_sensor_data_str)
            except json.JSONDecodeError:
                return jsonify({'message': 'Invalid JSON format in level_sensor_data'}), 400

            date_str = level_sensor_data.get('D', '')
            full_addr = level_sensor_data.get('address', 0)
            sensor_data_list = level_sensor_data.get('data', [])
            vehicleno = level_sensor_data.get('Vehicle no', '')

            if not all([date_str, full_addr, sensor_data_list, vehicleno]):
                missing_fields = []
                if not date_str: missing_fields.append('date')
                if full_addr is None: missing_fields.append('full_addr')
                if not sensor_data_list: missing_fields.append('sensor_data')
                if not vehicleno: missing_fields.append('vehicleno')
                return jsonify({'message': f'Missing required fields: {", ".join(missing_fields)}'}), 400

            if isinstance(sensor_data_list, list) and sensor_data_list:
                sensor_data = sensor_data_list[0]
            else:
                return jsonify({'message': 'Invalid sensor data format'}), 400

            try:
                sensor_data = float(sensor_data)
            except ValueError:
                return jsonify({'message': 'Invalid sensor data format'}), 400

            try:
                date = datetime.strptime(date_str, '%d/%m/%Y %H:%M:%S')
            except ValueError:
                return jsonify({'message': 'Date format is incorrect, should be %d/%m/%Y %H:%M:%S'}), 400

            volume_liters = get_volume(sensor_data)
            if volume_liters is None:
                return jsonify({'message': 'Sensor data value not found in conversion table'}), 400

            new_data = LevelSensorData(
                date=date,
                full_addr=full_addr,
                sensor_data=sensor_data,
                vehicleno=vehicleno,
                volume_liters=volume_liters
            )
            db.session.add(new_data)
            db.session.commit()
            return jsonify({'message': 'Data added successfully!'}), 201

        except Exception as e:
            print(f"Error occurred: {e}")
            return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

    elif request.method == 'GET':
        try:
            data = db.session.query(LevelSensorData).all()
            result = [{
                'id': d.id,
                'date': d.date.strftime('%d/%m/%Y %H:%M:%S') if d.date else None,
                'full_addr': d.full_addr,
                'sensor_data': d.sensor_data,
                'vehicleno': d.vehicleno,
                'volume_liters': d.volume_liters
            } for d in data]
            return jsonify(result)
        except Exception as e:
            print(f"Error occurred while retrieving data: {e}")
            return jsonify({'message': 'An error occurred while retrieving data', 'error': str(e)}), 500







def is_super_admin(user):
    return user.email == 'admin@gmail.com'

def create_dynamic_admin_route(admin_id):
    endpoint = f"/api/admin/{admin_id}/data"

    @app.route(endpoint, methods=['POST'])
    def dynamic_admin_data():
        data = request.json
        return jsonify({"message": f"Data received for admin {admin_id}"}), 200

    return endpoint
from datetime import datetime
import json
import base64  # For encoding bytes to string

def custom_json_serializer(obj):
    if isinstance(obj, datetime):
        # Convert datetime object to a string
        return obj.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(obj, bytes):
        # Convert bytes to a base64 encoded string
        return base64.b64encode(obj).decode('utf-8')
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

def custom_json_serializer(obj):
    if isinstance(obj, datetime):
        return obj.strftime('%Y-%m-%d %H:%M:%S')
    raise TypeError("Type not serializable")




@app.route('/api/admin/<adminname>/sensor_data', methods=['GET', 'POST'])
def manage_sensor_data(adminname):
    user = User.query.filter_by(name=adminname).first()
    if not user:
        return jsonify({"message": "Admin not found"}), 404

    table_name = f'level_sensor_data_{adminname}'
    metadata = MetaData()
    level_sensor_table = Table(
        table_name, metadata,
        autoload_with=db.engine,
        extend_existing=True
    )

    if request.method == 'GET':
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # Convert start_date and end_date to datetime objects
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d %H:%M:%S')
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return jsonify({"message": "Invalid date format"}), 400

        # Fetching data within the date range
        with db.engine.connect() as connection:
            query = level_sensor_table.select().where(
                and_(
                    level_sensor_table.c.date >= start_date_obj,
                    level_sensor_table.c.date <= end_date_obj
                )
            )
            result = connection.execute(query).fetchall()

        # Manually convert data to JSON serializable format
        data = [dict(row) for row in result]
        for row in data:
            for key, value in row.items():
                if isinstance(value, datetime):
                    row[key] = value.strftime('%Y-%m-%d %H:%M:%S')  # Format the datetime object

        return jsonify(data)

    elif request.method == 'POST':
        # Adding new sensor data
        data = request.json.get('level_sensor_data')
        if not data:
            return jsonify({"message": "Invalid data"}), 400

        parsed_data = json.loads(data)
        date_str = parsed_data.get('D')

        try:
            date_obj = datetime.strptime(date_str, '%d/%m/%Y %H:%M:%S')
        except ValueError:
            return jsonify({"message": "Invalid date format"}), 400

        sensor_data_value = parsed_data.get('data')[0]
        volume_liters = get_volume(sensor_data_value)

        new_data = {
            "date": date_obj,
            "full_addr": parsed_data.get('address'),
            "sensor_data": sensor_data_value,
            "vehicleno": parsed_data.get('Vehicle no'),
            "volume_liters": volume_liters
        }

        with db.engine.connect() as connection:
            connection.execute(level_sensor_table.insert().values(new_data))

        return jsonify({"message": f"Data added to {table_name}"}), 201


# Route to add a new company
# Route to display form and add a company
import logging
@app.route('/add_company', methods=['GET', 'POST'])
@login_required
def add_company():
    if request.method == 'GET':
        # Render the form or page for adding a company
        return render_template('add_company.html', user=current_user)
    
    if request.method == 'POST':
        # Handle POST request
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin')

        # Validate form data
        if not name or not email or not password or not is_admin:
            return jsonify({"error": "Please fill out all fields"}), 400

        is_super_admin = True if email == 'admin@gmail.com' else False
        status = True

        try:
            # Create a new user
            new_user = User(
                email=email,
                name=name,
                is_admin=int(is_admin),
                status=status,
                is_super_admin=is_super_admin
            )
            new_user.set_password(password)  # Hash the password before storing it
            db.session.add(new_user)
            db.session.commit()

            # Create a new table for the new company
            table_name = f'level_sensor_data_{name}'
            get_or_create_level_sensor_data_class(table_name)

            return jsonify({"message": "Company added successfully!"}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Error adding company: {str(e)}"}), 500
    
    
from flask import request, jsonify
from datetime import datetime

@app.route('/api/fetch_level_sensor_data_range/<admin_name>', methods=['GET'])
def fetch_level_sensor_data_range(admin_name):
    # Dynamically set the table name
    table_name = f'level_sensor_data_{admin_name}'
    
    # Get the ORM class for the dynamically generated table
    LevelSensorData = get_or_create_level_sensor_data_class(table_name)

    # Get query parameters for start_date and end_date
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    if not start_date_str or not end_date_str:
        return jsonify({'message': 'Please provide both start_date and end_date'}), 400

    try:
        # Convert string dates to datetime objects
        start_date = datetime.strptime(start_date_str, '%d/%m/%Y %H:%M:%S')
        end_date = datetime.strptime(end_date_str, '%d/%m/%Y %H:%M:%S')
    except ValueError:
        return jsonify({'message': 'Incorrect date format, should be %d/%m/%Y %H:%M:%S'}), 400

    try:
        # Query the database for records between the start_date and end_date
        data = db.session.query(LevelSensorData)\
                         .filter(LevelSensorData.date >= start_date)\
                         .filter(LevelSensorData.date <= end_date)\
                         .all()

        # Prepare the response
        result = [{
            'id': d.id,
            'date': d.date.strftime('%d/%m/%Y %H:%M:%S') if d.date else None,
            'full_addr': d.full_addr,
            'sensor_data': d.sensor_data,
            'vehicleno': d.vehicleno,
            'volume_liters': d.volume_liters
        } for d in data]

        # If no data is found, return an appropriate message
        if not result:
            return jsonify({'message': 'No data found for the selected range'}), 404

        return jsonify(result), 200
    except Exception as e:
        print(f"Error occurred while retrieving data: {e}")
        return jsonify({'message': 'An error occurred while retrieving data', 'error': str(e)}), 500
    
if __name__ == '__main__':
    
    app.run(debug=True)
