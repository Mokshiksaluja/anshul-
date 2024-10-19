from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urban_harvest.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app)

# Model for Users
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)  # Email is unique and required
    phone = db.Column(db.String(20), unique=True, nullable=True)     # Phone is optional, unique if provided
    password_hash = db.Column(db.String(150), nullable=False)        # Store hashed passwords

    # Method to set the hashed password
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check the password against the hash
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


    # Method to set password (hashes the plain password)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check password (compares the provided password with the stored hash)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


    # Method to set a password
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Self-referential many-to-many relationship for friends
    friends = db.relationship('User', secondary='friendships', 
                              primaryjoin=(id == db.c.friendships.c.user_id),
                              secondaryjoin=(id == db.c.friendships.c.friend_id),
                              backref='friend_of', lazy='dynamic')

# Friendships join table
friendships = db.Table('friendships',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('friend_id', db.Integer, db.ForeignKey('user.id'))
)

# Model for Marketplace Items (seeds, soil, equipment)
class MarketItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)

# Model for Soil Source Database
class SoilSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(150), nullable=False)
    soil_type = db.Column(db.String(50), nullable=False)
    ph_level = db.Column(db.Float, nullable=False)

# Model for Posts
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.relationship('Like', backref='post', lazy=True)

# Model for Likes
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# Model for Friendships
friendships = db.Table('friendships',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('friend_id', db.Integer, db.ForeignKey('user.id'))
)

# Model for Reviews in Marketplace
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    market_item_id = db.Column(db.Integer, db.ForeignKey('market_item.id'), nullable=False)

# Flask-login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route for homepage
@app.route('/')
def index():
    return render_template('index.html')

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']

        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(email=email, phone=phone, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for('marketplace'))

    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('marketplace'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))
    
    return render_template('login.html')

# User Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Marketplace
@app.route('/marketplace')
@login_required
def marketplace():
    items = MarketItem.query.all()
    return render_template('marketplace.html', items=items)

# Add review to a marketplace item
@app.route('/review/<int:item_id>', methods=['POST'])
@login_required
def add_review(item_id):
    content = request.form['content']
    new_review = Review(content=content, market_item_id=item_id)
    db.session.add(new_review)
    db.session.commit()
    return redirect(url_for('marketplace'))

# Soil Source Database
@app.route('/soils')
@login_required
def soil_sources():
    soils = SoilSource.query.all()
    return render_template('soils.html', soils=soils)

# Create Post
@app.route('/post', methods=['POST'])
@login_required
def create_post():
    content = request.form['content']
    new_post = Post(content=content, user_id=current_user.id)
    db.session.add(new_post)
    db.session.commit()
    return redirect(url_for('index'))

# Like a post
@app.route('/like/<int:post_id>')
@login_required
def like_post(post_id):
    new_like = Like(user_id=current_user.id, post_id=post_id)
    db.session.add(new_like)
    db.session.commit()
    return redirect(url_for('index'))

# Chat functionality using SocketIO
@socketio.on('message')
def handle_message(data):
    emit('message', data, broadcast=True)

# Custom Error Handling
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Ensure the database and tables are created
    if not os.path.exists('urban_harvest.db'):
        db.create_all()  # Create database tables if they do not exist
    socketio.run(app, debug=True)