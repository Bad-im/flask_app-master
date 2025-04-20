import hashlib
import os
import base64
import pyotp
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from datetime import datetime

# Инициализация базовых объектов
db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        # Генерация соли
        self.salt = base64.b64encode(os.urandom(32)).decode('utf-8')

        # Хэширование пароля с солью
        password_hash = hashlib.sha256((password + self.salt).encode()).hexdigest()
        self.password_hash = password_hash

    def check_password(self, password):
        # Проверка пароля с использованием соли
        password_hash = hashlib.sha256((password + self.salt).encode()).hexdigest()
        return self.password_hash == password_hash

    def enable_2fa(self):
        # Генерация секретного ключа для TOTP
        self.otp_secret = pyotp.random_base32()
        self.is_2fa_enabled = True
        return self.otp_secret

    def get_totp_uri(self):
        # Получение URI для QR-кода
        return pyotp.totp.TOTP(self.otp_secret).provisioning_uri(
            name=self.username,
            issuer_name="Financial Manager"
        )

    def verify_totp(self, token):
        # Проверка TOTP кода с допуском временного окна
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token, valid_window=1)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), nullable=False, default='USD')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='accounts')


# Настройка приложения Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация расширений
db.init_app(app)
bcrypt.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    accounts = current_user.accounts
    total_balance = sum(account.balance for account in accounts)
    return render_template('index.html', accounts=accounts, total_balance=total_balance)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.is_2fa_enabled:
                session['user_id_for_2fa'] = user.id
                return redirect(url_for('verify_2fa'))
            else:
                login_user(user)
                return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'user_id_for_2fa' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id_for_2fa']
    user = User.query.get(user_id)

    if not user:
        session.pop('user_id_for_2fa', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')

        if user.verify_totp(otp_code):
            login_user(user)
            session.pop('user_id_for_2fa', None)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный код аутентификации', 'error')

    return render_template('verify_2fa.html')


@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')

        if current_user.verify_totp(otp_code):
            flash('Двухфакторная аутентификация успешно настроена!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неверный код подтверждения', 'error')

    if not current_user.is_2fa_enabled:
        secret = current_user.enable_2fa()
        db.session.commit()

        totp_uri = current_user.get_totp_uri()

        return render_template('setup_2fa.html', secret=secret, totp_uri=totp_uri)

    return render_template('setup_2fa.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/accounts/add', methods=['GET', 'POST'])
@login_required
def add_account():
    if request.method == 'POST':
        name = request.form.get('name')
        balance = float(request.form.get('balance'))
        currency = request.form.get('currency')

        new_account = Account(
            name=name,
            balance=balance,
            currency=currency,
            user_id=current_user.id
        )
        db.session.add(new_account)
        db.session.commit()
        flash('Счет успешно добавлен!', 'success')
        return redirect(url_for('index'))

    return render_template('add_account.html')


@app.route('/accounts/edit/<int:account_id>', methods=['GET', 'POST'])
@login_required
def edit_account(account_id):
    account = Account.query.get_or_404(account_id)
    
    # Проверка что счет принадлежит текущему пользователю
    if account.user_id != current_user.id:
        flash('У вас нет прав для редактирования этого счета', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        account.name = request.form.get('name')
        account.balance = float(request.form.get('balance'))
        account.currency = request.form.get('currency')
        
        db.session.commit()
        flash('Счет успешно обновлен!', 'success')
        return redirect(url_for('index'))

    return render_template('edit_account.html', account=account)


@app.route('/accounts/delete/<int:account_id>', methods=['POST'])
@login_required
def delete_account(account_id):
    account = Account.query.get_or_404(account_id)
    
    if account.user_id != current_user.id:
        flash('У вас нет прав для удаления этого счета', 'error')
        return redirect(url_for('index'))

    db.session.delete(account)
    db.session.commit()
    flash('Счет успешно удален', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Создаем тестового пользователя, если его нет
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin")
            admin.set_password("password")
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)