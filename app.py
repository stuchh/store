from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SECRET_KEY'] = 'super secret key'

db = SQLAlchemy(app)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    description = db.Column(db.String(255))
    image = db.Column(db.String(255))
    in_stock = db.Column(db.Boolean())


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<User {self.name}>'


class ProductView(ModelView):
    form_columns = ('name', 'price', 'description', 'image', 'in_stock')


class UserView(ModelView):
    form_columns = ('name', 'email')


admin = Admin(app, name='Online Store Admin Panel')
admin.add_view(ProductView(Product, db.session))
admin.add_view(UserView(User, db.session))


@app.route('/')
@app.route('/index')
def index():
    items = Product.query.order_by(Product.price).all()
    return render_template('index.html', data=items)


@app.route('/about')
def about():
    return 'Здесь будет страница о нас'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        # Проверяем, что все поля заполнены
        if not name or not email or not password:
            return 'Заполните все поля'

        # Проверяем, что пользователь с таким email уже не зарегистрирован
        if User.query.filter_by(email=email).first():
            return 'Пользователь с таким email уже зарегистрирован'

        # Создаем нового пользователя
        user = User(name=name, email=email, password=password_hash)

        # Добавляем пользователя в базу данных
        db.session.add(user)
        db.session.commit()

        return 'Регистрация прошла успешно!'
    else:
        return render_template('register.html')


# Обработчик запроса на авторизацию
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Проверяем, что логин и пароль корректны
        if username == 'admin' and password == 'password':
            # Создаем сессию для администратора
            session['logged_in'] = True
            return redirect(url_for('admin.index'))

    return render_template('login.html')


# Декоратор для проверки авторизации администратора
def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Защищенный ресурс, доступный только для администраторов
@app.route('/admin')
@admin_login_required
def admin():
    return redirect(url_for('admin.index'))


if __name__ == '__main__':
    app.run(debug=True)
