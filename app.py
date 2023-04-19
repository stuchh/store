import os
import random
import flask_admin
from flask import Flask, render_template, request, abort, flash
from flask_admin import form
from flask_admin.contrib.sqla import ModelView
from flask_admin.form import Select2Field
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_admin import AdminIndexView, expose
from flask_login import current_user
from flask import redirect, url_for

app = Flask(__name__, template_folder=os.path.abspath('/templates'))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SECRET_KEY'] = 'super secret key'
app.config['STORAGE'] = 'static/products_img/'
login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)


class Catalog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    products = db.relationship('Product', backref='catalog', lazy=True)
    image = db.Column(db.String(255))


class Collections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    products = db.relationship('Product', backref='collections', lazy=True)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    description = db.Column(db.String(255))
    count_available = db.Column(db.Integer)
    image = db.Column(db.String(255))
    catalog_id = db.Column(db.Integer, db.ForeignKey('catalog.id'))
    collection_id = db.Column(db.Integer, db.ForeignKey('collections.id'))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean(), default=False)

    def __repr__(self):
        return f'<User {self.name}>'

    def get_id(self):
        return str(self.id)

    # Кринге полный, переделывай
    def is_authenticated(self):
        return True


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<Cart {self.user_id}:{self.product_id}>"

    def add_to_cart(self, product_id, quantity):
        user_id = current_user.id
        cart_item = Cart.query.filter_by(user_id=user_id, product_id=product_id).first()
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = Cart(user_id=user_id, product_id=product_id, quantity=quantity)
            db.session.add(cart_item)
        db.session.commit()

    def remove_from_cart(self, product_id):
        user_id = current_user.id
        cart_item = Cart.query.filter_by(user_id=user_id, product_id=product_id).first()
        if cart_item:
            db.session.delete(cart_item)
            db.session.commit()

    def update_quantity(self, product_id, quantity):
        user_id = current_user.id
        cart_item = Cart.query.filter_by(user_id=user_id, product_id=product_id).first()
        if cart_item:
            cart_item.quantity = quantity
            db.session.commit()

    def get_cart_items(self, user_id):
        return Cart.query.filter_by(user_id=user_id).all()

    def clear_cart(self, user_id):
        Cart.query.filter_by(user_id=user_id).delete()
        db.session.commit()


class MyAdminIndexView(AdminIndexView):
    @expose("/")
    def index(self):
        if not current_user:
            return redirect(url_for('userlogin'))
        if current_user.is_admin:
            return super(MyAdminIndexView, self).index()
        abort(404)

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin


class StorageAdminModel(ModelView):
    form_extra_fields = {
        'file': form.FileUploadField('file')
    }

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def _change_path_data(self, _form):
        try:
            storage_file = _form.file.data

            if storage_file is not None:
                hash = random.getrandbits(128)
                ext = storage_file.filename.split('.')[-1]
                path = '%s.%s' % (hash, ext)

                storage_file.save(
                    os.path.join(app.config['STORAGE'], path)
                )

                _form.image.data = path

                del _form.file

        except Exception as ex:
            pass

        return _form

    def edit_form(self, obj=None):
        return self._change_path_data(
            super(StorageAdminModel, self).edit_form(obj)
        )

    def create_form(self, obj=None):
        return self._change_path_data(
            super(StorageAdminModel, self).create_form(obj)
        )


class ProductAdminModel(StorageAdminModel):
    form_extra_fields = {
        'catalog_id': Select2Field('Catalog', choices=[]),
        'collection_id': Select2Field('Collection', choices=[]),
        'file': form.FileUploadField('file')
    }

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def _change_path_data(self, _form):
        try:
            storage_file = _form.file.data

            if storage_file is not None:
                hash = random.getrandbits(128)
                ext = storage_file.filename.split('.')[-1]
                path = '%s.%s' % (hash, ext)

                storage_file.save(
                    os.path.join(app.config['STORAGE'], path)
                )

                _form.image.data = path

                del _form.file

        except Exception as ex:
            pass

        return _form

    def create_form(self, obj=None):
        form = super(ProductAdminModel, self).create_form(obj=obj)
        form.collection_id.choices = [(c.id, c.title) for c in Collections.query.all()]
        form.catalog_id.choices = [(c.id, c.title) for c in Catalog.query.all()]
        return form

    def edit_form(self, obj=None):
        form = super(StorageAdminModel, self).edit_form(obj=obj)
        form.collection_id.choices = [(c.id, c.title) for c in Collections.query.all()]
        return form


class UserView(ModelView):
    form_columns = ('name', 'email')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin


class CollectionView(ModelView):
    form_columns = ('title', 'products')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin


admin = flask_admin.Admin(app, index_view=MyAdminIndexView())
admin.add_view(ProductAdminModel(Product, db.session))
admin.add_view(StorageAdminModel(Catalog, db.session))
admin.add_view(CollectionView(Collections, db.session))
admin.add_view(UserView(User, db.session))


@app.route('/')
@app.route('/index')
def index():
    collections = Collections.query.order_by(Collections.title).all()
    catalog = Catalog.query.order_by(Catalog.title).all()
    print(current_user)
    return render_template('index.html', collections=collections, catalog=catalog, user=current_user)


@app.route('/info')
def info():
    return render_template('info.html', user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        # Проверяем, что все поля заполнены
        if not name or not email or not password:
            return render_template('register.html', notification='Заполните все поля', color='red', user=current_user)

        # Проверяем, что пользователь с таким email уже не зарегистрирован
        if User.query.filter_by(email=email).first():
            return render_template('register.html', notification='Пользователь с таким email уже зарегистрирован',
                                   color='red', user=current_user)

        # Создаем нового пользователя
        user = User(name=name, email=email, password=password_hash)

        # Добавляем пользователя в базу данных
        db.session.add(user)
        db.session.commit()

        return render_template('userlogin.html', notification='Регистрация прошла успешно', color='green',
                               user=current_user)
    else:
        return render_template('register.html', user=current_user)


@app.route('/catalog/<int:catalog_id>/product/<int:product_id>')
def product_page(catalog_id, product_id):
    catalogs = catalog_id
    product = Product.query.get(product_id)
    if product is None:
        abort(404)
    return render_template('product.html', product=product, catalog_id=catalogs, user=current_user)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/userlogin', methods=['GET', 'POST'])
def userlogin():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']

        # Find user by email
        user = User.query.filter_by(email=email).first()

        if not user or not user.password or not user.password.startswith('pbkdf2:sha256:'):
            # Invalid email or password hash format
            flash('Invalid email or password')
            return render_template('userlogin.html', notification='Неверный логин или пароль', color='red',
                                   user=current_user)

        if check_password_hash(user.password, password):
            # Password is correct, login the user
            login_user(user)

            flash('Logged in successfully.')
            return render_template('userlogin.html', notification='Вы успешно вошли!', color='green', user=current_user)
        else:
            # Password is incorrect
            flash('Invalid email or password')
            return render_template('userlogin.html', notification='Неверный логин или пароль', color='red',
                                   user=current_user)
    else:
        return render_template('userlogin.html', user=current_user)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        print(current_user.email)
        user = User.query.filter_by(email=current_user.email).first()
        last_password = request.form['lastpassword']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        if not user or not user.password or not user.password.startswith('pbkdf2:sha256:'):
            return "ЭЭЭЭЭЭЭ"
        if not (check_password_hash(user.password, last_password)):
            return render_template('profile.html', user=current_user, color="red", notification='Неверный пароль')
        elif last_password == password:
            return render_template('profile.html', user=current_user, color="red", notification='Пароли не должны \
             совпадать')
        else:
            user.password = password_hash
            db.session.commit()
            return render_template('profile.html', user=current_user, color="green", notification='Пароль успешно \
             изменён')



    else:
        return render_template('profile.html', user=current_user)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        # Change password
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(current_user.password, old_password):
            flash('Invalid password')
            return redirect(url_for('settings'))

        if new_password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('settings'))

        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Password changed successfully')
        return redirect(url_for('settings'))

    return render_template('settings.html', user=current_user)


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    db.session.delete(current_user)
    db.session.commit()

    logout_user()
    flash('Account deleted successfully')
    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/catalog')
def catalog():
    category = request.args.get('category')
    collections = Catalog.query.order_by(Catalog.title).all()
    if category:
        catalog = Catalog.query.filter_by(category=category).order_by(Catalog.title).all()
    else:
        catalog = Catalog.query.order_by(Catalog.title).all()
    return render_template('clothing_catalog.html', collections=collections, catalog=catalog, user=current_user)


@app.route('/catalog/<int:catalog_id>')
def catalog_tag(catalog_id):
    catalogs = Catalog.query.get(catalog_id)
    if catalogs is None:
        abort(404)
    collections = request.args.getlist('collection')
    collection = Collections.query.order_by(Collections.id).all()
    if not collections:
        product = Product.query.filter(Product.catalog_id == catalog_id).order_by(Product.name).all()
    else:
        product = Product.query.filter(Product.catalog_id == catalog_id, Product.collection_id.in_(collections)).all()
    return render_template('catalog.html', product=product, collection=collection, collections=collections,
                           catalog_id=catalog_id, user=current_user)


@app.route('/cart')
def cart():
    return render_template('cart.html', user=current_user)


if __name__ == '__main__':
    app.run(debug=True)
