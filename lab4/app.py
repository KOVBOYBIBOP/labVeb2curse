from flask import Blueprint, Flask, render_template, url_for, request, session, redirect, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from mysql_db import MySQL
import re

app = Flask(__name__)

# Инициализация менеджера входа
login_manager = LoginManager()
login_manager.init_app(app)

# Инициализация базы данных MySQL
db = MySQL(app)

# Настройки менеджера входа
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к данной странице необходимо пройти аутентификацию'
login_manager.login_message_category = "warning"

application = app

# Загрузка конфигурации из файла
app.config.from_pyfile('config.py')

# Класс для представления пользователя
class User(UserMixin):
    def __init__(self, user_id, login):
        self.id = user_id
        self.login = login

# Загрузка пользователя из базы данных по user_id
@login_manager.user_loader
def load_user(user_id):
    cursor = db.connection().cursor(named_tuple=True)
    query = 'SELECT id, login FROM users WHERE users.id = %s'
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    if user:
        return User(user.id, user.login)
    return None

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

# Страница аутентификации
@app.route('/auth')
def auth():
    return render_template('auth.html')

# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        cursor = db.connection().cursor(named_tuple=True)
        query = 'SELECT * FROM users WHERE users.login = %s and users.password_hash = SHA2(%s, 256)'
        cursor.execute(query, (login, password))
        user = cursor.fetchone()
        cursor.close()
        if user:
            login_user(User(user.id, user.login), remember=remember)
            param = request.args.get('next')
            flash('Успешный вход', 'success')
            return redirect(param or url_for('index'))
        flash('Логин или пароль введены неверно', 'danger')
    return render_template('login.html')

# Страница выхода
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# Страница создания пользователя (доступна только аутентифицированным пользователям)
@app.route('/createuser', methods=["GET", "POST"])
@login_required
def createuser():
    errors_login = []
    errors_password = []
    errors_firstname = []
    errors_lastname = []

    if request.method == 'GET':
        return render_template('createuser.html')
    elif request.method == "POST":
        login = request.form['login']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        middle_name = ''

        if request.form['middle_name']:
            middle_name = request.form['middle_name']

        # Латинский и кириллический алфавиты
        latin_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        cyrillic_alphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя"

        # Проверка пароля
        if password == "":
            errors_password.append('Поле пароль не должно быть пустым')
        if len(password) < 8:
            errors_password.append('Пароль должен содержать не менее 8 символов')
        if len(password) > 128:
            errors_password.append('Пароль должен содержать не более 128 символов')
        if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
            errors_password.append('Пароль должен содержать минимум одну заглавную и одну строчную букву')
        if not all(c in latin_alphabet or c in cyrillic_alphabet or c.isdigit() for c in password):
            errors_password.append('Пароль должен содержать только латинские, кириллические буквы или цифры')
        if not any(c.isdigit() for c in password):
            errors_password.append('Пароль должен содержать как минимум одну цифру')
        if ' ' in password:
            errors_password.append('Пароль не должен содержать пробел')

        # Проверка логина
        if login == "":
            errors_login.append('Поле логин не должно быть пустым')
        if len(login) <= 5:
            errors_login.append('Логин должен содержать больше 5 символов')
        if not all(c in latin_alphabet or c in cyrillic_alphabet or c.isdigit() for c in login):
            errors_login.append('Логин должен содержать только буквы латинского алфавита и цифры')

        # Проверка имени и фамилии
        if last_name == "":
            errors_lastname.append('Поле фамилия не должно быть пустым')
        if first_name == "":
            errors_firstname.append('Поле имя не должно быть пустым')

        # Если есть ошибки, отображаем их
        if errors_firstname or errors_lastname or errors_login or errors_password:
            errors = {
                'errors_login': ", ".join(errors_login),
                'errors_password': ", ".join(errors_password),
                'errors_firstname': ", ".join(errors_firstname),
                'errors_lastname': ", ".join(errors_lastname)
            }

            values = {
                'login': login,
                'password': password,
                'firstname': first_name,
                'lastname': last_name
            }

            flash('Ошибки создания', 'danger')
            return render_template('createuser.html', errors=errors, values=values)

        # Проверка на существование пользователя с таким логином
        cursor = db.connection().cursor(named_tuple=True)
        query = 'SELECT * FROM users where login=%s'
        values = (login,)
        cursor.execute(query, values)
        user = cursor.fetchone()
        cursor.close()
        if user:
            flash('Пользователь с таким логином уже есть', 'danger')
            return redirect(url_for('createuser'))
        else:
            # Создание нового пользователя
            cursor = db.connection().cursor(named_tuple=True)
            query = 'INSERT INTO users (login, password_hash, first_name, last_name, middle_name) VALUES (%s, SHA2(%s, 256), %s, %s, %s)'
            values = (login, password, first_name, last_name, middle_name)
            cursor.execute(query, values)
            db.connection().commit()
            cursor.close()
            flash('Пользователь успешно создан', 'success')
            return redirect(url_for('index'))

# Страница со списком пользователей (доступна только аутентифицированным пользователям)
@app.route('/userlist')
@login_required
def userlist():
    cursor = db.connection().cursor(named_tuple=True)
    query = 'SELECT id, login, first_name, last_name, middle_name FROM users'
    cursor.execute(query)
    users = cursor.fetchall()
    cursor.close()
    return render_template('userlist.html', users=users)

# Страница с информацией о пользователе (доступна только аутентифицированным пользователям)
@app.route('/user/show/<int:user_id>')
@login_required
def showuser(user_id):
    cursor = db.connection().cursor(named_tuple=True)
    query = 'SELECT id, login, first_name, last_name, middle_name FROM users WHERE id=%s'
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('showuser.html', user=user)

# Страница редактирования пользователя (доступна только аутентифицированным пользователям)
@app.route('/user/edit/<int:user_id>', methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if request.method == 'POST':
        cursor = db.connection().cursor(named_tuple=True)
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        middle_name = request.form['middle_name']
        query = 'UPDATE users SET first_name=%s, last_name=%s, middle_name=%s WHERE id=%s'
        cursor.execute(query, (first_name, last_name, middle_name, user_id))
        db.connection().commit()
        cursor.close()
        cursor = db.connection().cursor(named_tuple=True)
        query = 'SELECT login from users WHERE id=%s'
        cursor.execute(query, (user_id,))
        login = cursor.fetchone()
        cursor.close()
        flash(f'Данные пользователя {login.login} изменены', 'success')
        return redirect(url_for('userlist'))

    cursor = db.connection().cursor(named_tuple=True)
    query = 'SELECT id, login, first_name, last_name, middle_name FROM users WHERE id=%s'
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('edit_user.html', user=user)

# Страница удаления пользователя (доступна только аутентифицированным пользователям)
@app.route('/user/delete/<int:user_id>', methods=["GET", "POST"])
@login_required
def delete_user(user_id):
    if request.method == 'POST':
        cursor = db.connection().cursor(named_tuple=True)
        query = 'SELECT login from users WHERE id=%s'
        cursor.execute(query, (user_id,))
        login = cursor.fetchone()
        cursor.close()
        cursor = db.connection().cursor(named_tuple=True)
        query = 'DELETE FROM users WHERE id=%s'
        cursor.execute(query, (user_id,))
        db.connection().commit()
        cursor.close()
        flash(f'Пользователь {login.login} удален', 'success')
        return redirect(url_for('userlist'))

    cursor = db.connection().cursor(named_tuple=True)
    query = 'SELECT id, login, first_name, last_name, middle_name FROM users WHERE id=%s'
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('delete_user.html', user=user)

@app.route('/change_password', methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == 'GET':
        return render_template('change_password.html')
    elif request.method == "POST":
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        repeat_new_password = request.form['repeat_new_password']

        if not old_password or not new_password or not repeat_new_password:
            flash('Поля не заполнены', 'danger')
            return redirect(url_for('change_password'))

        cursor = db.connection().cursor(named_tuple=True)
        query = 'SELECT login FROM users WHERE id=%s AND password_hash=SHA2(%s, 256)'
        values = (current_user.id, old_password)
        cursor.execute(query, values)
        login = cursor.fetchone()
        cursor.close()

        if login is None:
            flash('Неправильный старый пароль', 'danger')
            return redirect(url_for('change_password'))
        elif new_password != repeat_new_password:
            flash('Новые пароли не совпадают', 'danger')
            return redirect(url_for('change_password'))
        elif not validate_password(new_password):
            flash('Пароль несоответствует требованиям. Пароль должен содержать от 8 до 128 символов, минимум одну заглавную и одну строчную букву, только латинские и кириллические символы, как минимум одну цифру, только арабские цифры, без пробелов и другие допустимые символы: ~ ! ? @ # $ % ^ & * _ - + ( ) [ ] { } > < / \\ | \" \' . , : ;', 'danger')
            return redirect(url_for('change_password'))

        cursor = db.connection().cursor(named_tuple=True)
        query = 'UPDATE users SET password_hash=SHA2(%s, 256) WHERE id=%s'
        cursor.execute(query, (new_password, current_user.id))
        db.connection().commit()
        cursor.close()
        flash('Пароль успешно изменен', 'success')
        return redirect(url_for('index'))



# Функция для валидации пароля
def validate_password(password):
    if not re.match(r"^(?=.*[a-zа-я])(?=.*[A-ZА-Я])(?=.*\d)[A-Za-zА-Яа-я0-9~!@#$%^&*_\-\+()\[\]{}><\/\\|\"'\.,:;]{8,128}$", password):
        return False
    return True 

# Запуск приложения
if __name__ == '__main__':
    app.run()
