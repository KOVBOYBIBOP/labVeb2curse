from flask import Flask, render_template, session, request, redirect, url_for, flash
# Импортируем необходимые модули из Flask

from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
# Импортируем необходимые компоненты из Flask-Login для управления аутентификацией пользователей

app = Flask(__name__)
# Создаем экземпляр Flask-приложения

application = app
# Создаем алиас application для совместимости с некоторыми хостингами

app.config.from_pyfile("config.py")
# Загружаем конфигурацию приложения из файла config.py

login_manager = LoginManager()
# Создаем экземпляр LoginManager для управления аутентификацией

login_manager.login_view = 'enter'
# Указываем представление (URL), которое будет использоваться для входа пользователей

login_manager.login_message = 'Пожалуйста, авторизуйтесь.'
# Устанавливаем сообщение, которое будет отображаться неавторизованным пользователям

login_manager.login_message_category = 'warning'
# Устанавливаем категорию сообщения (для стилизации)

login_manager.init_app(app)
# Инициализируем LoginManager с приложением

class User(UserMixin):
    # Определяем класс User, который наследует UserMixin для работы с Flask-Login
    def __init__(self, login, user_id):
        self.login = login
        self.id = user_id
    # Конструктор, принимающий логин и ID пользователя

@login_manager.user_loader
# Указываем функцию, которая будет загружать пользователя по ID

def load_user(user_id):
    for user_data in users_list():
        if user_data["user_id"] == user_id:
            return User(user_data['login'], user_data['user_id'])
    return None
    # Ищем пользователя по ID в списке пользователей и возвращаем объект User

def users_list():
    # Определяем функцию, возвращающую список пользователей (обычно данные берутся из базы данных)
    return [{"user_id": "3", "login": "login", "password": "password"}, {"user_id": "4", "login": "user", "password":"qwerty"}]

    # Определяем функцию, возвращающую список пользователей (обычно данные берутся из базы данных)
    return [{"user_id": "3", "login": "login", "password": "password"}, {"user_id": "4", "login": "user", "password":"qwerty"}]

@app.route('/')
# Определяем маршрут для главной страницы

def index():
    return render_template('index.html')
    # Отображаем шаблон index.html

@app.route('/counter')
# Определяем маршрут для счетчика посещений

def counter():
    if not("counter" in session):
        session["counter"] = 1
        # Если счетчик не существует в сессии, создаем его и устанавливаем в 1
    else:
        session["counter"] += 1
        # Если счетчик существует, увеличиваем его на 1
    return render_template('counter.html')
    # Отображаем шаблон counter.html

@app.route('/enter', methods=['post', 'get'])
# Определяем маршрут для страницы входа, обрабатывающий как GET, так и POST запросы

def enter():
    massage=''
    if request.method == 'POST':
        user_login = request.form['login']
        user_password = request.form['password']
        check_remember = True if request.form.get('user_remember') else False
        # Получаем данные из формы: логин, пароль и опцию "запомнить меня"

        for user in users_list():
            if user_login == user['login'] and user_password == user['password']:
                login_user(User(user['login'], user['user_id']), remember=check_remember)
                flash("Вход выполнен успешно", "success")
                # Если логин и пароль совпадают, авторизуем пользователя и показываем сообщение об успешном входе

                return redirect(request.args.get('next', url_for('index')))
                # Перенаправляем на следующую страницу или на главную, если next не указан

        massage = 'Введены неверные данные'
        flash(massage, "danger")
        # Если данные неверны, показываем сообщение об ошибке
    return render_template('enter.html')
    # Отображаем шаблон enter.html

@app.route('/logout')
# Определяем маршрут для выхода пользователя

def logout():
    logout_user()
    return redirect(url_for('index'))
    # Выходим пользователя и перенаправляем на главную страницу

@app.route('/secret')
@login_required
# Определяем маршрут для секретной страницы, доступной только авторизованным пользователям

def secret():
    # if not current_user.is_authenticated:
    #     flash("Доступ только авторизованным пользователям", "warning")
    #     return redirect(url_for('index'))
    # Эти строки закомментированы, так как декоратор @login_required уже обеспечивает проверку аутентификации
    return render_template('secret.html')
    # Отображаем шаблон secret.html
      

# Комментарии для установки и запуска приложения
# python3 -m venv ve  # Создаем виртуальное окружение
# . ve/bin/activate -- Linux  # Активируем виртуальное окружение в Linux
# ve\Scripts\activate -- Windows  # Активируем виртуальное окружение в Windows
# pip install flask python-dotenv  # Устанавливаем необходимые пакеты

if __name__ == '__main__':
    app.run(debug=True)