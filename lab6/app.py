from flask import Flask, render_template, send_from_directory
from flask_migrate import Migrate
from sqlalchemy.exc import SQLAlchemyError
from models import db, Category, Image
from auth import bp as auth_bp, init_login_manager
from courses import bp as courses_bp

# Создание экземпляра Flask приложения
app = Flask(__name__)
application = app

# Загрузка конфигурации из файла config.py
app.config.from_pyfile('config.py')

# Инициализация базы данных и миграций
db.init_app(app)
migrate = Migrate(app, db)

# Инициализация менеджера логинов
init_login_manager(app)

# Обработка ошибок базы данных
@app.errorhandler(SQLAlchemyError)
def handle_sqlalchemy_error(err):
    error_msg = ('Возникла ошибка при подключении к базе данных. '
                 'Повторите попытку позже.')
    return f'{error_msg} (Подробнее: {err})', 500

# Регистрация blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(courses_bp)

# Главная страница
@app.route('/')
def index():
    categories = db.session.execute(db.select(Category)).scalars()
    return render_template(
        'index.html',
        categories=categories,
    )

# Маршрут для получения изображений
@app.route('/images/<image_id>')
def image(image_id):
    img = db.get_or_404(Image, image_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               img.storage_filename)
