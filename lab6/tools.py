import hashlib
import uuid
import os
from werkzeug.utils import secure_filename
from flask import current_app
from models import db, Course, Image

# Класс для фильтрации курсов
class CoursesFilter:
    def __init__(self, name, category_ids):
        self.name = name
        self.category_ids = category_ids
        self.query = db.select(Course)

    def perform(self):
        self.__filter_by_name()
        self.__filter_by_category_ids()
        return self.query.order_by(Course.created_at.desc())

    def __filter_by_name(self):
        if self.name:
            self.query = self.query.filter(
                Course.name.ilike('%' + self.name + '%'))

    def __filter_by_category_ids(self):
        if self.category_ids:
            self.query = self.query.filter(
                Course.category_id.in_(self.category_ids))

# Класс для сохранения изображений
class ImageSaver:
    def __init__(self, file):
        self.file = file

    def save(self):
        self.img = self.__find_by_md5_hash()
        if self.img is not None:
            return self.img
        file_name = secure_filename(self.file.filename)
        self.img = Image(
            id=str(uuid.uuid4()),
            file_name=file_name,
            mime_type=self.file.mimetype,
            md5_hash=self.md5_hash)
        save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], self.img.storage_filename)
        # Создание директории, если её нет
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        self.file.save(save_path)
        db.session.add(self.img)
        db.session.commit()
        return self.img

    def __find_by_md5_hash(self):
        self.md5_hash = hashlib.md5(self.file.read()).hexdigest()
        self.file.seek(0)
        return db.session.execute(db.select(Image).filter(Image.md5_hash == self.md5_hash)).scalar()
