from flask import Flask, render_template, request, make_response

app = Flask(__name__)
application = app

# Определение маршрута для главной страницы
@app.route('/')
def index():
    # Получаем текущий URL запроса
    url = request.url
    # Возвращаем шаблон index.html с передачей URL в качестве аргумента
    return render_template('index.html', url=url)

# Определение маршрута для страницы с параметрами URL
@app.route('/args')
def args():
    # Возвращаем шаблон args.html
    return render_template('args.html')

# Определение маршрута для страницы с заголовками запроса
@app.route('/headers')
def headers():
    # Возвращаем шаблон headers.html
    return render_template('headers.html')

# Определение маршрута для страницы с куки
@app.route('/cookies')
def cookies():
    # Создаем ответ на запрос с использованием шаблона cookies.html
    response = make_response(render_template('cookies.html'))
    # Проверяем, есть ли куки 'username' в запросе
    if 'username' in request.cookies:
        # Если есть, удаляем куки 'username' из ответа
        response.delete_cookie(key='username')
    else:
        # Если нет, устанавливаем куки 'username' в 'student'
        response.set_cookie('username', 'student')
    # Проверяем, есть ли куки 'password' в запросе
    if 'password' in request.cookies:
        # Если есть, удаляем куки 'password' из ответа
        response.delete_cookie(key='password')
    else:
        # Если нет, устанавливаем куки 'password' в '12345678'
        response.set_cookie('password', '12345678')
    # Возвращаем ответ
    return response 

# Определение маршрута для страницы с формой отправки
@app.route('/form', methods=['get',"post"])
def form():
    # Возвращаем шаблон form.html
    return render_template('form.html')

# Определение маршрута для страницы с калькулятором
@app.route('/calculate', methods=['GET', 'POST'])
def calculate():
    if request.method == "POST":
        # Получаем значения number1, number2 и operator из запроса
        number1 = request.form.get("number1")
        number2 = request.form.get("number2")
        operator = request.form.get("operator")

        # Проверяем, являются ли number1 и number2 числами
        if not (number1.isdigit() and number2.isdigit()):
            return render_template('calculate.html', msg="Оба значения должны быть числами!")

        # Преобразуем number1 и number2 в целые числа
        a = int(number1)
        b = int(number2)

        # Выполняем операцию в зависимости от оператора
        if operator == "+":
            res = a + b
        elif operator == "-":
            res = a - b
        elif operator == "*":
            res = a * b
        elif operator == "/":
            # Проверяем деление на ноль
            if b == 0:
                return render_template('calculate.html', msg="Деление на ноль невозможно!")
            res = a / b

        # Возвращаем шаблон calculate.html с результатом вычисления
        return render_template('calculate.html', res=res)

    # Если метод запроса не POST, возвращаем пустой результат
    return render_template('calculate.html')
  
# Определение маршрута для страницы с проверкой номера телефона
@app.route('/check_phone_number', methods=['GET', 'POST'])
def check_phone_number():
    if request.method == "GET":
        return render_template("check_phone_number.html", msg="0")
    else:
        phone_number = request.form["check_number1"]
        
        # Список допустимых символов, кроме цифр
        acceptable_symbols_except_digits = [" ", "(", ")", ".", "+", "-"]
        
        # Подсчёт количества цифр в номере
        counter_of_digits = sum(1 for char in phone_number if char.isdigit())
        
        # Проверка, что количество цифр соответствует стандарту
        if counter_of_digits not in [10, 11]:
            return render_template("check_phone_number.html", msg="1")
        
        # Проверка на допустимые символы
        if any(char not in acceptable_symbols_except_digits and not char.isdigit() for char in phone_number):
            return render_template("check_phone_number.html", msg="2")
        
        # Форматирование номера телефона
        formatted_phone_number = phone_number.replace('(', '').replace(')', '').replace('.', '').replace(' ', '').replace('-', '').replace('+', '')
        
        if len(formatted_phone_number) == 10 and formatted_phone_number.startswith('8'):
            formatted_phone_number = '8' + formatted_phone_number[1:]
        
        formatted_phone_number = formatted_phone_number[:1] + '-' + formatted_phone_number[1:4] + '-' + formatted_phone_number[4:7] + '-' + formatted_phone_number[7:9] + '-' + formatted_phone_number[9:]
        
        return render_template("check_phone_number.html", msg="3", phone_number=formatted_phone_number)

if __name__ == "__main__":
    app.run(debug=True)
