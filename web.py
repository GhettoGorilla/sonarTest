from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os
import requests
import pickle
import xml.etree.ElementTree as ET
from lxml import etree
import base64

app = Flask(__name__)

DATABASE = 'vuln_portal.db'
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# **Главная страница**
@app.route('/')
def home():
    return '''
    <!doctype html>
    <html lang="ru">
    <head>
      <meta charset="UTF-8">
      <title>Портал по исследованию уязвимостей</title>
      <style>
         body {
             font-family: Arial, sans-serif;
             background: linear-gradient(to right, #FFA07A, #FFA07A);
             display: flex;
             justify-content: center;
             align-items: center;
             height: 100vh;
             margin: 0;
         }
         .container {
             text-align: center;
             background-color: rgba(255, 255, 255, 0.9);
             padding: 40px;
             border-radius: 15px;
             box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.2);
             max-width: 500px;
         }
         .btn {
             background-color: #28a745;
             color: white;
             padding: 12px 24px;
             text-decoration: none;
             border-radius: 5px;
             display: inline-block;
         }
         .btn:hover {
             background-color: #218838;
         }
      </style>
    </head>
    <body>
      <div class="container">
         <h1>Добро пожаловать!</h1>
         <p>Данный портал создан исключительно в образовательных целях.</p>
         <a href="/vulnerabilities" class="btn">Войти на портал</a>
      </div>
    </body>
    </html>
    '''

# **Страница списка уязвимостей**
@app.route('/vulnerabilities')
def vulnerabilities():
    return '''
    <h1>Список уязвимостей</h1>
    <ul>
        <li><a href="/login">SQL-инъекция</a></li>
        <li><a href="/comment">XSS</a></li>
        <li><a href="/transfer">CSRF</a></li>
        <li><a href="/upload">Загрузка файлов</a></li>
        <li><a href="/profile/1">IDOR</a></li>
        <li><a href="/xxe">XXE</a></li>
        <li><a href="/deserialization">Insecure Deserialization</a></li>
        <li><a href="/redirect">Open Redirect</a></li>
        <li><a href="/readfile">Directory Traversal</a></li>
        <li><a href="/ssrf">SSRF</a></li>
    </ul>
    '''

# **Open Redirect**
@app.route('/redirect', methods=['GET', 'POST'])
def open_redirect():
    if request.method == 'POST':
        target = request.form.get('target', '/')
        if target:
            return redirect(target)
    return '''
        <h2>Open Redirect</h2>
        <p><strong>Описание:</strong> Open Redirect уязвимость позволяет злоумышленнику заставить приложение перенаправить пользователя на вредоносный сайт.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может манипулировать URL, передаваемым в запросе, и заставить приложение выполнить перенаправление на вредоносный сайт.</p>
        <p><strong>Рекомендации по устранению:</strong> Используйте белые списки разрешенных доменов для перенаправлений и всегда проверяйте URL перед его обработкой.</p>
        <form method="post">
            Введите целевой URL: <input name="target" type="text" value="http://example.com"><br>
            <input type="submit" value="Перейти">
        </form>
    '''

# **Directory Traversal**
@app.route('/readfile', methods=['GET'])
def readfile():
    # Теория об уязвимости
    vulnerability_description = '''
        <h2>Directory Traversal</h2>
        <p><strong>Описание:</strong> Directory Traversal позволяет злоумышленнику получить доступ к файлам, которые не предназначены для публичного доступа.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может манипулировать параметрами URL, чтобы получить доступ к файлам за пределами веб-каталога.</p>
        <p><strong>Рекомендации по устранению:</strong> Ограничьте доступ к важным файлам, используйте методы фильтрации путей и проверяйте входящие параметры.</p>
    '''

    # Получаем путь к файлу из параметра URL
    file_path = request.args.get('file', '')
    
    # Если путь к файлу не указан, выводим теорию
    if not file_path:
        return vulnerability_description
    
    # Делаем путь абсолютным (чтобы предотвратить вывод файлов за пределами разрешенной директории)
    abs_path = os.path.abspath(file_path)
    
    # Пытаемся открыть файл и прочитать его содержимое
    try:
        if os.path.isdir(abs_path):
            raise IsADirectoryError("Попытка открыть каталог вместо файла.")
        
        with open(abs_path, 'r') as file:
            content = file.read()
        return f"{vulnerability_description}<pre>{content}</pre>"

    except Exception as e:
        return f"{vulnerability_description}<p>Ошибка при чтении файла: {e}</p>"

# **SQL-инъекция**
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db_connection()
        cur = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cur.execute(query)
        user = cur.fetchone()
        conn.close()
        return f"Добро пожаловать, {user['username']}!" if user else "Неверные данные!"
    return '''
        <h2>SQL-инъекция</h2>
        <p><strong>Описание:</strong> SQL-инъекция — это атака, при которой злоумышленник вставляет или "внедряет" вредоносные SQL-запросы в приложение с целью получения несанкционированного доступа к базе данных.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может использовать недооцененные поля ввода, такие как форма логина, чтобы вставить SQL-запросы и манипулировать базой данных.</p>
        <p><strong>Рекомендации по устранению:</strong> Используйте подготовленные выражения (prepared statements) или ORM для работы с базой данных, чтобы избежать внедрения SQL-кода через пользовательский ввод.</p>
        <form method="post">
            Логин: <input name="username"><br>
            Пароль: <input name="password" type="password"><br>
            <input type="submit" value="Войти">
        </form>
    '''

# **XSS**
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        user_comment = request.form.get('comment', '')
        return render_template_string(f"<h2>Ваш комментарий:</h2><p>{user_comment}</p>")
    return '''
        <h2>Cross-Site Scripting (XSS)</h2>
        <p><strong>Описание:</strong> XSS — это атака, при которой злоумышленник вставляет вредоносный скрипт в веб-страницу, который затем выполняется в браузере жертвы.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может вставить JavaScript-код в поля ввода, такие как комментарии или формы, чтобы выполнить код в браузере других пользователей.</p>
        <p><strong>Рекомендации по устранению:</strong> Очищайте все пользовательские данные, экранируя специальные символы HTML, чтобы предотвратить выполнение вредоносных скриптов.</p>
        <form method="post">
            Введите комментарий: <textarea name="comment"></textarea><br>
            <input type="submit" value="Отправить">
        </form>
    '''

# **CSRF**
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if request.method == 'POST':
        account = request.form.get('account', '')
        amount = request.form.get('amount', '0')
        return f"Переведено {amount} на счёт {account}!"
    return '''
        <h2>CSRF-атака</h2>
        <p><strong>Описание:</strong> CSRF-атака заставляет пользователя выполнить нежелательные действия на сайте, на котором он авторизован, без его ведома.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может создать вредоносную ссылку или форму, которая отправит запросы от имени жертвы, если она уже вошла в систему.</p>
        <p><strong>Рекомендации по устранению:</strong> Используйте уникальные токены для каждого запроса, такие как токены CSRF, чтобы убедиться, что запрос был отправлен с настоящего сайта.</p>
        <form method="post">
            Номер счёта: <input name="account"><br>
            Сумма: <input name="amount"><br>
            <input type="submit" value="Перевести">
        </form>
    '''

# **Загрузка файлов**
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "Файл не найден!"
        file = request.files['file']
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        return f"Файл {file.filename} загружен!"
    return '''
        <h2>Загрузка файлов</h2>
        <p><strong>Описание:</strong> Загрузка файлов может быть использована злоумышленниками для загрузки вредоносных файлов, таких как скрипты или исполнимые файлы.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может загрузить файл с расширением, которое сервер не проверяет, и выполнить его на сервере.</p>
        <p><strong>Рекомендации по устранению:</strong> Проверяйте тип файлов по MIME-типа, ограничьте типы файлов, которые могут быть загружены, и используйте безопасные методы для работы с файлами.</p>
        <form method="post" enctype="multipart/form-data">
            Выберите файл: <input type="file" name="file"><br>
            <input type="submit" value="Загрузить">
        </form>
    '''

# **IDOR**
@app.route('/profile/<int:user_id>')
def profile(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    return f'''
        <h2>IDOR (Insecure Direct Object Reference)</h2>
        <p><strong>Описание:</strong> IDOR уязвимость возникает, когда приложение позволяет пользователям получать доступ к объектам, не проверяя их право на это. Это может привести к несанкционированному доступу к данным других пользователей.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может изменить параметры URL или другие данные, чтобы получить доступ к объектам или данным, к которым он не должен иметь доступ.</p>
        <p><strong>Рекомендации по устранению:</strong> Проверяйте права доступа каждого пользователя перед предоставлением доступа к объектам.</p>
        <p>Профиль: {user['username']} (Роль: {user['role']})</p>
    ''' if user else "Пользователь не найден!"

# **XXE**
@app.route('/xxe', methods=['GET', 'POST'])
def xxe():
    if request.method == 'POST':
        xml_data = request.form.get('xml_data', None)

        if xml_data:
            try:
                # Настройка парсера с разрешением на использование внешних сущностей
                parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
                
                # Обрабатываем XML
                tree = etree.fromstring(xml_data, parser=parser)
                
                # Выводим разобранный XML, чтобы отследить, что произошло
                return f"XML успешно обработан. Содержимое: {etree.tostring(tree)}"
            except Exception as e:
                return f"Ошибка при обработке XML: {str(e)}"
        else:
            return "Ошибка: данные не были предоставлены."

    return '''
        <h2>XXE (XML External Entity)</h2>
        <p><strong>Описание:</strong> XXE уязвимость позволяет злоумышленникам использовать внешние сущности XML для выполнения атак, таких как чтение конфиденциальных файлов.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может отправить XML с внешней сущностью, которая будет использовать уязвимость для выполнения атаки.</p>
        <p><strong>Рекомендации по устранению:</strong> Отключите внешние сущности в обработчике XML и всегда проверяйте XML на наличие вредоносных элементов.</p>
        <form method="post">
            Введите XML данные: <textarea name="xml_data"></textarea><br>
            <input type="submit" value="Отправить">
        </form>
    '''

# **Insecure Deserialization**
@app.route('/deserialization', methods=['GET', 'POST'])
def deserialize():
    if request.method == 'POST':
        base64_data = request.form.get('serialized_data', None)
        
        if base64_data:
            try:
                # Добавляем паддинг вручную для base64
                padding = '=' * (4 - len(base64_data) % 4)  # Для корректного завершения
                base64_data += padding

                # Декодируем данные
                serialized_data = base64.b64decode(base64_data)

                # Десериализуем данные
                deserialized_object = pickle.loads(serialized_data)

                # Выполним команду (если это команда)
                if isinstance(deserialized_object, str):
                    result = os.popen(deserialized_object).read()
                    return f"Результат выполнения команды: {result}"

                return f"Десериализованный объект: {deserialized_object}"

            except Exception as e:
                return f"Ошибка при десериализации: {str(e)}"
        else:
            return "Ошибка: данные не были предоставлены."
            
    return '''
        <h2>Insecure Deserialization</h2>
        <p><strong>Описание:</strong> Insecure Deserialization позволяет злоумышленникам выполнить произвольный код или манипулировать данными при десериализации объектов.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может отправить сериализованный объект, который будет обработан сервером и выполнит вредоносный код при десериализации.</p>
        <p><strong>Рекомендации по устранению:</strong> Используйте безопасные форматы сериализации, такие как JSON, и проверяйте данные перед их десериализацией.</p>
        <form method="post">
            Введите сериализованные данные: 
            <textarea name="serialized_data" rows="10" cols="50"></textarea><br>
            <input type="submit" value="Отправить">
        </form>
    '''

# **SSRF**
@app.route('/ssrf', methods=['GET', 'POST'])
def ssrf():
    if request.method == 'POST':
        target_url = request.form.get('target_url', '')
        
        if target_url:
            try:
                # Попытка сделать HTTP-запрос к целевому URL
                response = requests.get(target_url)
                return f"Ответ от сервера: {response.text}"
            except requests.exceptions.RequestException as e:
                return f"Ошибка при подключении к URL: {e}"
    
    return '''
        <h2>SSRF (Server-Side Request Forgery)</h2>
        <p><strong>Описание:</strong> SSRF уязвимость позволяет злоумышленнику заставить сервер отправлять запросы к произвольным целям, включая внутренние сервисы.</p>
        <p><strong>Способы эксплуатации:</strong> Атакующий может манипулировать URL, который сервер использует для отправки запросов, чтобы заставить его подключиться к внутренним или внешним системам.</p>
        <p><strong>Рекомендации по устранению:</strong> Ограничьте доступ для серверов, которые делают запросы, и фильтруйте URL перед их использованием.</p>
        <form method="post">
            Введите целевой URL: <input name="target_url" type="text"><br>
            <input type="submit" value="Отправить запрос">
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)
