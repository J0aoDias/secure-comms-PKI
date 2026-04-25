#!/usr/bin/env python3
"""
Assignment 2 - Communications and Cybersecurity
Secure Web Application with Flask + HTTPS + PostgreSQL TLS

Tecnologias:
- Flask (Python Web Framework)
- HTTPS com certificados TLS
- PostgreSQL com mutual TLS authentication
- psycopg2 para conexão à base de dados
"""

from flask import Flask, jsonify, request, redirect, url_for, session
import psycopg2
from psycopg2.extras import RealDictCursor
from functools import wraps
import pyotp
import qrcode
import io
import base64
import os

# =============================================================================
# CONFIGURAÇÃO DA APLICAÇÃO
# =============================================================================

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Caminhos dos certificados
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE_DIR, '..', 'database', 'client-certs')
CA_CERT_DIR = os.path.join(BASE_DIR, '..', 'ca', 'certs')
CA_KEY_DIR = os.path.join(BASE_DIR, '..', 'ca', 'private')

# Configuração PostgreSQL
DB_CONFIG = {
    'host': 'postgres.cc.local',
    'port': 5432,
    'database': 'assignment2_db',
    'sslmode': 'verify-full',
    'sslrootcert': os.path.join(CERT_DIR, 'ca.crt'),
}

# Certificados por utilizador da BD
DB_USERS = {
    'webapp': {
        'sslcert': os.path.join(CERT_DIR, 'postgres-webapp.crt'),
        'sslkey': os.path.join(CERT_DIR, 'postgres-webapp.key'),
    },
    'readonly': {
        'sslcert': os.path.join(CERT_DIR, 'postgres-readonly.crt'),
        'sslkey': os.path.join(CERT_DIR, 'postgres-readonly.key'),
    }
}

# =============================================================================
# FUNÇÕES DE BASE DE DADOS
# =============================================================================

def get_db_connection(user='webapp'):
    """Criar conexão à base de dados com TLS mutual authentication."""
    config = {**DB_CONFIG, 'user': user, **DB_USERS[user]}
    try:
        conn = psycopg2.connect(**config, cursor_factory=RealDictCursor)
        return conn
    except psycopg2.Error as e:
        print(f"[DB ERROR] Conexão falhou: {e}")
        return None


def db_execute(query, params=None, user='webapp', fetch=True):
    """Executar query na base de dados."""
    conn = get_db_connection(user)
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if fetch:
                result = cur.fetchall()
            else:
                conn.commit()
                result = cur.rowcount
        return result
    except psycopg2.Error as e:
        print(f"[DB ERROR] Query falhou: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def generate_totp_secret(username):
    totp = pyotp.TOTP(pyotp.random_base32())
    uri = totp.provisioning_uri(
        name=username,
        issuer_name="Assignment2-CC"
    )
    return totp.secret, uri

@app.route("/2fa/verify")
def verify_2fa():
    if "tmp_user" not in session:
        return redirect(url_for("login"))

    content = """
    <div class="card">
        <h2>Verificação 2FA</h2>
        <form method="POST" action="/2fa/confirm">
            <input type="text" name="code" placeholder="Código de 6 dígitos" required>
            <button type="submit">Confirmar</button>
        </form>
    </div>
    """
    return render_page("2FA", content)
@app.route("/2fa/confirm", methods=["POST"])
def confirm_2fa():
    if "tmp_user" not in session:
        return redirect(url_for("login"))

    code = request.form.get("code")
    username = session["tmp_user"]

    result = db_execute(
        "SELECT totp_secret FROM users WHERE username = %s",
        (username,),
        user='readonly'
    )

    if not result or not result[0]["totp_secret"]:
        return redirect(url_for("login"))

    totp = pyotp.TOTP(result[0]["totp_secret"])

    if totp.verify(code, valid_window=1):
        session["user"] = username
        session.pop("tmp_user", None)
        return redirect(url_for("index"))

    return render_page("2FA Error", "<p class='error'>Código inválido</p>")




@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        result = db_execute(
            "SELECT id FROM users WHERE username = %s AND password_hash = crypt(%s, password_hash)",
            (username, password),
            user='readonly'
        )

        if result:
            user = result[0]
            twofa = db_execute(
                "SELECT totp_enabled FROM users WHERE username = %s",
                (username,),
                user='readonly'
            )[0]['totp_enabled']

            session['tmp_user'] = username

            if twofa:
                return redirect(url_for("verify_2fa"))
            else:
                session['user'] = username
                session.pop('tmp_user', None)
                return redirect(url_for("index"))

        else:
            error = "Credenciais inválidas"

    content = f"""
    <div class="card">
        <h2>Login</h2>
        {f"<p class='error'>{error}</p>" if error else ""}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Entrar</button>
        </form>
    </div>
    """
    return render_page("Login", content)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

@app.before_request
def require_login():
    if request.endpoint is None:
        return

    public_endpoints = (
        "login",
        "static",
        "api_status",
        "verify_2fa",
        "confirm_2fa",
        "enable_2fa",
    )

    if request.endpoint not in public_endpoints and "user" not in session:
        return redirect(url_for("login"))

@app.route("/2fa/setup")
@login_required
def setup_2fa():
    username = session["user"]

    result = db_execute(
        "SELECT totp_enabled, totp_secret FROM users WHERE username = %s",
        (username,),
        user='readonly'
    )

    if result[0]["totp_enabled"]:
        return redirect(url_for("index"))

    if result[0]["totp_secret"]:
        secret = result[0]["totp_secret"]
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=username,
            issuer_name="Assignment2-CC"
        )
    else:
        secret, uri = generate_totp_secret(username)
        db_execute(
            "UPDATE users SET totp_secret = %s WHERE username = %s",
            (secret, username),
            user='webapp',
            fetch=False
        )

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode()

    content = f"""
    <div class="card">
        <h2>Ativar 2FA</h2>
        <p>Digitaliza este QR Code no Google Authenticator</p>
        <img src="data:image/png;base64,{img_b64}">
        <form method="POST" action="/2fa/enable">
            <input type="text" name="code" placeholder="Código de 6 dígitos" required>
            <button type="submit">Confirmar</button>
        </form>
    </div>
    """
    return render_page("2FA Setup", content)

@app.route("/2fa/enable", methods=["POST"])
@login_required
def enable_2fa():
    code = request.form.get("code")
    username = session["user"]

    result = db_execute(
        "SELECT totp_secret FROM users WHERE username = %s",
        (username,),
        user='readonly'
    )

    if not result or not result[0]["totp_secret"]:
        return redirect(url_for("index"))

    totp = pyotp.TOTP(result[0]["totp_secret"])

    if totp.verify(code, valid_window=1):
        db_execute(
            "UPDATE users SET totp_enabled = TRUE WHERE username = %s",
            (username,),
            user='webapp',
            fetch=False
        )
        return redirect(url_for("index"))

    return render_page("2FA Error", "<p class='error'>Código inválido</p>")




# =============================================================================
# PÁGINA HTML BASE
# =============================================================================

def render_page(title, content):
    """Renderizar página HTML completa."""
    return f"""
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Assignment 2 CC</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        header {{
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }}
        h1 {{ color: #4ecca3; margin-bottom: 10px; }}
        .badge {{
            display: inline-block;
            background: #4ecca3;
            color: #1a1a2e;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 5px;
        }}
        nav {{ text-align: center; margin: 20px 0; }}
        nav a {{
            color: #4ecca3;
            text-decoration: none;
            margin: 0 10px;
            padding: 10px 20px;
            border: 1px solid #4ecca3;
            border-radius: 5px;
        }}
        nav a:hover {{ background: #4ecca3; color: #1a1a2e; }}
        .card {{
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .card h2 {{ color: #4ecca3; margin-bottom: 15px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }}
        th {{ background: rgba(78,204,163,0.2); color: #4ecca3; }}
        .success {{ color: #4ecca3; }}
        .error {{ color: #ff6b6b; }}
        form {{ margin: 15px 0; }}
        input, textarea {{
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 5px;
            background: rgba(255,255,255,0.1);
            color: #eee;
        }}
        button {{
            background: #4ecca3;
            color: #1a1a2e;
            padding: 10px 25px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin: 5px;
        }}
        button:hover {{ background: #3db892; }}
        button.delete {{ background: #ff6b6b; }}
        button.delete:hover {{ background: #ff5252; }}
        .info {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }}
        .info-item {{ background: rgba(255,255,255,0.05); padding: 10px; border-radius: 5px; }}
        .info-item strong {{ color: #4ecca3; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Assignment 2 - CC</h1>
            <span class="badge">HTTPS/TLS</span>
            <span class="badge">PostgreSQL mTLS</span>

            {session.get("user") and f'<span class="badge">Utilizador: {session["user"]} | <a href="/logout" style="color: #1a1a2e; text-decoration: underline;">Logout</a></span>' or ''}
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/status">Status</a>
            <a href="/news">Noticias</a>
            <a href="/users">Utilizadores</a>
        </nav>
        {content}
    </div>
</body>
</html>
"""


# =============================================================================
# ROTAS - PÁGINAS PRINCIPAIS
# =============================================================================

@app.route("/")
@login_required
def index():
    username = session["user"]

    result = db_execute(
        "SELECT totp_enabled FROM users WHERE username = %s",
        (username,),
        user='readonly'
    )

    totp_enabled = result[0]["totp_enabled"]

    twofa_block = ""
    if not totp_enabled:
        twofa_block = """
        <div class="card">
            <h2>Segurança da Conta</h2>
            <p>Recomendamos ativar autenticação de dois fatores (2FA).</p>
            <a href="/2fa/setup">
                <button>Ativar 2FA</button>
            </a>
        </div>
        """
    else:
        twofa_block = """
        <div class="card">
            <h2>Segurança da Conta</h2>
            <p class="success">2FA ativo nesta conta</p>
        </div>
        """

    content = f"""
    <div class="card">
        <h2>Bem-vindo</h2>
        <p>Aplicacao web segura para o Assignment 2 de Comunicacoes e Ciberseguranca.</p>
        <br>
        <div class="info">
            <div class="info-item"><strong>Web Server:</strong> Flask + HTTPS</div>
            <div class="info-item"><strong>Base de Dados:</strong> PostgreSQL + TLS</div>
            <div class="info-item"><strong>Autenticacao BD:</strong> Certificados mTLS</div>
            <div class="info-item"><strong>Porta:</strong> 443 (HTTPS)</div>
        </div>
    </div>

    {twofa_block}

    <div class="card">
        <h2>Funcionalidades</h2>
        <ul style="margin-left: 20px; line-height: 2;">
            <li><a href="/status" style="color: #4ecca3;">Status</a> - Verificar conexao a BD</li>
            <li><a href="/news" style="color: #4ecca3;">Noticias</a> - CRUD de noticias</li>
            <li><a href="/users" style="color: #4ecca3;">Utilizadores</a> - Gestao de utilizadores</li>
            <li><a href="/api/news" style="color: #4ecca3;">API JSON</a> - Endpoint REST</li>
        </ul>
    </div>
    """

    return render_page("Home", content)



@app.route("/status")
@login_required
def status():
    """Verificar estado da conexão à base de dados."""
    # Testar conexão readonly
    readonly_ok = False
    readonly_info = {}
    result = db_execute(
        "SELECT current_user, current_database(), version(), pg_is_in_recovery()",
        user='readonly'
    )
    if result:
        readonly_ok = True
        readonly_info = result[0]
    
    # Testar conexão webapp
    webapp_ok = False
    result = db_execute("SELECT current_user", user='webapp')
    if result:
        webapp_ok = True
    
    # Verificar SSL
    ssl_info = db_execute("""
        SELECT ssl, version as tls_version, cipher 
        FROM pg_stat_ssl 
        JOIN pg_stat_activity ON pg_stat_ssl.pid = pg_stat_activity.pid 
        WHERE usename = current_user
    """, user='readonly')
    
    status_class = "success" if (readonly_ok and webapp_ok) else "error"
    status_text = "Todas as conexoes OK" if (readonly_ok and webapp_ok) else "Erro nas conexoes"
    
    ssl_details = ""
    if ssl_info and len(ssl_info) > 0:
        s = ssl_info[0]
        ssl_details = f"""
        <div class="info">
            <div class="info-item"><strong>SSL Ativo:</strong> {s.get('ssl', 'N/A')}</div>
            <div class="info-item"><strong>Versao TLS:</strong> {s.get('tls_version', 'N/A')}</div>
            <div class="info-item"><strong>Cipher:</strong> {s.get('cipher', 'N/A')}</div>
        </div>
        """
    
    content = f"""
    <div class="card">
        <h2>Estado do Sistema</h2>
        <p class="{status_class}" style="font-size: 1.2em; margin: 15px 0;">{status_text}</p>
        
        <h3 style="margin-top: 20px; color: #4ecca3;">Conexoes a Base de Dados</h3>
        <table>
            <tr><th>Utilizador</th><th>Estado</th></tr>
            <tr>
                <td>readonly</td>
                <td class="{'success' if readonly_ok else 'error'}">{'Conectado' if readonly_ok else 'Falhou'}</td>
            </tr>
            <tr>
                <td>webapp</td>
                <td class="{'success' if webapp_ok else 'error'}">{'Conectado' if webapp_ok else 'Falhou'}</td>
            </tr>
        </table>
        
        <h3 style="margin-top: 20px; color: #4ecca3;">Detalhes TLS</h3>
        {ssl_details}
        
        <h3 style="margin-top: 20px; color: #4ecca3;">Informacao do Servidor</h3>
        <div class="info">
            <div class="info-item"><strong>Database:</strong> {readonly_info.get('current_database', 'N/A')}</div>
            <div class="info-item"><strong>Versao:</strong> {str(readonly_info.get('version', 'N/A'))[:50]}...</div>
        </div>
    </div>
    """
    return render_page("Status", content)


# =============================================================================
# ROTAS - NOTÍCIAS (CRUD)
# =============================================================================

@app.route("/news")
@login_required
def news_list():
    """Listar todas as notícias."""
    news = db_execute("SELECT * FROM news ORDER BY created_at DESC", user='readonly')
    
    rows = ""
    if news:
        for n in news:
            rows += f"""
            <tr>
                <td>{n['id']}</td>
                <td>{n['title']}</td>
                <td>{n['author']}</td>
                <td>{n['created_at']}</td>
                <td>
                    <form method="POST" action="/news/delete/{n['id']}" style="display:inline;">
                        <button type="submit" class="delete">Eliminar</button>
                    </form>
                </td>
            </tr>
            """
    else:
        rows = '<tr><td colspan="5">Nenhuma noticia encontrada</td></tr>'
    
    content = f"""
    <div class="card">
        <h2>Noticias</h2>
        <table>
            <tr><th>ID</th><th>Titulo</th><th>Autor</th><th>Data</th><th>Acoes</th></tr>
            {rows}
        </table>
    </div>
    
    <div class="card">
        <h2>Adicionar Noticia</h2>
        <form method="POST" action="/news/add">
            <input type="text" name="title" placeholder="Titulo" required>
            <textarea name="content" placeholder="Conteudo" rows="4" required></textarea>
            <input type="text" name="author" placeholder="Autor" required>
            <button type="submit">Adicionar</button>
        </form>
    </div>
    """
    return render_page("Noticias", content)


@app.route("/news/add", methods=["POST"])
@login_required
def news_add():
    """Adicionar nova notícia."""
    title = request.form.get('title')
    content = request.form.get('content')
    author = request.form.get('author')
    
    if title and content and author:
        result = db_execute(
            "INSERT INTO news (title, content, author) VALUES (%s, %s, %s)",
            (title, content, author),
            user='webapp',
            fetch=False
        )
        if result:
            print(f"[NEWS] Noticia adicionada: {title}")
    
    return redirect(url_for('news_list'))


@app.route("/news/delete/<int:news_id>", methods=["POST"])
@login_required
def news_delete(news_id):
    """Eliminar notícia."""
    result = db_execute(
        "DELETE FROM news WHERE id = %s",
        (news_id,),
        user='webapp',
        fetch=False
    )
    if result:
        print(f"[NEWS] Noticia eliminada: ID {news_id}")
    
    return redirect(url_for('news_list'))


# =============================================================================
# ROTAS - UTILIZADORES
# =============================================================================

@app.route("/users")
@login_required
def users_list():
    """Listar utilizadores."""
    users = db_execute("SELECT id, username, created_at FROM users ORDER BY id", user='readonly')
    
    rows = ""
    if users:
        for u in users:
            rows += f"""
            <tr>
                <td>{u['id']}</td>
                <td>{u['username']}</td>
                <td>{u['created_at']}</td>
                <td>
                    <form method="POST" action="/users/delete/{u['id']}" style="display:inline;">
                        <button type="submit" class="delete">Eliminar</button>
                    </form>
                </td>
            </tr>
            """
    else:
        rows = '<tr><td colspan="4">Nenhum utilizador encontrado</td></tr>'
    
    content = f"""
    <div class="card">
        <h2>Utilizadores</h2>
        <p style="margin-bottom: 15px; opacity: 0.7;">Passwords armazenadas com bcrypt (pgcrypto)</p>
        <table>
            <tr><th>ID</th><th>Username</th><th>Criado em</th><th>Acoes</th></tr>
            {rows}
        </table>
    </div>
    
    <div class="card">
        <h2>Adicionar Utilizador</h2>
        <form method="POST" action="/users/add">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Adicionar</button>
        </form>
    </div>
    """
    return render_page("Utilizadores", content)


@app.route("/users/add", methods=["POST"])
@login_required
def users_add():
    """Adicionar novo utilizador com password encriptada."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username and password:
        # Usar bcrypt do pgcrypto para encriptar password
        result = db_execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, crypt(%s, gen_salt('bf')))",
            (username, password),
            user='webapp',
            fetch=False
        )
        if result:
            print(f"[USERS] Utilizador adicionado: {username}")
    
    return redirect(url_for('users_list'))


@app.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
def users_delete(user_id):
    """Eliminar utilizador."""
    result = db_execute(
        "DELETE FROM users WHERE id = %s",
        (user_id,),
        user='webapp',
        fetch=False
    )
    if result:
        print(f"[USERS] Utilizador eliminado: ID {user_id}")
    
    return redirect(url_for('users_list'))


# =============================================================================
# API REST (JSON)
# =============================================================================

@app.route("/api/news", methods=["GET"])
def api_news_list():
    """API: Listar notícias em JSON."""
    news = db_execute("SELECT * FROM news ORDER BY created_at DESC", user='readonly')
    if news:
        result = []
        for n in news:
            result.append({
                'id': n['id'],
                'title': n['title'],
                'content': n['content'],
                'author': n['author'],
                'created_at': str(n['created_at'])
            })
        return jsonify({'status': 'success', 'data': result})
    return jsonify({'status': 'error', 'message': 'Nao foi possivel obter noticias'})


@app.route("/api/news", methods=["POST"])
def api_news_add():
    """API: Adicionar notícia via JSON."""
    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'JSON invalido'}), 400
    
    title = data.get('title')
    content = data.get('content')
    author = data.get('author')
    
    if not all([title, content, author]):
        return jsonify({'status': 'error', 'message': 'Campos em falta'}), 400
    
    result = db_execute(
        "INSERT INTO news (title, content, author) VALUES (%s, %s, %s) RETURNING id",
        (title, content, author),
        user='webapp'
    )
    
    if result:
        return jsonify({'status': 'success', 'id': result[0]['id']}), 201
    return jsonify({'status': 'error', 'message': 'Falha ao inserir'}), 500


@app.route("/api/users", methods=["GET"])
def api_users_list():
    """API: Listar utilizadores em JSON (sem passwords)."""
    users = db_execute("SELECT id, username, created_at FROM users ORDER BY id", user='readonly')
    if users:
        result = []
        for u in users:
            result.append({
                'id': u['id'],
                'username': u['username'],
                'created_at': str(u['created_at'])
            })
        return jsonify({'status': 'success', 'data': result})
    return jsonify({'status': 'error', 'message': 'Nao foi possivel obter utilizadores'})


@app.route("/api/status", methods=["GET"])
def api_status():
    """API: Estado do sistema."""
    readonly_ok = db_execute("SELECT 1", user='readonly') is not None
    webapp_ok = db_execute("SELECT 1", user='webapp') is not None
    
    return jsonify({
        'status': 'ok' if (readonly_ok and webapp_ok) else 'error',
        'connections': {
            'readonly': readonly_ok,
            'webapp': webapp_ok
        },
        'tls': True
    })


# =============================================================================
# INICIALIZAÇÃO
# =============================================================================

if __name__ == "__main__":
    # Certificados TLS para HTTPS
    ssl_context = (
        os.path.join(CA_CERT_DIR, 'webserver.crt'),
        os.path.join(CA_KEY_DIR, 'webserver.key')
    )
    
    print("=" * 60)
    print("Assignment 2 - Secure Web Application")
    print("=" * 60)
    print(f"[*] HTTPS: Enabled")
    print(f"[*] Certificate: {ssl_context[0]}")
    print(f"[*] Key: {ssl_context[1]}")
    print(f"[*] Database: PostgreSQL with mTLS")
    print("=" * 60)
    print("[*] Starting server on https://0.0.0.0:443")
    print("=" * 60)
    
    app.run(
        host="0.0.0.0",
        port=443,
        ssl_context=ssl_context,
        debug=False
    )
