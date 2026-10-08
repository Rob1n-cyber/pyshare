import os
import json
import uuid
import secrets
import hashlib
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    request,
    session,
    jsonify,
    send_from_directory,
    render_template_string,
)
from flask_socketio import SocketIO, emit


# ============================================================
# CONFIGURATION
# ============================================================

HOST = "0.0.0.0"
PORT = 8080

DATA_FILE = "server_data.json"
FILES_DIR = "shared_files"

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB

os.makedirs(FILES_DIR, exist_ok=True)

app = Flask(__name__)

# Clé utilisée pour les sessions Flask
app.config["SECRET_KEY"] = secrets.token_hex(32)

# Taille maximale d'un fichier envoyé
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


# ============================================================
# DONNÉES
# ============================================================

def load_data():
    if not os.path.exists(DATA_FILE):
        return {
            "users": {},
            "messages": [],
            "files": []
        }

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        data.setdefault("users", {})
        data.setdefault("messages", [])
        data.setdefault("files", {} if False else [])

        return data

    except Exception:
        print("Impossible de lire server_data.json")
        return {
            "users": {},
            "messages": [],
            "files": []
        }


data = load_data()


def save_data():
    temporary = DATA_FILE + ".tmp"

    with open(temporary, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    os.replace(temporary, DATA_FILE)


# ============================================================
# MOTS DE PASSE
# ============================================================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    return (
        salt.hex(),
        password_hash.hex()
    )


def verify_password(password, salt_hex, password_hash_hex):
    try:
        salt = bytes.fromhex(salt_hex)

        _, calculated = hash_password(
            password,
            salt
        )

        return secrets.compare_digest(
            calculated,
            password_hash_hex
        )

    except Exception:
        return False


# ============================================================
# UTILITAIRES
# ============================================================

def current_user():
    username = session.get("username")

    if not username:
        return None

    if username not in data["users"]:
        return None

    return username


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user():
            return jsonify({
                "success": False,
                "error": "Vous devez être connecté."
            }), 401

        return func(*args, **kwargs)

    return wrapper


def clean_filename(filename):
    """
    Empêche les chemins du genre ../../fichier.txt
    """
    filename = os.path.basename(filename)

    forbidden = [
        "\\",
        "/",
        "\x00"
    ]

    for char in forbidden:
        filename = filename.replace(char, "")

    if not filename:
        filename = "fichier"

    return filename


def format_size(size):
    if size < 1024:
        return f"{size} B"

    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"

    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"

    return f"{size / (1024 * 1024 * 1024):.1f} GB"


# ============================================================
# PAGE PRINCIPALE
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html lang="fr">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>PyShare</title>

<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #eef2f7;
    color: #202938;
}

button,
input {
    font: inherit;
}

button {
    cursor: pointer;
}

/* =========================================================
   LOGIN
   ========================================================= */

#loginScreen {
    position: fixed;
    inset: 0;

    display: flex;
    align-items: center;
    justify-content: center;

    background:
        radial-gradient(circle at top left, #dcecff, transparent 40%),
        radial-gradient(circle at bottom right, #e5ddff, transparent 40%),
        #eef2f7;
}

.loginBox {
    width: min(420px, calc(100% - 30px));

    background: rgba(255,255,255,0.9);
    backdrop-filter: blur(15px);

    padding: 35px;

    border-radius: 22px;

    box-shadow:
        0 20px 60px rgba(0,0,0,0.12);
}

.logo {
    font-size: 32px;
    font-weight: bold;
    text-align: center;

    margin-bottom: 8px;
}

.subtitle {
    text-align: center;
    color: #687386;
    margin-bottom: 30px;
}

.loginBox input {
    width: 100%;
    padding: 13px 15px;

    border: 1px solid #d5dce7;
    border-radius: 12px;

    margin-bottom: 12px;

    outline: none;
}

.loginBox input:focus {
    border-color: #7188ff;
}

.primary {
    width: 100%;

    border: 0;
    border-radius: 12px;

    padding: 13px;

    color: white;
    background: #6275e9;

    font-weight: bold;
}

.primary:hover {
    background: #5265d9;
}

.switchAuth {
    text-align: center;
    margin-top: 18px;

    color: #6275e9;

    cursor: pointer;
}

#error {
    color: #d64d5a;
    text-align: center;

    min-height: 20px;

    margin-top: 10px;
}

/* =========================================================
   APP
   ========================================================= */

#app {
    display: none;

    height: 100vh;

    overflow: hidden;
}

.sidebar {
    width: 260px;

    background: #1e2634;
    color: white;

    display: flex;
    flex-direction: column;

    padding: 20px;
}

.sidebarLogo {
    font-size: 25px;
    font-weight: bold;

    margin-bottom: 30px;
}

.userInfo {
    background: rgba(255,255,255,0.08);

    padding: 14px;

    border-radius: 12px;

    margin-bottom: 20px;
}

.username {
    font-weight: bold;
}

.online {
    font-size: 13px;
    color: #82e0a0;
}

.navButton {
    width: 100%;

    text-align: left;

    background: transparent;
    color: #dce2ec;

    border: 0;

    padding: 13px;

    border-radius: 10px;

    margin-bottom: 5px;
}

.navButton:hover,
.navButton.active {
    background: rgba(255,255,255,0.1);
}

.logout {
    margin-top: auto;

    color: #ff9ca5;
}

/* =========================================================
   CONTENT
   ========================================================= */

.content {
    flex: 1;

    display: flex;
    flex-direction: column;

    min-width: 0;
}

.topbar {
    height: 65px;

    background: white;

    border-bottom: 1px solid #e1e6ee;

    display: flex;
    align-items: center;

    padding: 0 25px;

    font-weight: bold;
}

.page {
    flex: 1;

    display: none;

    min-height: 0;
}

.page.active {
    display: flex;
}

/* =========================================================
   CHAT
   ========================================================= */

.chatPage {
    flex-direction: column;
}

.messages {
    flex: 1;

    overflow-y: auto;

    padding: 25px;
}

.message {
    margin-bottom: 15px;

    max-width: 75%;
}

.message.mine {
    margin-left: auto;
    text-align: right;
}

.messageHeader {
    font-size: 12px;
    color: #788397;

    margin-bottom: 4px;
}

.messageBubble {
    display: inline-block;

    background: white;

    padding: 11px 15px;

    border-radius: 15px;

    box-shadow: 0 2px 8px rgba(0,0,0,0.04);

    word-break: break-word;
}

.mine .messageBubble {
    background: #6275e9;
    color: white;
}

.chatInput {
    display: flex;

    gap: 10px;

    padding: 15px;

    background: white;

    border-top: 1px solid #e1e6ee;
}

.chatInput input {
    flex: 1;

    padding: 13px 15px;

    border: 1px solid #d8dee8;

    border-radius: 12px;

    outline: none;
}

.sendButton {
    border: 0;

    background: #6275e9;

    color: white;

    padding: 0 20px;

    border-radius: 12px;
}

/* =========================================================
   FILES
   ========================================================= */

.filesPage {
    flex-direction: column;

    padding: 25px;

    overflow-y: auto;
}

.uploadBox {
    background: white;

    border-radius: 18px;

    padding: 25px;

    margin-bottom: 20px;

    border: 2px dashed #cbd3e1;

    text-align: center;
}

.uploadBox.dragover {
    border-color: #6275e9;
    background: #f2f4ff;
}

.uploadButton {
    display: inline-block;

    background: #6275e9;
    color: white;

    padding: 12px 20px;

    border-radius: 10px;

    cursor: pointer;
}

#fileInput {
    display: none;
}

.fileList {
    display: grid;

    grid-template-columns:
        repeat(auto-fill, minmax(250px, 1fr));

    gap: 15px;
}

.fileCard {
    background: white;

    border-radius: 16px;

    padding: 18px;

    box-shadow: 0 2px 8px rgba(0,0,0,0.04);
}

.fileName {
    font-weight: bold;

    word-break: break-word;

    margin-bottom: 8px;
}

.fileMeta {
    color: #7b8595;

    font-size: 13px;

    margin-bottom: 15px;
}

.fileActions {
    display: flex;
    gap: 8px;
}

.download {
    flex: 1;

    text-decoration: none;

    text-align: center;

    background: #6275e9;
    color: white;

    padding: 9px;

    border-radius: 9px;
}

.delete {
    border: 0;

    background: #ffe6e8;
    color: #c43c49;

    border-radius: 9px;

    padding: 9px 12px;
}

/* =========================================================
   RESPONSIVE
   ========================================================= */

@media(max-width: 700px) {

    #app {
        flex-direction: column;
    }

    .sidebar {
        width: 100%;
        height: auto;

        padding: 10px;

        flex-direction: row;
        align-items: center;
        gap: 8px;
    }

    .sidebarLogo,
    .userInfo {
        display: none;
    }

    .navButton {
        width: auto;
        margin: 0;
    }

    .logout {
        margin: 0 0 0 auto;
    }

}

</style>
</head>

<body>

<!-- =======================================================
     LOGIN
     ======================================================= -->

<div id="loginScreen">

    <div class="loginBox">

        <div class="logo">
            PyShare
        </div>

        <div class="subtitle">
            Chat et partage de fichiers
        </div>

        <input
            id="username"
            placeholder="Nom d'utilisateur"
            autocomplete="username"
        >

        <input
            id="password"
            type="password"
            placeholder="Mot de passe"
            autocomplete="current-password"
        >

        <button
            class="primary"
            onclick="login()"
            id="authButton"
        >
            Se connecter
        </button>

        <div
            class="switchAuth"
            onclick="toggleRegister()"
            id="switchText"
        >
            Créer un compte
        </div>

        <div id="error"></div>

    </div>

</div>


<!-- =======================================================
     APPLICATION
     ======================================================= -->

<div id="app">

    <aside class="sidebar">

        <div class="sidebarLogo">
            PyShare
        </div>

        <div class="userInfo">
            <div class="username" id="displayUsername"></div>
            <div class="online">
                ● En ligne
            </div>
        </div>

        <button
            class="navButton active"
            onclick="showPage('chat', this)"
        >
            💬 Chat
        </button>

        <button
            class="navButton"
            onclick="showPage('files', this)"
        >
            📁 Fichiers
        </button>

        <button
            class="navButton logout"
            onclick="logout()"
        >
            Déconnexion
        </button>

    </aside>


    <main class="content">

        <div class="topbar" id="pageTitle">
            💬 Chat
        </div>


        <!-- CHAT -->

        <section
            id="chatPage"
            class="page active chatPage"
        >

            <div
                id="messages"
                class="messages"
            ></div>

            <div class="chatInput">

                <input
                    id="messageInput"
                    placeholder="Écrire un message..."
                    maxlength="2000"
                    autocomplete="off"
                >

                <button
                    class="sendButton"
                    onclick="sendMessage()"
                >
                    Envoyer
                </button>

            </div>

        </section>


        <!-- FILES -->

        <section
            id="filesPage"
            class="page filesPage"
        >

            <div
                class="uploadBox"
                id="uploadBox"
            >

                <p>
                    Glisse un fichier ici
                    ou sélectionne-le.
                </p>

                <label class="uploadButton">

                    Choisir un fichier

                    <input
                        type="file"
                        id="fileInput"
                        onchange="uploadFile()"
                    >

                </label>

                <p id="uploadStatus"></p>

            </div>

            <div
                id="fileList"
                class="fileList"
            ></div>

        </section>

    </main>

</div>


<script>

let registerMode = false;
let socket = null;
let currentUsername = "";


/* =========================================================
   AUTH
   ========================================================= */

function toggleRegister() {

    registerMode = !registerMode;

    const button =
        document.getElementById("authButton");

    const switchText =
        document.getElementById("switchText");

    if (registerMode) {

        button.textContent = "Créer le compte";

        switchText.textContent =
            "J'ai déjà un compte";

    } else {

        button.textContent =
            "Se connecter";

        switchText.textContent =
            "Créer un compte";
    }
}


async function login() {

    const username =
        document.getElementById("username").value.trim();

    const password =
        document.getElementById("password").value;

    const error =
        document.getElementById("error");

    error.textContent = "";

    if (!username || !password) {

        error.textContent =
            "Remplis tous les champs.";

        return;
    }

    const endpoint =
        registerMode
            ? "/api/register"
            : "/api/login";

    try {

        const response = await fetch(
            endpoint,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    username,
                    password
                })
            }
        );

        const result =
            await response.json();

        if (!result.success) {

            error.textContent =
                result.error;

            return;
        }

        currentUsername = result.username;

        showApp();

    } catch (e) {

        error.textContent =
            "Impossible de contacter le serveur.";
    }
}


async function logout() {

    await fetch("/api/logout", {
        method: "POST"
    });

    location.reload();
}


async function checkSession() {

    try {

        const response =
            await fetch("/api/me");

        const result =
            await response.json();

        if (result.logged) {

            currentUsername =
                result.username;

            showApp();
        }

    } catch (e) {}
}


function showApp() {

    document.getElementById(
        "loginScreen"
    ).style.display = "none";

    document.getElementById(
        "app"
    ).style.display = "flex";

    document.getElementById(
        "displayUsername"
    ).textContent = currentUsername;

    connectSocket();

    loadMessages();
    loadFiles();
}


/* =========================================================
   CHAT
   ========================================================= */

function connectSocket() {

    socket = io();

    socket.on("connect", () => {

        console.log("Socket connecté");

    });


    socket.on("new_message", message => {

        addMessage(message);

    });

}


async function loadMessages() {

    const response =
        await fetch("/api/messages");

    const result =
        await response.json();

    const container =
        document.getElementById("messages");

    container.innerHTML = "";

    result.messages.forEach(
        addMessage
    );

    scrollMessages();
}


function addMessage(message) {

    const container =
        document.getElementById("messages");

    const div =
        document.createElement("div");

    const mine =
        message.username === currentUsername;

    div.className =
        "message" +
        (mine ? " mine" : "");

    const header =
        document.createElement("div");

    header.className =
        "messageHeader";

    header.textContent =
        message.username +
        " • " +
        message.time;

    const bubble =
        document.createElement("div");

    bubble.className =
        "messageBubble";

    bubble.textContent =
        message.text;

    div.appendChild(header);
    div.appendChild(bubble);

    container.appendChild(div);

    scrollMessages();
}


function scrollMessages() {

    const container =
        document.getElementById("messages");

    container.scrollTop =
        container.scrollHeight;
}


function sendMessage() {

    const input =
        document.getElementById(
            "messageInput"
        );

    const text =
        input.value.trim();

    if (!text) return;

    if (!socket) return;

    socket.emit(
        "send_message",
        {
            text: text
        }
    );

    input.value = "";

    input.focus();
}


document.getElementById(
    "messageInput"
).addEventListener(
    "keydown",
    function(event) {

        if (
            event.key === "Enter" &&
            !event.shiftKey
        ) {

            event.preventDefault();

            sendMessage();
        }
    }
);


/* =========================================================
   NAVIGATION
   ========================================================= */

function showPage(page, button) {

    document
        .querySelectorAll(".page")
        .forEach(element => {

            element.classList.remove(
                "active"
            );

        });

    document
        .querySelectorAll(".navButton")
        .forEach(element => {

            element.classList.remove(
                "active"
            );

        });

    if (page === "chat") {

        document
            .getElementById("chatPage")
            .classList.add("active");

        document
            .getElementById("pageTitle")
            .textContent = "💬 Chat";

    }

    if (page === "files") {

        document
            .getElementById("filesPage")
            .classList.add("active");

        document
            .getElementById("pageTitle")
            .textContent = "📁 Fichiers";

        loadFiles();
    }

    button.classList.add("active");
}


/* =========================================================
   FICHIERS
   ========================================================= */

async function uploadFile() {

    const input =
        document.getElementById(
            "fileInput"
        );

    if (!input.files.length)
        return;

    const file =
        input.files[0];

    const status =
        document.getElementById(
            "uploadStatus"
        );

    status.textContent =
        "Envoi de " + file.name + "...";


    const formData =
        new FormData();

    formData.append(
        "file",
        file
    );


    try {

        const response =
            await fetch(
                "/api/upload",
                {
                    method: "POST",
                    body: formData
                }
            );

        const result =
            await response.json();

        if (!result.success) {

            status.textContent =
                result.error;

            return;
        }

        status.textContent =
            "Fichier envoyé !";

        input.value = "";

        loadFiles();

    } catch (e) {

        status.textContent =
            "Erreur pendant l'envoi.";
    }
}


async function loadFiles() {

    const response =
        await fetch("/api/files");

    const result =
        await response.json();

    const container =
        document.getElementById(
            "fileList"
        );

    container.innerHTML = "";

    result.files.forEach(file => {

        const card =
            document.createElement(
                "div"
            );

        card.className =
            "fileCard";

        const name =
            document.createElement(
                "div"
            );

        name.className =
            "fileName";

        name.textContent =
            "📄 " + file.original_name;


        const meta =
            document.createElement(
                "div"
            );

        meta.className =
            "fileMeta";

        meta.textContent =
            file.size +
            " • par " +
            file.owner +
            " • " +
            file.time;


        const actions =
            document.createElement(
                "div"
            );

        actions.className =
            "fileActions";


        const download =
            document.createElement(
                "a"
            );

        download.className =
            "download";

        download.href =
            "/download/" +
            encodeURIComponent(
                file.id
            );

        download.textContent =
            "Télécharger";


        actions.appendChild(
            download
        );


        if (
            file.owner === currentUsername
        ) {

            const deleteButton =
                document.createElement(
                    "button"
                );

            deleteButton.className =
                "delete";

            deleteButton.textContent =
                "Supprimer";

            deleteButton.onclick =
                () => deleteFile(file.id);

            actions.appendChild(
                deleteButton
            );
        }


        card.appendChild(name);
        card.appendChild(meta);
        card.appendChild(actions);

        container.appendChild(card);
    });
}


async function deleteFile(id) {

    if (
        !confirm(
            "Supprimer ce fichier ?"
        )
    ) {
        return;
    }

    const response =
        await fetch(
            "/api/files/" +
            encodeURIComponent(id),
            {
                method: "DELETE"
            }
        );

    const result =
        await response.json();

    if (!result.success) {

        alert(result.error);

        return;
    }

    loadFiles();
}


/* =========================================================
   DRAG & DROP
   ========================================================= */

const uploadBox =
    document.getElementById(
        "uploadBox"
    );

uploadBox.addEventListener(
    "dragover",
    event => {

        event.preventDefault();

        uploadBox.classList.add(
            "dragover"
        );
    }
);


uploadBox.addEventListener(
    "dragleave",
    () => {

        uploadBox.classList.remove(
            "dragover"
        );
    }
);


uploadBox.addEventListener(
    "drop",
    event => {

        event.preventDefault();

        uploadBox.classList.remove(
            "dragover"
        );

        const files =
            event.dataTransfer.files;

        if (!files.length)
            return;

        const input =
            document.getElementById(
                "fileInput"
            );

        /*
         * DataTransfer permet de placer
         * le fichier dans l'input.
         */

        const dt =
            new DataTransfer();

        dt.items.add(files[0]);

        input.files =
            dt.files;

        uploadFile();
    }
);


/* =========================================================
   START
   ========================================================= */

checkSession();

</script>

</body>
</html>
"""


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template_string(HTML)


# ============================================================
# AUTHENTIFICATION
# ============================================================

@app.post("/api/register")
def register():

    body = request.get_json(silent=True) or {}

    username = str(
        body.get("username", "")
    ).strip()

    password = str(
        body.get("password", "")
    )

    if len(username) < 3:
        return jsonify({
            "success": False,
            "error": "Le pseudo doit contenir au moins 3 caractères."
        })

    if len(username) > 24:
        return jsonify({
            "success": False,
            "error": "Le pseudo est trop long."
        })

    if len(password) < 4:
        return jsonify({
            "success": False,
            "error": "Le mot de passe doit contenir au moins 4 caractères."
        })

    if username in data["users"]:
        return jsonify({
            "success": False,
            "error": "Ce pseudo existe déjà."
        })

    salt, password_hash = hash_password(password)

    data["users"][username] = {
        "salt": salt,
        "password_hash": password_hash,
        "created": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    save_data()

    session["username"] = username

    return jsonify({
        "success": True,
        "username": username
    })


@app.post("/api/login")
def login():

    body = request.get_json(silent=True) or {}

    username = str(
        body.get("username", "")
    ).strip()

    password = str(
        body.get("password", "")
    )

    user = data["users"].get(username)

    if not user:

        return jsonify({
            "success": False,
            "error": "Pseudo ou mot de passe incorrect."
        })

    if not verify_password(
        password,
        user["salt"],
        user["password_hash"]
    ):

        return jsonify({
            "success": False,
            "error": "Pseudo ou mot de passe incorrect."
        })

    session["username"] = username

    return jsonify({
        "success": True,
        "username": username
    })


@app.post("/api/logout")
def logout():

    session.clear()

    return jsonify({
        "success": True
    })


@app.get("/api/me")
def me():

    username = current_user()

    if not username:

        return jsonify({
            "logged": False
        })

    return jsonify({
        "logged": True,
        "username": username
    })


# ============================================================
# MESSAGES
# ============================================================

@app.get("/api/messages")
@login_required
def get_messages():

    return jsonify({
        "messages": data["messages"][-200:]
    })


@socketio.on("send_message")
def socket_send_message(payload):

    username = current_user()

    if not username:
        return

    if not isinstance(payload, dict):
        return

    text = str(
        payload.get("text", "")
    ).strip()

    if not text:
        return

    if len(text) > 2000:
        text = text[:2000]

    now = datetime.now()

    message = {
        "id": str(uuid.uuid4()),
        "username": username,
        "text": text,
        "time": now.strftime("%H:%M")
    }

    data["messages"].append(message)

    # Maximum 5000 messages conservés
    if len(data["messages"]) > 5000:
        data["messages"] = data["messages"][-5000:]

    save_data()

    emit(
        "new_message",
        message,
        broadcast=True
    )


# ============================================================
# UPLOAD
# ============================================================

@app.post("/api/upload")
@login_required
def upload():

    if "file" not in request.files:

        return jsonify({
            "success": False,
            "error": "Aucun fichier reçu."
        })

    file = request.files["file"]

    if not file.filename:

        return jsonify({
            "success": False,
            "error": "Nom de fichier invalide."
        })

    original_name = clean_filename(file.filename)

    file_id = str(uuid.uuid4())

    # On garde l'extension du fichier
    extension = ""

    if "." in original_name:
        extension = os.path.splitext(
            original_name
        )[1]

    stored_name = (
        file_id +
        extension
    )

    path = os.path.join(
        FILES_DIR,
        stored_name
    )

    try:

        file.save(path)

        size = os.path.getsize(path)

    except Exception as e:

        return jsonify({
            "success": False,
            "error": "Impossible de sauvegarder le fichier."
        })


    now = datetime.now()

    file_info = {
        "id": file_id,
        "stored_name": stored_name,
        "original_name": original_name,
        "owner": current_user(),
        "size_bytes": size,
        "size": format_size(size),
        "time": now.strftime(
            "%d/%m/%Y %H:%M"
        )
    }

    data["files"].append(file_info)

    save_data()

    return jsonify({
        "success": True,
        "file": file_info
    })


# ============================================================
# LISTE DES FICHIERS
# ============================================================

@app.get("/api/files")
@login_required
def get_files():

    return jsonify({
        "files": data["files"]
    })


# ============================================================
# TÉLÉCHARGEMENT
# ============================================================

@app.get("/download/<file_id>")
@login_required
def download(file_id):

    file_info = None

    for item in data["files"]:

        if item["id"] == file_id:
            file_info = item
            break

    if not file_info:
        return "Fichier introuvable", 404

    path = os.path.join(
        FILES_DIR,
        file_info["stored_name"]
    )

    if not os.path.isfile(path):
        return "Fichier introuvable", 404

    return send_from_directory(
        FILES_DIR,
        file_info["stored_name"],
        as_attachment=True,
        download_name=file_info["original_name"]
    )


# ============================================================
# SUPPRESSION
# ============================================================

@app.delete("/api/files/<file_id>")
@login_required
def delete_file(file_id):

    username = current_user()

    file_info = None

    for item in data["files"]:

        if item["id"] == file_id:
            file_info = item
            break

    if not file_info:

        return jsonify({
            "success": False,
            "error": "Fichier introuvable."
        })


    # Pour l'instant seul le propriétaire
    # peut supprimer son fichier.

    if file_info["owner"] != username:

        return jsonify({
            "success": False,
            "error": "Vous ne pouvez pas supprimer ce fichier."
        })


    path = os.path.join(
        FILES_DIR,
        file_info["stored_name"]
    )

    try:

        if os.path.isfile(path):
            os.remove(path)

    except Exception:

        return jsonify({
            "success": False,
            "error": "Impossible de supprimer le fichier."
        })


    data["files"] = [
        item
        for item in data["files"]
        if item["id"] != file_id
    ]

    save_data()

    return jsonify({
        "success": True
    })


# ============================================================
# ERREUR FICHIER TROP GROS
# ============================================================

@app.errorhandler(413)
def too_large(error):

    return jsonify({
        "success": False,
        "error": "Fichier trop volumineux. Maximum : 500 MB."
    }), 413


# ============================================================
# LANCEMENT
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 55)
    print(" PyShare - Serveur")
    print("=" * 55)
    print()
    print(f"Serveur : http://127.0.0.1:{PORT}")
    print(f"LAN     : http://IP-DU-PC:{PORT}")
    print()
    print("Ctrl+C pour arrêter le serveur.")
    print()

    socketio.run(
        app,
        host=HOST,
        port=PORT,
        allow_unsafe_werkzeug=True
    )