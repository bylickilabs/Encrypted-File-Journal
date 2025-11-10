import os
import sys
import json
import base64
import hashlib
import sqlite3
import webbrowser
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QPushButton, QLabel, QFileDialog, QLineEdit, QTableWidget, QTableWidgetItem,
    QMessageBox, QStackedWidget, QProgressBar, QInputDialog, QHeaderView
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

APP_NAME = "Encrypted File Journal"

APP_VERSION = "1.0.0"

APP_AUTHOR = "Thorsten Bylicki — BYLICKILABS"
APP_ORG = "BYLICKILABS Secure Software Division"
GITHUB_URL = "https://github.com/bylickilabs"

CONFIG_PATH = "journal_config.json"
DB_PATH = "journal.db"

I18N = {
    "de": {
        "app_title": f"{APP_NAME} v{APP_VERSION} — {APP_AUTHOR}",
        "nav_dashboard": "Dashboard",
        "nav_crypto": "Verschlüsseln & Entschlüsseln",
        "nav_journal": "Journal",
        "nav_settings": "Einstellungen",
        "nav_github": "GitHub",
        "lang_toggle": "Deutsch / Englisch",
        "status_ready": "Bereit.",
        "status_encrypting": "Verschlüsselung läuft...",
        "status_decrypting": "Entschlüsselung läuft...",
        "label_master_setup": "Master-Passwort für verschlüsselte Datenbank setzen",
        "label_master_confirm": "Master-Passwort bestätigen",
        "label_master_enter": "Master-Passwort eingeben",
        "err_master_empty": "Master-Passwort ist erforderlich.",
        "err_master_mismatch": "Master-Passwörter stimmen nicht überein.",
        "err_master_invalid": "Ungültiges Master-Passwort.",
        "language_select_title": "Sprache / Language",
        "language_select_text": "Bitte Sprache für die Anwendung wählen / Please select application language:",
        "language_de": "Deutsch",
        "language_en": "English",
        "encrypt_title": "Datei verschlüsseln und Vorgang protokollieren",
        "select_file": "Zu verschlüsselnde Datei auswählen",
        "browse": "Durchsuchen",
        "btn_encrypt": "Verschlüsseln & eintragen",
        "no_file": "Keine Datei ausgewählt.",
        "file_not_found": "Datei nicht gefunden.",
        "progress_encrypt": "Verschlüsselung läuft...",
        "progress_done": "Verschlüsselung abgeschlossen.",
        "msg_encrypt_success": "Datei erfolgreich verschlüsselt und im Journal erfasst.",
        "msg_encrypt_error": "Fehler bei der Verschlüsselung.",
        "decrypt_title": "Verschlüsselte Datei entschlüsseln",
        "select_enc_file": "Verschlüsselte Datei (.bea) auswählen",
        "browse_enc": "Durchsuchen",
        "decrypt_output_hint": "Zieldatei (optional, sonst Originalname ohne .bea)",
        "btn_decrypt": "Entschlüsseln & eintragen",
        "no_enc_file": "Keine verschlüsselte Datei ausgewählt.",
        "file_not_bea": "Erwartet eine .bea Datei.",
        "msg_decrypt_success": "Datei erfolgreich entschlüsselt und im Journal erfasst.",
        "msg_decrypt_error": "Fehler bei der Entschlüsselung.",
        "journal_header_ts": "Zeitstempel",
        "journal_header_name": "Dateiname",
        "journal_header_hash": "SHA-512 (gekürzt)",
        "journal_header_algo": "Algorithmus",
        "journal_header_size": "Größe (Bytes)",
        "journal_header_status": "Status",
        "status_encrypted": "Verschlüsselt",
        "status_decrypted": "Entschlüsselt",
        "status_failed": "Fehlgeschlagen",
        "settings_title": "Einstellungen",
        "settings_info": "Diese Anwendung speichert alle Vorgänge lokal in einer AES-256-GCM verschlüsselten SQLite-Datenbank. Das Master-Passwort wird nur zur Schlüsselableitung verwendet.",
        "settings_algos": "Verfahren: AES-256-GCM (Dateien & Journalfelder), PBKDF2-HMAC-SHA256 (Key-Derivation), SHA-512 (Audit-Hash).",
        "footer_pulse": "Integrity Pulse aktiv — Datenbank gesichert.",
        "info_title": "Anwendungsinformation",
        "info_description": "{app} ist ein BYLICKILABS Security-Tool zur manipulationssicheren Dokumentation von Datei-Verschlüsselungen und -Entschlüsselungen.\n\nAlle Operationen erfolgen lokal.\nVersion: {ver}\nEntwickler: {auth}\nOrganisation: {org}",
        "github_open": "GitHub-Profil öffnen"
    },
    "en": {
        "app_title": f"{APP_NAME} v{APP_VERSION} — {APP_AUTHOR}",
        "nav_dashboard": "Dashboard",
        "nav_crypto": "Encrypt & Decrypt",
        "nav_journal": "Journal",
        "nav_settings": "Settings",
        "nav_github": "GitHub",
        "lang_toggle": "German / English",
        "status_ready": "Ready.",
        "status_encrypting": "Encrypting...",
        "status_decrypting": "Decrypting...",
        "label_master_setup": "Set master password for encrypted database",
        "label_master_confirm": "Confirm master password",
        "label_master_enter": "Enter master password",
        "err_master_empty": "Master password is required.",
        "err_master_mismatch": "Master passwords do not match.",
        "err_master_invalid": "Invalid master password.",
        "language_select_title": "Language / Sprache",
        "language_select_text": "Bitte Sprache für die Anwendung wählen / Please select application language:",
        "language_de": "Deutsch",
        "language_en": "English",
        "encrypt_title": "Encrypt file and record operation in journal",
        "select_file": "Select file to encrypt",
        "browse": "Browse",
        "btn_encrypt": "Encrypt & log",
        "no_file": "No file selected.",
        "file_not_found": "File not found.",
        "progress_encrypt": "Encrypting...",
        "progress_done": "Encryption completed.",
        "msg_encrypt_success": "File encrypted and logged successfully.",
        "msg_encrypt_error": "Error during encryption.",
        "decrypt_title": "Decrypt encrypted file",
        "select_enc_file": "Select encrypted file (.bea)",
        "browse_enc": "Browse",
        "decrypt_output_hint": "Output file (optional, defaults to original name without .bea)",
        "btn_decrypt": "Decrypt & log",
        "no_enc_file": "No encrypted file selected.",
        "file_not_bea": "Expected a .bea file.",
        "msg_decrypt_success": "File decrypted and logged successfully.",
        "msg_decrypt_error": "Error during decryption.",
        "journal_header_ts": "Timestamp",
        "journal_header_name": "Filename",
        "journal_header_hash": "SHA-512 (short)",
        "journal_header_algo": "Algorithm",
        "journal_header_size": "Size (bytes)",
        "journal_header_status": "Status",
        "status_encrypted": "Encrypted",
        "status_decrypted": "Decrypted",
        "status_failed": "Failed",
        "settings_title": "Settings",
        "settings_info": "This application stores all operations locally in an AES-256-GCM encrypted SQLite database. The master password is only used for key derivation.",
        "settings_algos": "Mechanisms: AES-256-GCM (files & journal fields), PBKDF2-HMAC-SHA256 (key derivation), SHA-512 (audit hash).",
        "footer_pulse": "Integrity Pulse active — database secured.",
        "info_title": "Application Information",
        "info_description": "{app} is a BYLICKILABS security tool for tamper-resistant logging of file encryption and decryption operations.\n\nAll operations run locally.\nVersion: {ver}\nDeveloper: {auth}\nOrganization: {org}",
        "github_open": "Open GitHub profile"
    }
}

def derive_key(password, salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    ).derive(password.encode("utf-8"))

def make_key_check(key):
    return hashlib.sha256(key + b"|BYLICKILABS|EncryptedFileJournal|").hexdigest()

def encrypt_value(value, key):
    if value is None:
        value = ""
    data = value.encode("utf-8")
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, data, None)
    return base64.b64encode(nonce + ct).decode("utf-8")

def decrypt_value(enc_value, key):
    if not enc_value:
        return ""
    raw = base64.b64decode(enc_value.encode("utf-8"))
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(key)
    data = aes.decrypt(nonce, ct, None)
    return data.decode("utf-8", errors="ignore")

def encrypt_file_with_key(src_path, dst_path, key):
    with open(src_path, "rb") as f:
        plaintext = f.read()
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    with open(dst_path, "wb") as f:
        f.write(nonce + ciphertext)

def decrypt_file_with_key(src_path, dst_path, key):
    with open(src_path, "rb") as f:
        raw = f.read()
    if len(raw) < 13:
        raise ValueError("invalid encrypted file")
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ct, None)
    with open(dst_path, "wb") as f:
        f.write(plaintext)

def safe_load_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict) or "salt" not in cfg or "check" not in cfg:
            raise ValueError("invalid")
        return cfg
    except Exception:
        try:
            os.replace(CONFIG_PATH, CONFIG_PATH + ".bak")
        except Exception:
            pass
        return None

class DashboardPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.title = QLabel()
        self.sub = QLabel()
        self.sub.setWordWrap(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(8)
        layout.addWidget(self.title)
        layout.addWidget(self.sub)
        layout.addStretch(1)
        self.update_texts()
    def update_texts(self):
        if self.main.lang == "de":
            self.title.setText("Übersicht")
            self.sub.setText("Verwalte Verschlüsselungs- und Entschlüsselungsvorgänge zentral. Alle Protokolle werden lokal verschlüsselt gespeichert.")
        else:
            self.title.setText("Overview")
            self.sub.setText("Manage encryption and decryption operations centrally. All logs are stored locally in encrypted form.")

class CryptoPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.enc_title = QLabel()
        self.enc_title.setObjectName("SectionTitle")
        self.enc_file_edit = QLineEdit()
        self.enc_browse_btn = QPushButton()
        self.enc_btn = QPushButton()
        self.dec_title = QLabel()
        self.dec_title.setObjectName("SectionTitle")
        self.dec_file_edit = QLineEdit()
        self.dec_browse_btn = QPushButton()
        self.dec_out_edit = QLineEdit()
        self.dec_btn = QPushButton()
        self.progress = QProgressBar()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 18)
        layout.setSpacing(14)

        layout.addWidget(self.enc_title)
        enc_row = QHBoxLayout()
        enc_row.setSpacing(8)
        self.enc_file_edit.setMinimumHeight(30)
        self.enc_browse_btn.setMinimumHeight(30)
        enc_row.addWidget(self.enc_file_edit, 1)
        enc_row.addWidget(self.enc_browse_btn)
        layout.addLayout(enc_row)
        self.enc_btn.setMinimumHeight(34)
        layout.addWidget(self.enc_btn, alignment=Qt.AlignRight)

        layout.addSpacing(20)

        layout.addWidget(self.dec_title)
        dec_row1 = QHBoxLayout()
        dec_row1.setSpacing(8)
        self.dec_file_edit.setMinimumHeight(30)
        self.dec_browse_btn.setMinimumHeight(30)
        dec_row1.addWidget(self.dec_file_edit, 1)
        dec_row1.addWidget(self.dec_browse_btn)
        layout.addLayout(dec_row1)

        self.dec_out_edit.setMinimumHeight(28)
        layout.addWidget(self.dec_out_edit)
        self.dec_btn.setMinimumHeight(34)
        layout.addWidget(self.dec_btn, alignment=Qt.AlignRight)

        self.progress.setVisible(False)
        self.progress.setMinimum(0)
        self.progress.setMaximum(0)
        layout.addWidget(self.progress)
        layout.addStretch(1)

        self.enc_browse_btn.clicked.connect(self.browse_enc_source)
        self.enc_btn.clicked.connect(self.encrypt_action)
        self.dec_browse_btn.clicked.connect(self.browse_dec_source)
        self.dec_btn.clicked.connect(self.decrypt_action)

        self.update_texts()

    def update_texts(self):
        t = self.main.tr
        self.enc_title.setText(t["encrypt_title"])
        self.enc_file_edit.setPlaceholderText(t["select_file"])
        self.enc_browse_btn.setText(t["browse"])
        self.enc_btn.setText(t["btn_encrypt"])
        self.dec_title.setText(t["decrypt_title"])
        self.dec_file_edit.setPlaceholderText(t["select_enc_file"])
        self.dec_browse_btn.setText(t["browse_enc"])
        self.dec_out_edit.setPlaceholderText(t["decrypt_output_hint"])
        self.dec_btn.setText(t["btn_decrypt"])

    def browse_enc_source(self):
        t = self.main.tr
        path, _ = QFileDialog.getOpenFileName(self, t["select_file"])
        if path:
            self.enc_file_edit.setText(path)

    def browse_dec_source(self):
        t = self.main.tr
        path, _ = QFileDialog.getOpenFileName(self, t["select_enc_file"])
        if path:
            self.dec_file_edit.setText(path)
            if path.endswith(".enc"):
                self.dec_out_edit.setText(path[:-4])

    def encrypt_action(self):
        t = self.main.tr
        path = self.enc_file_edit.text().strip()
        if not path:
            self.main.show_error(t["no_file"])
            return
        if not os.path.isfile(path):
            self.main.show_error(t["file_not_found"])
            return
        self.progress.setVisible(True)
        self.main.set_status(t["status_encrypting"])
        QApplication.processEvents()
        try:
            self.main.handle_encrypt(path)
            self.progress.setVisible(False)
            self.main.show_info(t["msg_encrypt_success"])
            self.main.set_status(t["progress_done"])
        except Exception as e:
            self.progress.setVisible(False)
            self.main.show_error(f"{t['msg_encrypt_error']}\n{e}")
            self.main.set_status(t["msg_encrypt_error"])

    def decrypt_action(self):
        t = self.main.tr
        enc_path = self.dec_file_edit.text().strip()
        if not enc_path:
            self.main.show_error(t["no_enc_file"])
            return
        if not os.path.isfile(enc_path):
            self.main.show_error(t["file_not_found"])
            return
        if not enc_path.lower().endswith(".enc"):
            self.main.show_error(t["file_not_bea"])
            return
        out_path = self.dec_out_edit.text().strip()
        if not out_path:
            out_path = enc_path[:-4] if enc_path.lower().endswith(".enc") else enc_path + ".dec"
        self.progress.setVisible(True)
        self.main.set_status(t["status_decrypting"])
        QApplication.processEvents()
        try:
            self.main.handle_decrypt(enc_path, out_path)
            self.progress.setVisible(False)
            self.main.show_info(t["msg_decrypt_success"])
            self.main.set_status(t["progress_done"])
        except Exception as e:
            self.progress.setVisible(False)
            self.main.show_error(f"{t['msg_decrypt_error']}\n{e}")
            self.main.set_status(t["msg_decrypt_error"])

class JournalPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 12)
        layout.setSpacing(8)
        self.table = QTableWidget(0, 6)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setMinimumHeight(320)
        layout.addWidget(self.table)
        layout.addStretch(1)
        self.update_headers()

    def update_headers(self):
        t = self.main.tr
        headers = [
            t["journal_header_ts"],
            t["journal_header_name"],
            t["journal_header_hash"],
            t["journal_header_algo"],
            t["journal_header_size"],
            t["journal_header_status"],
        ]
        self.table.setHorizontalHeaderLabels(headers)

    def load_entries(self, rows):
        self.table.setRowCount(0)
        for row in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            for c, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)
                self.table.setItem(r, c, item)
            self.table.setRowHeight(r, 26)

class SettingsPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.title = QLabel()
        self.title.setObjectName("SectionTitle")
        self.info = QLabel()
        self.info.setWordWrap(True)
        self.algos = QLabel()
        self.algos.setWordWrap(True)
        self.meta = QLabel()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 26, 26, 20)
        layout.setSpacing(10)
        layout.addWidget(self.title)
        layout.addWidget(self.info)
        layout.addWidget(self.algos)
        layout.addWidget(self.meta)
        layout.addStretch(1)
        self.update_texts()

    def update_texts(self):
        t = self.main.tr
        self.title.setText(t["settings_title"])
        self.info.setText(t["settings_info"])
        self.algos.setText(t["settings_algos"])
        self.meta.setText(f"{APP_NAME} | {APP_VERSION} | {APP_AUTHOR}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.lang = "de"
        self.tr = I18N[self.lang]
        self.master_key = None
        self.conn = None
        self.setMinimumSize(1150, 650)
        self.resize(1300, 740)
        self.apply_style()
        self.select_initial_language()
        self.setup_master()
        self.setup_db()
        self.build_ui()
        self.update_texts()
        self.load_journal()
        self.set_status(self.tr["status_ready"])

    def apply_style(self):
        self.setStyleSheet("""
        QMainWindow {
            background-color: #101018;
            color: #EEEEEE;
            font-family: "Segoe UI";
            font-size: 10.5pt;
        }
        #Sidebar {
            background-color: #15161E;
            border-right: 1px solid #262838;
        }
        #Logo {
            font-size: 16pt;
            font-weight: 600;
            color: #00FFFF;
            margin-bottom: 8px;
        }
        #Content {
            background-color: #101018;
        }
        #HeaderTitle {
            font-size: 14pt;
            font-weight: 600;
            color: #FF00FF;
            margin-bottom: 4px;
        }
        #SectionTitle {
            font-size: 12pt;
            font-weight: 500;
            color: #00FFFF;
        }
        #StatusBar {
            background-color: #101018;
            color: #AAAAAA;
            padding: 4px 6px;
            border-top: 1px solid #262838;
        }
        #MenuButton {
            background-color: #1E2028;
            color: #DDDDDD;
            border: 1px solid #2F3240;
            border-radius: 8px;
            padding: 8px 10px;
            text-align: left;
        }
        #MenuButton:hover {
            background-color: #262938;
            color: #00FFFF;
            border-color: #00FFFF;
        }
        #LangButton {
            background-color: #20222A;
            color: #BBBBBB;
            border-radius: 8px;
            padding: 6px 10px;
        }
        #LangButton:hover {
            background-color: #262938;
            color: #00FFFF;
        }
        QPushButton {
            font-family: "Segoe UI";
        }
        QLineEdit {
            background-color: #191B22;
            color: #EEEEEE;
            border-radius: 5px;
            border: 1px solid #303240;
            padding: 4px 6px;
        }
        QLineEdit:focus {
            border: 1px solid #00FFFF;
        }
        QTableWidget {
            background-color: #191B22;
            color: #EEEEEE;
            gridline-color: #303240;
            border-radius: 6px;
            border: 1px solid #303240;
        }
        QHeaderView::section {
            background-color: #20222A;
            color: #CCCCCC;
            padding: 4px;
            border: none;
            font-size: 9.5pt;
        }
        QTableWidget::item:selected {
            background-color: #293043;
            color: #00FFFF;
        }
        QProgressBar {
            border: 1px solid #303240;
            border-radius: 4px;
            background-color: #15161C;
            text-align: center;
            color: #CCCCCC;
        }
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                       stop:0 #00FFFF,
                                       stop:0.5 #FF00FF,
                                       stop:1 #FF66CC);
            border-radius: 3px;
        }
        """)

    def select_initial_language(self):
        msg = QMessageBox(self)
        msg.setWindowTitle(I18N["en"]["language_select_title"])
        msg.setText(I18N["en"]["language_select_text"])
        de_btn = msg.addButton(I18N["de"]["language_de"], QMessageBox.AcceptRole)
        en_btn = msg.addButton(I18N["en"]["language_en"], QMessageBox.DestructiveRole)
        msg.exec()
        if msg.clickedButton() == en_btn:
            self.lang = "en"
        else:
            self.lang = "de"
        self.tr = I18N[self.lang]
        self.setWindowTitle(self.tr["app_title"])

    def setup_master(self):
        cfg = safe_load_config()
        t = self.tr
        if cfg is None:
            while True:
                pwd1, ok1 = QInputDialog.getText(self, t["label_master_setup"], t["label_master_setup"], QLineEdit.Password)
                if not ok1 or not pwd1:
                    QMessageBox.critical(self, "Error", t["err_master_empty"])
                    continue
                pwd2, ok2 = QInputDialog.getText(self, t["label_master_confirm"], t["label_master_confirm"], QLineEdit.Password)
                if not ok2 or not pwd2:
                    QMessageBox.critical(self, "Error", t["err_master_empty"])
                    continue
                if pwd1 != pwd2:
                    QMessageBox.critical(self, "Error", t["err_master_mismatch"])
                    continue
                salt = os.urandom(16)
                key = derive_key(pwd1, salt)
                check = make_key_check(key)
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump({"salt": base64.b64encode(salt).decode("utf-8"), "check": check}, f, indent=2)
                self.master_key = key
                break
        else:
            salt = base64.b64decode(cfg["salt"].encode("utf-8"))
            check = cfg["check"]
            for _ in range(3):
                pwd, ok = QInputDialog.getText(self, t["label_master_enter"], t["label_master_enter"], QLineEdit.Password)
                if not ok or not pwd:
                    QMessageBox.critical(self, "Error", t["err_master_empty"])
                    continue
                key = derive_key(pwd, salt)
                if make_key_check(key) == check:
                    self.master_key = key
                    break
                QMessageBox.critical(self, "Error", t["err_master_invalid"])
            if self.master_key is None:
                sys.exit(1)

    def setup_db(self):
        self.conn = sqlite3.connect(DB_PATH)
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename_enc TEXT,
                filehash_enc TEXT,
                algorithm_enc TEXT,
                timestamp_enc TEXT,
                size_enc TEXT,
                status_enc TEXT
            )
            """
        )
        self.conn.commit()

    def build_ui(self):
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setMinimumWidth(260)
        sb = QVBoxLayout(self.sidebar)
        sb.setContentsMargins(18, 18, 18, 18)
        sb.setSpacing(10)

        self.logo = QLabel("🛡 BYLICKILABS")
        self.logo.setObjectName("Logo")
        sb.addWidget(self.logo)

        self.btn_dash = QPushButton()
        self.btn_dash.setObjectName("MenuButton")
        self.btn_crypto = QPushButton()
        self.btn_crypto.setObjectName("MenuButton")
        self.btn_journal = QPushButton()
        self.btn_journal.setObjectName("MenuButton")
        self.btn_settings = QPushButton()
        self.btn_settings.setObjectName("MenuButton")
        self.btn_github = QPushButton()
        self.btn_github.setObjectName("MenuButton")

        sb.addWidget(self.btn_dash)
        sb.addWidget(self.btn_crypto)
        sb.addWidget(self.btn_journal)
        sb.addWidget(self.btn_settings)
        sb.addWidget(self.btn_github)

        sb.addStretch(1)

        self.lang_btn = QPushButton()
        self.lang_btn.setObjectName("LangButton")
        self.lang_btn.clicked.connect(self.toggle_language)
        sb.addWidget(self.lang_btn)

        root.addWidget(self.sidebar)

        self.content = QFrame()
        self.content.setObjectName("Content")
        cl = QVBoxLayout(self.content)
        cl.setContentsMargins(18, 14, 18, 8)
        cl.setSpacing(6)

        self.header_label = QLabel(APP_NAME)
        self.header_label.setObjectName("HeaderTitle")
        cl.addWidget(self.header_label)

        self.stack = QStackedWidget()
        cl.addWidget(self.stack, 1)

        self.status_label = QLabel()
        self.status_label.setObjectName("StatusBar")
        cl.addWidget(self.status_label)

        root.addWidget(self.content, 1)
        self.setCentralWidget(central)

        self.page_dashboard = DashboardPage(self)
        self.page_crypto = CryptoPage(self)
        self.page_journal = JournalPage(self)
        self.page_settings = SettingsPage(self)

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_crypto)
        self.stack.addWidget(self.page_journal)
        self.stack.addWidget(self.page_settings)

        self.btn_dash.clicked.connect(lambda: self.switch_page(0))
        self.btn_crypto.clicked.connect(lambda: self.switch_page(1))
        self.btn_journal.clicked.connect(lambda: self.switch_page(2))
        self.btn_settings.clicked.connect(lambda: self.switch_page(3))
        self.btn_github.clicked.connect(self.open_github)

    def update_texts(self):
        t = self.tr
        self.setWindowTitle(t["app_title"])
        self.header_label.setText(APP_NAME)
        self.btn_dash.setText("🏠  " + t["nav_dashboard"])
        self.btn_crypto.setText("🔐  " + t["nav_crypto"])
        self.btn_journal.setText("📜  " + t["nav_journal"])
        self.btn_settings.setText("⚙️  " + t["nav_settings"])
        self.btn_github.setText("🌐  " + t["nav_github"])
        self.lang_btn.setText(t["lang_toggle"])
        self.page_dashboard.update_texts()
        self.page_crypto.update_texts()
        self.page_journal.update_headers()
        self.page_settings.update_texts()

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        self.set_status(self.tr["status_ready"])

    def toggle_language(self):
        self.lang = "en" if self.lang == "de" else "de"
        self.tr = I18N[self.lang]
        self.update_texts()
        self.load_journal()
        self.set_status(self.tr["status_ready"])

    def set_status(self, text):
        self.status_label.setText("◉ " + text)

    def show_info(self, msg):
        QMessageBox.information(self, self.tr["info_title"], msg)

    def show_error(self, msg):
        QMessageBox.critical(self, "Error", msg)

    def open_github(self):
        webbrowser.open(GITHUB_URL)

    def handle_encrypt(self, path):
        t = self.tr
        if not self.master_key:
            raise RuntimeError("missing master key")
        if not os.path.isfile(path):
            raise FileNotFoundError(t["file_not_found"])
        sha = hashlib.sha512()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                if not chunk:
                    break
                sha.update(chunk)
        file_hash = sha.hexdigest()
        dst = path + ".enc"
        encrypt_file_with_key(path, dst, self.master_key)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        algo = "AES-256-GCM (encrypt) + SHA-512 (audit)"
        size = os.path.getsize(path)
        status = t["status_encrypted"]
        self.insert_journal_entry(os.path.basename(path), file_hash, algo, ts, size, status)

    def handle_decrypt(self, enc_path, out_path):
        t = self.tr
        if not self.master_key:
            raise RuntimeError("missing master key")
        if not os.path.isfile(enc_path):
            raise FileNotFoundError(t["file_not_found"])
        decrypt_file_with_key(enc_path, out_path, self.master_key)
        sha = hashlib.sha512()
        with open(out_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                if not chunk:
                    break
                sha.update(chunk)
        file_hash = sha.hexdigest()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        algo = "AES-256-GCM (decrypt) + SHA-512 (audit)"
        size = os.path.getsize(out_path)
        status = t["status_decrypted"]
        self.insert_journal_entry(os.path.basename(out_path), file_hash, algo, ts, size, status)

    def insert_journal_entry(self, filename, filehash, algorithm, timestamp, size, status):
        k = self.master_key
        self.conn.execute(
            """
            INSERT INTO journal (
                filename_enc,filehash_enc,algorithm_enc,
                timestamp_enc,size_enc,status_enc
            ) VALUES (?,?,?,?,?,?)
            """,
            (
                encrypt_value(filename, k),
                encrypt_value(filehash, k),
                encrypt_value(algorithm, k),
                encrypt_value(timestamp, k),
                encrypt_value(str(size), k),
                encrypt_value(status, k),
            ),
        )
        self.conn.commit()
        self.load_journal()

    def load_journal(self):
        k = self.master_key
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT filename_enc,filehash_enc,algorithm_enc,
                   timestamp_enc,size_enc,status_enc
            FROM journal
            ORDER BY id DESC
            """
        )
        rows = []
        for r in cur.fetchall():
            filename = decrypt_value(r[0], k)
            filehash = decrypt_value(r[1], k)
            algorithm = decrypt_value(r[2], k)
            timestamp = decrypt_value(r[3], k)
            size = decrypt_value(r[4], k)
            status = decrypt_value(r[5], k)
            short_hash = (filehash[:40] + "...") if filehash else ""
            rows.append([
                timestamp or "",
                filename or "",
                short_hash,
                algorithm or "",
                size or "",
                status or ""
            ])
        self.page_journal.load_entries(rows)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
