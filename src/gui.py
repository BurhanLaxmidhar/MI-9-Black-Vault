from vault import (
    load_vault, add_file_to_vault, extract_file_from_vault, save_vault,
    VAULT_FILE, DECOY_FILE, file_exists, create_vault, try_unlock_vault,
    create_decoy_vault, try_unlock_decoy_vault
)
import time
import os
from PyQt5.QtWidgets import (
    QApplication, QDialog, QLineEdit, QMainWindow, QWidget, QVBoxLayout,
    QLabel, QListWidget, QPushButton, QFileDialog, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QShortcut
from PyQt5.QtGui import QKeySequence


class LoginDialog(QDialog):
    def __init__(self, vault_exists=True, parent=None):
        super().__init__(parent)
        self.setWindowTitle("MI 9: Black Vault – Login")
        self.setFixedSize(350, 160)
        self.vault_exists = vault_exists

        layout = QVBoxLayout()

        label = QLabel("Enter vault password:")
        layout.addWidget(label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.info_label = QLabel("")
        layout.addWidget(self.info_label)

        self.button = QPushButton("Unlock" if vault_exists else "Create Vault")
        layout.addWidget(self.button)

        self.button.clicked.connect(self.handle_login)

        self.setLayout(layout)
        self.password = None
        self.success = False

    def handle_login(self):
        pw = self.password_input.text()
        if not pw:
            self.info_label.setText("Password cannot be empty.")
            return

        self.password = pw
        self.success = True
        self.accept()

    def get_password(self):
        return self.password


class MainWindow(QMainWindow):
    def __init__(self, password=None, decoy_mode=False):
        super().__init__()
        self.decoy_mode = decoy_mode
        self.setWindowTitle("MI 9: Black Vault" + (" [DECOY MODE]" if decoy_mode else ""))
        self.setFixedSize(640, 480)
        self.password = password
        self.vault_data = load_vault(
            password, filename=DECOY_FILE if decoy_mode else VAULT_FILE
        )

        # Main layout
        central = QWidget()
        vbox = QVBoxLayout()

        # Spy-style mission banner
        self.banner = QLabel(
            "AGENT: Welcome to MI 9: Black Vault\n"
            "Your mission, should you choose to accept it:\n"
            "Protect, manage, and destroy sensitive files and messages."
        )
        self.banner.setAlignment(Qt.AlignCenter)
        self.banner.setStyleSheet("font-size: 18px; font-family: 'Consolas', monospace; color: #65ff7a;")
        vbox.addWidget(self.banner)

        # Vault file list
        self.label = QLabel("Your Vault Files:")
        self.label.setStyleSheet("font-size: 16px; color: #65ff7a; font-weight: bold;")
        vbox.addWidget(self.label)

        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QListWidget.ExtendedSelection)
        vbox.addWidget(self.file_list)

        self.shortcut_panic = QShortcut(QKeySequence("Ctrl+Shift+X"), self)
        self.shortcut_panic.activated.connect(self.panic_wipe)

        # Buttons for file import/export/delete
        hbox = QHBoxLayout()
        self.import_btn = QPushButton("Import File(s)")
        self.export_btn = QPushButton("Export Selected")
        self.delete_btn = QPushButton("Delete Selected")
        self.delete_btn.setStyleSheet(
            "background-color: #55ff4b; color: #111914; font-weight: bold;"
        )
        hbox.addWidget(self.import_btn)
        hbox.addWidget(self.export_btn)
        hbox.addWidget(self.delete_btn)

        self.import_btn.clicked.connect(self.import_file)
        self.export_btn.clicked.connect(self.export_file)
        self.delete_btn.clicked.connect(self.delete_file)

        vbox.addLayout(hbox)

        # Status label for decoy mode / self-destruct flavor
        self.status_label = QLabel(
            "All actions are monitored. Unauthorized access will self-destruct the vault."
        )
        self.status_label.setStyleSheet("color: #65ff7a; font-size: 13px;")
        vbox.addWidget(self.status_label)

        if self.decoy_mode:
            #self.status_label.setText("!! DECOY VAULT ACTIVE !! This is NOT your real vault.")
            self.status_label.setStyleSheet("color: #f2e849; font-size: 14px; font-weight: bold;")

        central.setLayout(vbox)
        self.setCentralWidget(central)

        self.refresh_file_list()

    def refresh_file_list(self):
        self.file_list.clear()
        for f in self.vault_data.get("files", []):
            t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(f.get("timestamp", 0)))
            self.file_list.addItem(f"{f['name']} (added {t})")

    def import_file(self):
        fnames, _ = QFileDialog.getOpenFileNames(self, "Select files to import")
        if fnames:
            for fname in fnames:
                add_file_to_vault(
                    self.password, self.vault_data, fname,
                    filename=DECOY_FILE if self.decoy_mode else VAULT_FILE
                )
            self.vault_data = load_vault(self.password, filename=DECOY_FILE if self.decoy_mode else VAULT_FILE)
            self.refresh_file_list()
            QMessageBox.information(self, "Files Imported", f"Added {len(fnames)} file(s) to your vault.")

    def export_file(self):
        selected = self.file_list.selectedIndexes()
        if not selected:
            QMessageBox.warning(self, "No File", "Select file(s) to export!")
            return
        for idx in selected:
            entry = self.vault_data["files"][idx.row()]
            out_fname, _ = QFileDialog.getSaveFileName(self, f"Save '{entry['name']}' as", entry["name"])
            if out_fname:
                extract_file_from_vault(entry, out_fname)
        QMessageBox.information(self, "Exported", f"Exported {len(selected)} file(s).")

    def delete_file(self):
        selected = self.file_list.selectedIndexes()
        if not selected:
            QMessageBox.warning(self, "No File", "Select file(s) to delete!")
            return
        names = [self.vault_data["files"][idx.row()]["name"] for idx in selected]
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to permanently delete these files?\n" +
            "\n".join(names),
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            # Delete in reverse order to avoid index shifting
            for idx in sorted([idx.row() for idx in selected], reverse=True):
                del self.vault_data["files"][idx]
            save_vault(
                self.password, self.vault_data,
                filename=DECOY_FILE if self.decoy_mode else VAULT_FILE
            )
            self.refresh_file_list()
            QMessageBox.information(self, "Files Deleted", f"Deleted {len(selected)} file(s) from the vault.")

    def panic_wipe(self):
    
        filename = DECOY_FILE if self.decoy_mode else VAULT_FILE
        try:
            os.remove(filename)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to destroy vault: {e}")
        # Force quit the app after wipe
        QApplication.quit()

def start_gui():
    app = QApplication([])

    # --------- GREEN "HACKER" THEME ----------
    app.setStyleSheet("""
        QWidget {
            background-color: #111914;
            color: #65ff7a;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 16px;
        }
        QLineEdit, QListWidget, QTextEdit {
            background-color: #18241b;
            color: #65ff7a;
            border: 1px solid #232d22;
            selection-background-color: #19532d;
        }
        QPushButton {
            background-color: #232d22;
            color: #65ff7a;
            border: 1px solid #19532d;
            border-radius: 6px;
            padding: 6px 18px;
        }
        QPushButton:hover {
            background-color: #65ff7a;
            color: #232d22;
        }
        QLabel {
            font-weight: bold;
        }
    """)
    # --------- END THEME ---------

    # Detect if vaults exist
    real_exists = file_exists(VAULT_FILE)
    decoy_exists = file_exists(DECOY_FILE)
    vault_on_disk = real_exists or decoy_exists

    login = LoginDialog(vault_exists=vault_on_disk)

    while True:
        if login.exec_() == QDialog.Accepted and login.success:
            password = login.get_password()
            # If neither vault exists, create the real vault
            if not real_exists and not decoy_exists:
                create_vault(password)
                QMessageBox.information(None, "Success", "Vault created! Please log in again.")
                real_exists = True
                login = LoginDialog(vault_exists=True)
                continue

            # Try real vault
            vault_data = try_unlock_vault(password)
            if vault_data is not None:
                window = MainWindow(password, decoy_mode=False)
                window.show()
                app.exec_()
                break

            # Try decoy vault
            decoy_data = try_unlock_decoy_vault(password)
            if decoy_data is not None:
                window = MainWindow(password, decoy_mode=True)
                window.show()
                app.exec_()
                break

            # At this point, neither unlocked—offer to create a decoy vault
            if not file_exists(DECOY_FILE):
                reply = QMessageBox.question(
                    None, "Create Decoy Vault",
                    "Password did not match any vault. Do you want to create a decoy vault with this password?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    create_decoy_vault(password)
                    QMessageBox.information(None, "Decoy Vault Created", "Decoy vault created! Please log in again with your decoy password.")
                    decoy_exists = True
                    login = LoginDialog(vault_exists=True)
                    continue  # Go back to login
            QMessageBox.warning(None, "Error", "Incorrect password or corrupted vault!")
            login = LoginDialog(vault_exists=True)
        else:
            break  # User cancelled, exit app.
 