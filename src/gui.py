
"""
We are using PyQt5 for the GUI framework. It is a python wrapper for the Qt framework, which is widely used for developing cross-platform applications.

"""
from vault import (
    load_vault, add_file_to_vault, extract_file_from_vault, save_vault, VAULT_FILE,
    file_exists, create_vault, try_unlock_vault
)
import time
import os
from PyQt5.QtWidgets import (
    QApplication, QDialog, QLineEdit, QMainWindow, QWidget, QVBoxLayout,
    QLabel, QListWidget, QPushButton, QFileDialog, QMessageBox, QHBoxLayout
)

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
        self.accept()  # Closes the dialog

    def get_password(self):
        return self.password


# QMainWindow provides a main application window with built-in support for menus, toolbars, and status bars.
# We subclassed it with our own MainWindow class to customize it.
class MainWindow(QMainWindow):
    def __init__(self, password=None):
        super().__init__()
        self.setWindowTitle("MI 9: Black Vault")
        self.setFixedSize(600, 400)
        self.password = password
        self.vault_data = load_vault(password)
        
        # Main layout
        central = QWidget()
        vbox = QVBoxLayout()
        
        self.label = QLabel("Your Vault Files:")
        vbox.addWidget(self.label)
        
        self.file_list = QListWidget()
        vbox.addWidget(self.file_list)
        
        # Buttons for file import/export
        hbox = QHBoxLayout()
        self.import_btn = QPushButton("Import File")
        self.export_btn = QPushButton("Export Selected File")
        self.delete_btn = QPushButton("Delete Selected File")
        hbox.addWidget(self.import_btn)
        hbox.addWidget(self.export_btn)
        hbox.addWidget(self.delete_btn)
        
        self.import_btn.clicked.connect(self.import_file)
        self.export_btn.clicked.connect(self.export_file)
        self.delete_btn.clicked.connect(self.delete_file)
        
        vbox.addLayout(hbox)

        central.setLayout(vbox)
        self.setCentralWidget(central)
        
        self.refresh_file_list()
        
    def refresh_file_list(self):
        self.file_list.clear()
        for f in self.vault_data.get("files", []):
            t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(f.get("timestamp", 0)))
            self.file_list.addItem(f"{f['name']} (added {t})")
    
    def import_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select file to import")
        if fname:
            add_file_to_vault(self.password, self.vault_data, fname)
            self.vault_data = load_vault(self.password)  # reload to update
            self.refresh_file_list()
            QMessageBox.information(self, "File Imported", f"Added {os.path.basename(fname)} to your vault.")
    
    def export_file(self):
        idx = self.file_list.currentRow()
        if idx == -1:
            QMessageBox.warning(self, "No File", "Select a file to export!")
            return
        entry = self.vault_data["files"][idx]
        out_fname, _ = QFileDialog.getSaveFileName(self, "Save exported file as", entry["name"])
        if out_fname:
            extract_file_from_vault(entry, out_fname)
            QMessageBox.information(self, "Exported", f"Exported {entry['name']} to {out_fname}.")

    def delete_file(self):
        idx = self.file_list.currentRow()
        if idx == -1:
            QMessageBox.warning(self, "No File", "Select a file to delete!")
            return
        entry = self.vault_data["files"][idx]
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to permanently delete '{entry['name']}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            del self.vault_data["files"][idx]
            # Save the updated vault
            save_vault(self.password, self.vault_data)
            self.refresh_file_list()
            QMessageBox.information(self, "File Deleted", f"'{entry['name']}' was deleted from the vault.")

# Function to start the GUI application
def start_gui():
    app = QApplication([])
    
    # Detect if vault exists
    vault_on_disk = file_exists()
    login = LoginDialog(vault_exists=vault_on_disk)
    
    while True:
        if login.exec_() == QDialog.Accepted and login.success:
            password = login.get_password()
            if not vault_on_disk:
                # Create new vault!
                create_vault(password)
                vault_on_disk = True
                QMessageBox.information(None, "Success", "Vault created! Please log in again.")
                login = LoginDialog(vault_exists=True)
                continue  # Loop back to login with new vault

            # Try to unlock vault
            vault_data = try_unlock_vault(password)
            if vault_data is not None:
                # Success! Show main window
                window = MainWindow(password)
                window.show()
                app.exec_()
                break
            else:
                QMessageBox.warning(None, "Error", "Incorrect password or corrupted vault!")
                # Re-show login dialog
                login = LoginDialog(vault_exists=True)
        else:
            break  # User cancelled, exit app