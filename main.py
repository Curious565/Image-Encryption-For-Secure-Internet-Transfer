from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QFileDialog, QMessageBox, QLineEdit, QTabWidget, QHBoxLayout
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtCore import QBuffer, QByteArray, QIODevice
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import numpy as np
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

class Application(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Image Encryption")
        self.setLayout(QVBoxLayout())

        self.tab_widget = QTabWidget(self)
        self.layout().addWidget(self.tab_widget)

        # Encrypt Tab
        self.encrypt_widget = QWidget(self)
        self.encrypt_widget.setLayout(QVBoxLayout())
        self.tab_widget.addTab(self.encrypt_widget, "Encrypt")

        self.encrypt_image_panel = QLabel(self.encrypt_widget)
        self.encrypt_image_panel.setFixedSize(500, 350)
        self.encrypt_image_panel.setStyleSheet("background-color: grey;")
        self.encrypt_image_panel.mousePressEvent = self.load_image
        
        
        h_box_layout_enc = QHBoxLayout()
        h_box_layout_enc.addStretch(1)
        h_box_layout_enc.addWidget(self.encrypt_image_panel)
        h_box_layout_enc.addStretch(1)

        
        self.encrypt_widget.layout().addLayout(h_box_layout_enc)

        self.key_input = QLineEdit(self.encrypt_widget)
        self.key_input.setReadOnly(True)

        self.rsa_public_key_input = QLineEdit(self.encrypt_widget)
        self.rsa_public_key_input.setReadOnly(True)

        self.key_generate_button = QPushButton("Key Generate", self.encrypt_widget)
        self.key_generate_button.clicked.connect(self.generate_key)
        
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("AES Key:"))
        key_layout.addWidget(self.key_input)
        key_layout.addWidget(QLabel("RSA Public Key:"))
        key_layout.addWidget(self.rsa_public_key_input)
        key_layout.addWidget(self.key_generate_button)
        self.encrypt_widget.layout().addLayout(key_layout)

        self.encrypt_button = QPushButton("Encrypt", self.encrypt_widget)
        self.encrypt_button.clicked.connect(self.encrypt_image)
        self.encrypt_widget.layout().addWidget(self.encrypt_button)

        # Decrypt Tab
        self.decrypt_widget = QWidget(self)
        self.decrypt_widget.setLayout(QVBoxLayout())
        self.tab_widget.addTab(self.decrypt_widget, "Decrypt")

        self.decrypt_image_panel = QLabel(self.decrypt_widget)
        self.decrypt_image_panel.setFixedSize(500, 350)
        self.decrypt_image_panel.setStyleSheet("background-color: grey")
        
        h_box_layout_dec = QHBoxLayout()
        h_box_layout_dec.addStretch(1)
        h_box_layout_dec.addWidget(self.decrypt_image_panel)
        h_box_layout_dec.addStretch(1)

        
        self.decrypt_widget.layout().addLayout(h_box_layout_dec)

        self.rsa_password_input = QLineEdit(self.decrypt_widget)
        
        self.select_button = QPushButton("Select Cipher File", self.decrypt_widget)
        self.select_button.clicked.connect(self.select_cipher_file)

        self.select_aes_button = QPushButton("Select AES Key File", self.decrypt_widget)
        self.select_aes_button.clicked.connect(self.select_aes_file)

        self.decrypt_button = QPushButton("Decrypt", self.decrypt_widget)
        self.decrypt_button.clicked.connect(self.decrypt_image)

        decrypt_layout = QHBoxLayout()
        decrypt_layout.addWidget(QLabel("RSA Private Key:"))
        decrypt_layout.addWidget(self.rsa_password_input)
        decrypt_layout.addWidget(self.select_button)
        decrypt_layout.addWidget(self.select_aes_button)
        self.decrypt_widget.layout().addLayout(decrypt_layout)

        self.decrypt_widget.layout().addWidget(self.decrypt_button)

     
    



    def load_image(self, event):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Image", "", "Images (*.png *.xpm *.jpg)")
        if file_name:
            pixmap = QPixmap(file_name)
            self.encrypt_image_panel.setPixmap(pixmap.scaled(500, 350))

    def generate_key(self):
        key = get_random_bytes(16)
        self.key_input.setText(b64encode(key).decode())  # Converts the key into base64 for easier handling

        # Generates RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode().replace('\n', '').replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '')
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode().replace('\n', '').replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '')

        self.rsa_public_key_input.setText(public_pem)
        self.rsa_password_input.setText(private_pem)

   
    def encrypt_image(self):
        if self.key_input.text() == "" or not self.encrypt_image_panel.pixmap():
            QMessageBox.critical(self, "Error", "You must select an image and generate a key before encryption.")
            return

        # Encrypt the AES key with RSA public key
        public_key_pem = '-----BEGIN PUBLIC KEY-----\n' + self.rsa_public_key_input.text() + '\n-----END PUBLIC KEY-----'
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        encrypted_key = public_key.encrypt(
            b64decode(self.key_input.text().encode()),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open('encrypted_aes_key.txt', 'w') as file:
            file.write(b64encode(encrypted_key).decode())

        # Encrypt the image with the AES key
        key = b64decode(self.key_input.text().encode())
        image = self.encrypt_image_panel.pixmap().toImage()

        byte_array = QByteArray()
        buffer = QBuffer(byte_array)
        buffer.open(QIODevice.WriteOnly)
        image.save(buffer, "PNG")

        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(byte_array.data())

        with open('cipher.txt', 'w') as file:
            file.write(b64encode(cipher.nonce + ciphertext).decode())

        np_array = np.random.rand(500, 350, 3) * 255
        noise_image = QImage(np_array.astype(np.uint8), 500, 350, QImage.Format_RGB888)
        noise_pixmap = QPixmap.fromImage(noise_image)
        self.encrypt_image_panel.setPixmap(noise_pixmap)

        noise_pixmap.save('noise_image.png')

    def select_cipher_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Cipher File", "", "Cipher (*.txt)")
        if file_name:
            with open(file_name, 'r') as file:
                ciphertext = b64decode(file.read().encode())
            noise_image = QPixmap('noise_image.png')
            self.decrypt_image_panel.setPixmap(noise_image.scaled(500, 350))

    def select_aes_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Encrypted AES Key File", "", "AES Key (*.txt)")
        if file_name:
            with open(file_name, 'r') as file:
                self.aes_key = b64decode(file.read().encode())

    def decrypt_image(self):
        if self.rsa_password_input.text() == "":
            QMessageBox.critical(self, "Error", "You must provide a RSA private key before decryption.")
            return

        try:
            # decryption aes key with rsa private key
            private_key_pem = '-----BEGIN PRIVATE KEY-----\n' + self.rsa_password_input.text() + '\n-----END PRIVATE KEY-----'
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
            key = private_key.decrypt(
                self.aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # decryptipn the image with aes key
            with open('cipher.txt', 'r') as file:
                ciphertext = b64decode(file.read().encode())
            nonce = ciphertext[:16]
            ciphertext = ciphertext[16:]

            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            byte_array = QByteArray(plaintext)

            image = QImage()
            image.loadFromData(byte_array, "PNG")

            pixmap = QPixmap.fromImage(image)
            self.decrypt_image_panel.setPixmap(pixmap)
            pixmap.save("decrypt_image_panel.png","PNG")
        except:
            QMessageBox.critical(self, "Error", "Failed to decrypt the image. The key may be incorrect or the cipher file may be corrupted.")
            noise_image = QPixmap('noise_image.png')
            self.decrypt_image_panel.setPixmap(noise_image.scaled(500, 350))


app = QApplication([])
window = Application()
window.setFixedSize(600, 600)

window.show()
app.exec()
