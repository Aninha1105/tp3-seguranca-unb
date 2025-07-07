# main.py
import os
import sys
import hashlib # Para HASH_ALGO
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QTextEdit, QFileDialog, QMessageBox, QTabWidget
)
from PyQt6.QtCore import Qt

# Ajuste do PATH para importar módulos irmãos
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Importar seus módulos
import number_theory
import rsa_core
import hasher
import rsa_pss
import utils 

# --- Constantes e Configurações ---
KEY_SIZE_BITS = 2048
DEFAULT_SALT_LEN = hashlib.sha3_256().digest_size
HASH_ALGO = hashlib.sha3_256
HASH_ALGO_NAME = "sha3_256"

PUBLIC_KEY_FILE = "public_key.pem"
PRIVATE_KEY_FILE = "private_key.pem"

# --- Variáveis Globais para Chaves Carregadas ---
current_public_key = None
current_private_key = None

# --- Classe Principal da Aplicação PyQt ---
class RSAPSSApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sistema de Assinatura e Verificação RSA-PSS")
        self.setGeometry(100, 100, 800, 600) # x, y, width, height

        self.init_ui()
        self.load_keys_on_startup() # Tenta carregar chaves ao iniciar

    def init_ui(self):
        main_layout = QVBoxLayout()
        self.tabs = QTabWidget()
        
        # Guia de Geração de Chaves
        self.key_gen_tab = QWidget()
        self.setup_key_gen_tab()
        self.tabs.addTab(self.key_gen_tab, "Gerar Chaves")

        # Guia de Assinatura
        self.sign_tab = QWidget()
        self.setup_sign_tab()
        self.tabs.addTab(self.sign_tab, "Assinar")

        # Guia de Verificação
        self.verify_tab = QWidget()
        self.setup_verify_tab()
        self.tabs.addTab(self.verify_tab, "Verificar")

        main_layout.addWidget(self.tabs)

        # Área de Log
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFixedHeight(150)
        main_layout.addWidget(QLabel("Log de Operações:"))
        main_layout.addWidget(self.log_output)

        self.setLayout(main_layout)

    def log(self, message):
        self.log_output.append(message)

    def setup_key_gen_tab(self):
        layout = QVBoxLayout()

        # Nomes dos arquivos de chave
        key_file_layout = QHBoxLayout()
        key_file_layout.addWidget(QLabel("Chave Pública:"))
        self.pub_key_path_label = QLineEdit(PUBLIC_KEY_FILE)
        self.pub_key_path_label.setReadOnly(True)
        key_file_layout.addWidget(self.pub_key_path_label)

        key_file_layout.addWidget(QLabel("Chave Privada:"))
        self.priv_key_path_label = QLineEdit(PRIVATE_KEY_FILE)
        self.priv_key_path_label.setReadOnly(True)
        key_file_layout.addWidget(self.priv_key_path_label)
        layout.addLayout(key_file_layout)

        # Botão Gerar Chaves
        generate_button = QPushButton("Gerar Novo Par de Chaves RSA")
        generate_button.clicked.connect(self.generate_keys)
        layout.addWidget(generate_button)
        
        layout.addStretch(1) # Para que o conteúdo não se espalhe
        self.key_gen_tab.setLayout(layout)

    def setup_sign_tab(self):
        layout = QVBoxLayout()

        # Tipo de conteúdo a assinar
        content_type_layout = QHBoxLayout()
        self.sign_message_radio = QPushButton("Mensagem de Texto")
        self.sign_message_radio.setCheckable(True)
        self.sign_message_radio.setChecked(True)
        self.sign_file_radio = QPushButton("Arquivo")
        self.sign_file_radio.setCheckable(True)
        
        self.sign_message_radio.clicked.connect(lambda: self.toggle_sign_input_type(True))
        self.sign_file_radio.clicked.connect(lambda: self.toggle_sign_input_type(False))

        content_type_layout.addWidget(self.sign_message_radio)
        content_type_layout.addWidget(self.sign_file_radio)
        layout.addLayout(content_type_layout)

        # Entrada de Mensagem (visível por padrão)
        self.message_input_label = QLabel("Mensagem a ser assinada:")
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Digite sua mensagem aqui...")
        self.message_input.setFixedHeight(100)
        layout.addWidget(self.message_input_label)
        layout.addWidget(self.message_input)

        # Entrada de Arquivo (inicialmente oculto)
        self.file_path_sign_layout = QHBoxLayout()
        self.file_path_sign_label = QLabel("Caminho do Arquivo:")
        self.file_path_sign_edit = QLineEdit()
        self.file_path_sign_browse_button = QPushButton("Procurar...")
        self.file_path_sign_browse_button.clicked.connect(self.browse_file_to_sign)
        self.file_path_sign_layout.addWidget(self.file_path_sign_label)
        self.file_path_sign_layout.addWidget(self.file_path_sign_edit)
        self.file_path_sign_layout.addWidget(self.file_path_sign_browse_button)
        
        layout.addLayout(self.file_path_sign_layout)
        # Oculta inicialmente o layout do arquivo
        self.set_layout_visibility(self.file_path_sign_layout, False)


        # Botão Assinar
        sign_button = QPushButton("Assinar Conteúdo")
        sign_button.clicked.connect(self.sign_content)
        layout.addWidget(sign_button)

        layout.addStretch(1)
        self.sign_tab.setLayout(layout)
    
    def toggle_sign_input_type(self, is_message):
        self.message_input.setVisible(is_message)
        self.message_input_label.setVisible(is_message)
        self.set_layout_visibility(self.file_path_sign_layout, not is_message)
        
        self.sign_message_radio.setChecked(is_message)
        self.sign_file_radio.setChecked(not is_message)


    def setup_verify_tab(self):
        layout = QVBoxLayout()

        # Tipo de conteúdo a verificar
        content_type_layout = QHBoxLayout()
        self.verify_message_radio = QPushButton("Mensagem de Texto")
        self.verify_message_radio.setCheckable(True)
        self.verify_message_radio.setChecked(True)
        self.verify_file_radio = QPushButton("Arquivo")
        self.verify_file_radio.setCheckable(True)
        
        self.verify_message_radio.clicked.connect(lambda: self.toggle_verify_input_type(True))
        self.verify_file_radio.clicked.connect(lambda: self.toggle_verify_input_type(False))

        content_type_layout.addWidget(self.verify_message_radio)
        content_type_layout.addWidget(self.verify_file_radio)
        layout.addLayout(content_type_layout)

        # Entrada de Mensagem Original para Verificação (visível por padrão)
        self.original_message_verify_label = QLabel("Mensagem Original:")
        self.original_message_verify_input = QTextEdit()
        self.original_message_verify_input.setPlaceholderText("Digite a mensagem original aqui...")
        self.original_message_verify_input.setFixedHeight(100)
        layout.addWidget(self.original_message_verify_label)
        layout.addWidget(self.original_message_verify_input)

        # Entrada de Arquivo Original para Verificação (inicialmente oculto)
        self.file_path_verify_layout = QHBoxLayout()
        self.file_path_verify_label = QLabel("Caminho do Arquivo Original:")
        self.file_path_verify_edit = QLineEdit()
        self.file_path_verify_browse_button = QPushButton("Procurar...")
        self.file_path_verify_browse_button.clicked.connect(self.browse_file_to_verify)
        self.file_path_verify_layout.addWidget(self.file_path_verify_label)
        self.file_path_verify_layout.addWidget(self.file_path_verify_edit)
        self.file_path_verify_layout.addWidget(self.file_path_verify_browse_button)
        
        layout.addLayout(self.file_path_verify_layout)
        # Oculta inicialmente o layout do arquivo
        self.set_layout_visibility(self.file_path_verify_layout, False)

        # Caminho do Arquivo de Assinatura
        signature_file_layout = QHBoxLayout()
        signature_file_layout.addWidget(QLabel("Arquivo de Assinatura:"))
        self.signature_file_edit = QLineEdit()
        self.signature_file_browse_button = QPushButton("Procurar...")
        self.signature_file_browse_button.clicked.connect(self.browse_signature_file)
        signature_file_layout.addWidget(self.signature_file_edit)
        signature_file_layout.addWidget(self.signature_file_browse_button)
        layout.addLayout(signature_file_layout)

        # Botão Verificar
        verify_button = QPushButton("Verificar Assinatura")
        verify_button.clicked.connect(self.verify_content)
        layout.addWidget(verify_button)

        layout.addStretch(1)
        self.verify_tab.setLayout(layout)

    def toggle_verify_input_type(self, is_message):
        self.original_message_verify_input.setVisible(is_message)
        self.original_message_verify_label.setVisible(is_message)
        self.set_layout_visibility(self.file_path_verify_layout, not is_message)
        
        self.verify_message_radio.setChecked(is_message)
        self.verify_file_radio.setChecked(not is_message)

    def set_layout_visibility(self, layout, visible):
        for i in range(layout.count()):
            widget = layout.itemAt(i).widget()
            if widget:
                widget.setVisible(visible)

    # --- Funções de Navegação de Arquivos ---
    def browse_file_to_sign(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Selecionar Arquivo para Assinar")
        if file_name:
            self.file_path_sign_edit.setText(file_name)

    def browse_file_to_verify(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Selecionar Arquivo Original")
        if file_name:
            self.file_path_verify_edit.setText(file_name)
    
    def browse_signature_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Selecionar Arquivo de Assinatura", filter="Assinatura Files (*.sig);;All Files (*)")
        if file_name:
            self.signature_file_edit.setText(file_name)

    # --- Lógica de Geração/Assinatura/Verificação ---
    def load_keys_on_startup(self):
        """Tenta carregar chaves existentes ao iniciar a aplicação."""
        global current_public_key, current_private_key
        public_key_data = utils.load_public_key(PUBLIC_KEY_FILE)
        private_key_data = utils.load_private_key(PRIVATE_KEY_FILE)

        if public_key_data and private_key_data:
            current_public_key = public_key_data
            current_private_key = private_key_data
            self.log(f"Chaves carregadas com sucesso de {PUBLIC_KEY_FILE} e {PRIVATE_KEY_FILE}.")
        else:
            self.log("Nenhuma chave existente encontrada. Por favor, gere novas chaves.")

    def generate_keys(self):
        global current_public_key, current_private_key
        self.log(f"Gerando um novo par de chaves RSA de {KEY_SIZE_BITS} bits...")
        try:
            P = number_theory.gen_prime(KEY_SIZE_BITS // 2)
            Q = number_theory.gen_prime(KEY_SIZE_BITS // 2)
            N = P * Q
            phi = (P - 1) * (Q - 1)
            e = 65537
            _, D_raw, _ = number_theory.gcd(e, phi)
            D = D_raw % phi
            if D < 0: D += phi

            current_public_key = {"n": N, "e": e}
            current_private_key = {"n": N, "d": D}
            utils.save_public_key(PUBLIC_KEY_FILE, N, e)
            utils.save_private_key(PRIVATE_KEY_FILE, N, D)
            self.log("Chaves geradas e salvas com sucesso.")
        except Exception as e:
            self.log(f"Erro ao gerar chaves: {e}")
            QMessageBox.critical(self, "Erro", f"Falha na geração de chaves: {e}")
            current_public_key = None
            current_private_key = None

    def sign_content(self):
        if not current_private_key:
            self.log("Erro: Nenhuma chave privada carregada. Por favor, gere ou carregue chaves primeiro.")
            QMessageBox.warning(self, "Erro", "Nenhuma chave privada carregada.")
            return

        message_bytes_to_sign = None
        output_filename = None

        if self.sign_message_radio.isChecked():
            message = self.message_input.toPlainText().strip()
            if not message:
                self.log("Erro: Mensagem vazia.")
                QMessageBox.warning(self, "Erro", "Por favor, digite a mensagem a ser assinada.")
                return
            message_bytes_to_sign = message.encode('utf-8')
            output_filename = "assinatura_mensagem.sig"
        else: # Assinando arquivo
            file_path = self.file_path_sign_edit.text().strip()
            if not file_path:
                self.log("Erro: Caminho do arquivo vazio.")
                QMessageBox.warning(self, "Erro", "Por favor, selecione um arquivo para assinar.")
                return
            if not os.path.exists(file_path):
                self.log(f"Erro: Arquivo '{file_path}' não encontrado.")
                QMessageBox.critical(self, "Erro", f"Arquivo '{file_path}' não encontrado.")
                return
            try:
                with open(file_path, 'rb') as f:
                    message_bytes_to_sign = f.read()
                output_filename = os.path.basename(file_path) + ".sig"
            except Exception as e:
                self.log(f"Erro ao ler o arquivo '{file_path}': {e}")
                QMessageBox.critical(self, "Erro", f"Erro ao ler o arquivo: {e}")
                return

        try:
            self.log(f"Iniciando assinatura para '{output_filename}'...")
            signature_int, _ = rsa_pss.generate_pss_signature(
                message_bytes_to_sign,
                current_private_key["d"],
                current_private_key["n"],
                DEFAULT_SALT_LEN,
                HASH_ALGO
            )

            formatted_signature_str = rsa_pss.format_pss_signature_for_storage(
                signature_int,
                current_private_key["n"],
                DEFAULT_SALT_LEN,
                HASH_ALGO_NAME
            )
            with open(output_filename, "w") as f:
                f.write(formatted_signature_str)
            self.log(f"Assinatura gerada e salva em '{output_filename}'.")
            QMessageBox.information(self, "Sucesso", "Assinatura gerada com sucesso!")
        except Exception as e:
            self.log(f"Erro ao gerar assinatura: {e}")
            QMessageBox.critical(self, "Erro", f"Falha na geração da assinatura: {e}")

    def verify_content(self):
        if not current_public_key:
            self.log("Erro: Nenhuma chave pública carregada. Por favor, gere ou carregue chaves primeiro.")
            QMessageBox.warning(self, "Erro", "Nenhuma chave pública carregada.")
            return

        signature_file_path = self.signature_file_edit.text().strip()
        if not signature_file_path:
            self.log("Erro: Caminho do arquivo de assinatura vazio.")
            QMessageBox.warning(self, "Erro", "Por favor, selecione o arquivo de assinatura.")
            return
        if not os.path.exists(signature_file_path):
            self.log(f"Erro: Arquivo de assinatura '{signature_file_path}' não encontrado.")
            QMessageBox.critical(self, "Erro", f"Arquivo de assinatura '{signature_file_path}' não encontrado.")
            return

        try:
            with open(signature_file_path, "r") as f:
                formatted_signature_str = f.read()
            parsed_sig_data = rsa_pss.parse_pss_signature_from_storage(formatted_signature_str)
        except Exception as e:
            self.log(f"Erro ao ler ou parsear o arquivo de assinatura '{signature_file_path}': {e}")
            QMessageBox.critical(self, "Erro", f"Erro ao parsear a assinatura: {e}")
            return
        
        original_content_bytes = None
        m_hash_for_verification = None

        if self.verify_message_radio.isChecked():
            message = self.original_message_verify_input.toPlainText().strip()
            if not message:
                self.log("Erro: Mensagem original vazia.")
                QMessageBox.warning(self, "Erro", "Por favor, digite a mensagem original para verificação.")
                return
            original_content_bytes = message.encode('utf-8')
            m_hash_for_verification = hasher.calculate_sha3_256_from_bytes(original_content_bytes)
        else: # Verificando arquivo
            file_path = self.file_path_verify_edit.text().strip()
            if not file_path:
                self.log("Erro: Caminho do arquivo original vazio.")
                QMessageBox.warning(self, "Erro", "Por favor, selecione o arquivo original para verificação.")
                return
            if not os.path.exists(file_path):
                self.log(f"Erro: Arquivo original '{file_path}' não encontrado.")
                QMessageBox.critical(self, "Erro", f"Arquivo '{file_path}' não encontrado.")
                return
            try:
                # Lendo o conteúdo bruto do arquivo para hasher.calculate_sha3_256_from_file
                original_content_bytes = open(file_path, 'rb').read() 
                m_hash_for_verification = hasher.calculate_sha3_256_from_file(file_path) # Hash do arquivo
            except Exception as e:
                self.log(f"Erro ao ler ou hashear o arquivo original '{file_path}': {e}")
                QMessageBox.critical(self, "Erro", f"Erro ao ler o arquivo original: {e}")
                return
            
        try:
            self.log("Iniciando verificação da assinatura...")
            em_recovered_int = rsa_pss.pss_verify_decrypt_signature(
                parsed_sig_data["signature_int"],
                current_public_key["e"],
                current_public_key["n"]
            )
            
            is_valid = rsa_pss.pss_decode(
                em_recovered_int,
                m_hash_for_verification, # Hash do conteúdo original (mensagem ou arquivo)
                current_public_key["n"].bit_length() - 1,
                parsed_sig_data["salt_length"],
                HASH_ALGO
            )

            if is_valid:
                self.log("\n>>> VERIFICAÇÃO BEM-SUCEDIDA: A assinatura é VÁLIDA! <<<")
                QMessageBox.information(self, "Resultado", "Assinatura VÁLIDA!")
            else:
                self.log("\n>>> VERIFICAÇÃO FALHOU: A assinatura é INVÁLIDA! <<<")
                QMessageBox.warning(self, "Resultado", "Assinatura INVÁLIDA!")
        except Exception as e:
            self.log(f"Erro durante o processo de verificação: {e}")
            QMessageBox.critical(self, "Erro", f"Falha na verificação da assinatura: {e}")

# --- Ponto de Entrada da Aplicação ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RSAPSSApp()
    window.show()
    sys.exit(app.exec())