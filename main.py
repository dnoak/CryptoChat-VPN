import threading
import time
import cryptochat
import sys
from pathlib import Path
from qt.chat_window import Ui_CHAT
from qt.menu_window import Ui_MENU
from PyQt5 import QtWidgets

class ChatWindow(QtWidgets.QMainWindow):
    def __init__(self, chat: cryptochat.CryptoChatVpn):
        super().__init__()
        self.ui = Ui_CHAT()
        self.ui.setupUi(self)
        self.chat = chat
        self.update_chat()
        threading.Thread(target=self.receive_message_loop).start()
        self.send_message_loop()

    def update_chat(self):
        self.ui.label_chat_history.setText(''.join(self.chat.history))
        self.ui.scrollArea.verticalScrollBar().setValue(self.ui.scrollArea.verticalScrollBar().maximum())
        self.ui.friend_name.setText(self.chat.friend_id)

    def send_message(self):
        message = self.ui.input_message.text()
        self.chat.send_message(message)
        self.ui.input_message.clear()
        self.update_chat()
    
    def receive_message_loop(self):
        while True:
            self.chat.receive_message()
            self.update_chat()
        
    def send_message_loop(self):
        self.ui.button_send_message.released.connect(self.send_message)
        self.ui.input_message.returnPressed.connect(self.send_message)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MENU()
        self.ui.setupUi(self)
        self.inputs_dict = {}
        self.chat_window_trigger()
    
    def inputs_triggers(self):
        self.ui.button_connect.released.connect(self.get_inputs)
        self.ui.input_user_id.returnPressed.connect(self.get_inputs)
        self.ui.input_host.returnPressed.connect(self.get_inputs)
        self.ui.input_local_server.returnPressed.connect(self.get_inputs)
        self.ui.input_vpn.returnPressed.connect(self.get_inputs)

    def get_inputs(self):
        try:
            self.inputs_dict['user_id'] = self.ui.input_user_id.text()
            self.inputs_dict['local_server_ip'] = self.ui.input_local_server.text().split(':')[0]
            self.inputs_dict['local_server_port'] = int(self.ui.input_local_server.text().split(':')[1])
            if self.ui.input_vpn.text() != '':
                self.inputs_dict['host_ip'] = self.ui.input_vpn.text().split(':')[0]
                self.inputs_dict['host_port'] = int(self.ui.input_vpn.text().split(':')[1])
                self.inputs_dict['vpn_ip'] = self.ui.input_host.text().split(':')[0]
                self.inputs_dict['vpn_port'] = int(self.ui.input_host.text().split(':')[1])
            else:
                self.inputs_dict['host_ip'] = self.ui.input_host.text().split(':')[0]
                self.inputs_dict['host_port'] = int(self.ui.input_host.text().split(':')[1])
                self.inputs_dict['vpn_ip'] = None
                self.inputs_dict['vpn_port'] = None
            self.chat_window_trigger()
        except Exception as e:
            print(e)
            self.inputs_dict = {}
    
    def call_chat_window(self, chat):
        self.chat_window = ChatWindow(chat)
        self.chat_window.show()
        self.hide()

    def set_vpn_connection(self):
        connection = cryptochat.Connection(
            client_ip=self.inputs_dict['vpn_ip'],
            client_port=self.inputs_dict['vpn_port'],
            local_server_ip=self.inputs_dict['local_server_ip'],
            local_server_port=self.inputs_dict['local_server_port'])

    def chat_window_trigger(self):
        try:
            self.inputs_triggers()
            print(self.inputs_dict)
            user = cryptochat.User(user_id=self.inputs_dict['user_id']).login()
            connection = cryptochat.Connection(
                client_ip=self.inputs_dict['host_ip'],
                client_port=self.inputs_dict['host_port'],
                local_server_ip=self.inputs_dict['local_server_ip'],
                local_server_port=self.inputs_dict['local_server_port'])
            vpn = cryptochat.VpnDestination(
                vpn_destination_ip=self.inputs_dict['vpn_ip'],
                vpn_destination_port=self.inputs_dict['vpn_port'])
            chat = cryptochat.CryptoChatVpn(
                    user=user, 
                    connection=connection, 
                    vpn=vpn if self.inputs_dict['vpn_ip'] else None,
                ).start()
            self.call_chat_window(chat)
        except Exception as e:
            print(e)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())