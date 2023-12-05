# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'chat_window.ui'
#
# Created by: PyQt5 UI code generator 5.15.10
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_CHAT(object):
    def setupUi(self, CHAT):
        CHAT.setObjectName("CHAT")
        CHAT.resize(480, 468)
        CHAT.setStyleSheet("background-color: rgb(60, 60, 60)")
        self.centralwidget = QtWidgets.QWidget(CHAT)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.friend_name = QtWidgets.QLabel(self.centralwidget)
        font = QtGui.QFont()
        font.setPointSize(16)
        self.friend_name.setFont(font)
        self.friend_name.setAlignment(QtCore.Qt.AlignCenter)
        self.friend_name.setObjectName("friend_name")
        self.verticalLayout.addWidget(self.friend_name)
        self.frame = QtWidgets.QFrame(self.centralwidget)
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.frame)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.scrollArea = QtWidgets.QScrollArea(self.frame)
        self.scrollArea.setStyleSheet("")
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 440, 295))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.scrollAreaWidgetContents)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_chat_history = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        font = QtGui.QFont()
        font.setPointSize(16)
        self.label_chat_history.setFont(font)
        self.label_chat_history.setStyleSheet("background-color: rgb(255, 255, 255)")
        self.label_chat_history.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.label_chat_history.setObjectName("label_chat_history")
        self.horizontalLayout_3.addWidget(self.label_chat_history)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.horizontalLayout_2.addWidget(self.scrollArea)
        self.verticalLayout.addWidget(self.frame)
        self.frame_2 = QtWidgets.QFrame(self.centralwidget)
        self.frame_2.setMaximumSize(QtCore.QSize(16777215, 57))
        self.frame_2.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_2.setObjectName("frame_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.frame_2)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.input_message = QtWidgets.QLineEdit(self.frame_2)
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        self.input_message.setFont(font)
        self.input_message.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.input_message.setText("")
        self.input_message.setObjectName("input_message")
        self.horizontalLayout.addWidget(self.input_message)
        self.button_send_message = QtWidgets.QPushButton(self.frame_2)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.button_send_message.setFont(font)
        self.button_send_message.setStyleSheet("background-color: rgb(152, 152, 152)")
        self.button_send_message.setObjectName("button_send_message")
        self.horizontalLayout.addWidget(self.button_send_message)
        self.verticalLayout.addWidget(self.frame_2)
        CHAT.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(CHAT)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 480, 22))
        self.menubar.setObjectName("menubar")
        CHAT.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(CHAT)
        self.statusbar.setObjectName("statusbar")
        CHAT.setStatusBar(self.statusbar)

        self.retranslateUi(CHAT)
        QtCore.QMetaObject.connectSlotsByName(CHAT)

    def retranslateUi(self, CHAT):
        _translate = QtCore.QCoreApplication.translate
        CHAT.setWindowTitle(_translate("CHAT", "MainWindow"))
        self.friend_name.setText(_translate("CHAT", "<html><head/><body><p><span style=\" font-weight:700; color:#ffffff;\">-</span></p></body></html>"))
        self.label_chat_history.setText(_translate("CHAT", "<html><head/><body><p><span style=\" font-size:14pt; font-weight:700; color:#ffffff;\">&gt;</span></p></body></html>"))
        self.button_send_message.setText(_translate("CHAT", "Send"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    CHAT = QtWidgets.QMainWindow()
    ui = Ui_CHAT()
    ui.setupUi(CHAT)
    CHAT.show()
    sys.exit(app.exec_())
