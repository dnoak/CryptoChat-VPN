import cryptochat

if __name__ == '__main__':
    user_B = cryptochat.User(user_id='B').login()
    B_connection = cryptochat.Connection(
        client_ip='127.0.0.1',
        client_port=60_002,
        local_server_ip='127.0.0.1',
        local_server_port=60_000,
    )
    
    chat = cryptochat.CryptoChatVpn(
        user=user_B, 
        connection=B_connection,
    ).start()._test_threaded_chat()