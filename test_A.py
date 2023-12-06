import cryptochat

if __name__ == '__main__':
    user_A = cryptochat.User(user_id='A').login()

    vpn_connection = cryptochat.VpnDestination(
        vpn_destination_ip='127.0.0.1',
        vpn_destination_port=60_000)
    
    A_connection = cryptochat.Connection(
        client_ip='127.0.0.1',
        client_port=50_002,
        local_server_ip='127.0.0.1',
        local_server_port=50_000,
    )
    
    chat = cryptochat.CryptoChatVpn(
        user=user_A, 
        connection=A_connection,
        vpn=vpn_connection,
    ).start()._test_threaded_chat()



