import cryptochat

if __name__ == '__main__':
    vpn = cryptochat.VpnServer(
        vpn_user=cryptochat.User(user_id='VPN').login(),
        local_server_ip='127.0.0.1',
        local_server_port_source=50_002,
        local_server_port_destination=60_002,
        source_ip='127.0.0.1',
        source_port=50_000,
    )
    vpn.connect_to_source()
    vpn.connect_to_destination()
    vpn.authenticate_between_source_and_destination()

    
