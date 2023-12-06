import cryptochat

if __name__ == '__main__':
    vpn = cryptochat.VpnServer(
        vpn_user=cryptochat.User(user_id='VPN').login(),
        local_server_ip='0.0.0.0',
        local_server_port_source=50_002,
        local_server_port_destination=60_002,
        source_ip='172.20.53.103',
        source_port=50_000,
    )
    vpn.connect_to_source()
    print("----------src")
    vpn.connect_to_destination()
    print("----------dest")
    vpn.authenticate_between_source_and_destination()
