import socket

PORT_NUM = 50001
IP_ADDR = "127.0.0.1"
AMOUNT_CLIENTS_AT_SAME_TIME = 1
MAX_SIZE_BUFFER = 1024


def main():
    # Building the server
    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_addr = (IP_ADDR, PORT_NUM)
    listening_socket.bind(server_addr)
    listening_socket.listen(AMOUNT_CLIENTS_AT_SAME_TIME)
    print("Waiting for a client")
    client_sock, client_addr = listening_socket.accept()
    print("Got client! ")
    while True:
        msg = client_sock.recv(MAX_SIZE_BUFFER).decode()
        print("Got a msg")
        print(str(msg))
        if msg == str(400):
            break


if __name__ == "__main__":
    main()
