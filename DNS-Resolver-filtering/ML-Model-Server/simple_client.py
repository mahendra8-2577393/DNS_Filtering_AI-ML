import socket
import pickle

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server's address and port
server_address = ('192.168.0.245', 5050)
client_socket.connect(server_address)
print('Connected to {}:{}'.format(*server_address))

try:
    # Send a string to the server
    message_to_send = 'sih.gov.in'
    client_socket.sendall(message_to_send.encode('utf-8'))
    print('Sent string: {!r}'.format(message_to_send))

    # Receive the serialized data (tuple) from the server
    serialized_data = client_socket.recv(4096)

    # Deserialize the data using pickle
    received_tuple = pickle.loads(serialized_data)
    print('Received data (answer): {!r}'.format(received_tuple))

finally:
    # Clean up the connection
    client_socket.close()
