from tensorflow.keras.models import load_model
import math
import socket
import pickle

def load_ml_model():
    # load model 
    model = load_model('dns_tunneling_ml.h5')
    return model

ff = load_ml_model()

tokenizer = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']

def extract_single_value(variable):
    if isinstance(variable, list):
        if len(variable) == 1:
            return extract_single_value(variable[0])
        else:
            raise ValueError("The provided list has more than one element.")
    else:
        return variable

def count_vector(url) -> list:
    tmp = []
    for i in range(96):
        tmp.append(0)
    for i in url:
        if (i in tokenizer):
            tmp[tokenizer.index(i)] += 1
    return tmp

def entropy_calculator(url) -> float:
    if not url:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(url.count(chr(x)))/len(url)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def calculate_length(url) -> int:
  if not url:
    return 0
  return len(url)

def isDNSTunneling(custom_dns):

    custom_temp = count_vector(custom_dns)
    custom_temp[94] = float(entropy_calculator(custom_dns))
    custom_temp[95] = float(calculate_length(custom_dns))

    x_custom = [custom_temp,]


    y_custom = ff.predict(x_custom)
    probability = 1
    result = ""
    if y_custom < 0.5 :
        probability = (1-y_custom)*100
        result = 0
    else:
        probability = y_custom[0,0]*100

    return result

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific address and port
server_address = ('0.0.0.0', 5050)
server_socket.bind(server_address)

# Listen for incoming connections (max 1 connection in this example)
server_socket.listen(1)
print('Server is listening on {}:{}'.format(*server_address))

while True:
    # Wait for a connection
    print('Waiting for a connection...')
    client_socket, client_address = server_socket.accept()
    print('Connection established with {}:{}'.format(*client_address))

    try:
        # Receive the string from the client
        received_string = client_socket.recv(1024).decode('utf-8')
        my_dns = '{!r}'.format(received_string)
        print('Received string:', my_dns)

        # Process the string (you can perform any logic here)
        # For simplicity, let's create a sample tuple as a response
        response_t = isDNSTunneling(my_dns)

        # Serialize the tuple using pickle
        serialized_data = pickle.dumps(response_t)

        # Send the serialized data (tuple) back to the client
        client_socket.sendall(serialized_data)
        print('Sent data: {!r}'.format(response_t))

    finally:
        # Clean up the connection
        client_socket.close()
