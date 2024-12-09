import sys
import socket
import select
import json
import signal

def run_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    s.listen()
    print(f"Server listening on port {port}")   
    buffers = {}
    set = [s]

    def signal_handler(sig, frame): #closes gracufully when ctrl c is used
        print("Shutting down server...")
        s.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while True: # wait for data
        ready_sockets, _, _ = select.select(set, [], [])
        for ready_socket in ready_sockets:
            if ready_socket == s: #if connection socket, accept connection
                conn = s.accept()[0]
                set.append(conn) #client will send hello message later to inform server of name
                buffers[conn] = b""
            
            else: #if data socket, receive data
                data = ready_socket.recv(1024)
                buffers[ready_socket] += data
                while packet_complete(buffers[ready_socket]): #as long as we have a complete message in teh buffer for the client
                    data, buffers[ready_socket] = packet_extract(buffers[ready_socket])
                    data = data[header_size:]
                    data = json.loads(data.decode())
                    match data["type"]:
                        case "hello":
                            message = {"type": "join", "nick": data["nick"]}
                            packet = build_packet(message)
                            #send all data to clients
                            for client_socket in set: 
                                send_packet(client_socket, s, ready_socket, packet)

                        case "leave":
                            message = {"type": "leave", "nick": data["nick"]}
                            packet = build_packet(message)
                            set.remove(ready_socket)
                            buffers.pop(ready_socket, None)
                            for client_socket in set:
                                send_packet(client_socket, s, ready_socket, packet)
                            ready_socket.close()
                            break

                        case "message":
                            message = {"type": "message", "nick": data["nick"], "message": data["message"]}
                            packet = build_packet(message)
                            for client_socket in set:
                                send_packet(client_socket, s, ready_socket,packet)

def send_packet(client_socket, connection_socket, ready_socket, packet):
    if client_socket != connection_socket and client_socket != ready_socket:
        client_socket.sendall(packet)

header_size = 4
def packet_complete(data):
    if len(data) < header_size: #no complete header / buffer empty
        return False
    length = int.from_bytes(data[:header_size], byteorder="big") #extract length from the header (\x00\x05 -> 5)
    message = data[header_size:length+header_size] #extract message from the data (\x00\x05hello -> hello)
    return  length == len(message)#if the expected length is the actual length of the message, return True

def packet_extract(data):
    length = int.from_bytes(data[:4], byteorder="big") #extract length from the header
    packet = data[:length+header_size] #extract packet from the data (\x00\x05hello\x00\x01\h -> \x00\x05hello)
    remaining_buffer= data[length+header_size:] #extract remaining buffer
    return packet, remaining_buffer #return packet and remaining buffer

def build_packet(data):
    data = json.dumps(data).encode()
    return len(data).to_bytes(4, byteorder="big") + data


def usage():
    print("Usage: python chat_server.py <port>")
    return

def main(argv):
    try:
        port = int(argv[1])
    except:
        usage()
        return 1

    run_server(port)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
