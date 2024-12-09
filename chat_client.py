import sys
import socket
import threading
from chatui import init_windows, read_command, print_message, end_windows
import signal
import json


def usage():
    print("Usage: python chat_client.py <username> <host> <port>")
    return

def main(argv):
    try:
        host = argv[2]
        port = int(argv[3])
        name = argv[1]
    except:
        usage()
        return 1
    init_windows()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    hello_message = json.dumps({"type": "hello", "nick": name}).encode()
    hello_message_length = len(hello_message).to_bytes(4, byteorder='big')
    s.send(hello_message_length + hello_message)

    stop_event = threading.Event()#will shop receiver when sender calls exit()
    signal.signal(signal.SIGINT, lambda signal, frame: exit(s, name, stop_event)) #exit when ctrl+c is pressed w/out errors

    sending_thread = threading.Thread(target=send, args=(name,s, stop_event))
    recieving_thread = threading.Thread(target=receive, args=(s,stop_event))
    sending_thread.start()
    recieving_thread.start()

    sending_thread.join()
    recieving_thread.join()

    end_windows()
    s.close()


def exit(s, name, stop_event):
    print("Exiting...")
    exit_message = json.dumps({
    "type": "leave",
    "nick": name
    }).encode()
    exit_message_length = len(exit_message).to_bytes(4, byteorder='big')
    s.send(exit_message_length + exit_message)
    stop_event.set()
    s.close()
    sys.exit(0)
    


def receive(s, stop_event):
    buffer = b""
    #recieve from server
    while not stop_event.is_set():
        data = s.recv(1024)
        buffer += data
        while packet_complete(buffer):
            packet, buffer = packet_extract(buffer)
            packet = packet[header_size:]
            data = json.loads(packet.decode())
            match data["type"]:
                case "join":
                    message = f"*** {data['nick']} has joined the chat"
                    print_message(message)

                case "leave":
                    message = f"*** {data['nick']} has left the chat"
                    print_message(message)

                case "message":
                    message = f"{data['nick']}: {data['message']}"
                    print_message(message)
def send(name, s, stop_event):
    #handle input
    while True:
        try: 
            message = read_command(name+"> ") 
            split_message = list(message)
            if len(split_message) > 0:
                if split_message[0] == "/":
                    if split_message[1] == "q":
                        exit(s, name, stop_event)
            message = {"type": "message", "nick": name, "message": message}
            packet = build_packet(message)
            s.send(packet)
            #update terminal
            print_message(name+": "+message["message"])
        except BrokenPipeError:
            print("Server has disconnected")
            stop_event.set()
            sys.exit(0)

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


if __name__ == "__main__":
    sys.exit(main(sys.argv))