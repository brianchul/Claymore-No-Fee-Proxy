#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import socket
import threading
import json
from collections import OrderedDict
import binascii
import re
import datetime
import time
import argparse
from termcolor import colored
import os


def server_loop(local_host, local_port, remote_host, remote_port):
    # create the server object
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # lets see if we can stand up the server
    try:
        print(colored("[!] Daemon is launched on %s:%d, do not close this windows\n" % (local_host, local_port), "yellow"))
        server.bind((local_host, local_port))
    except:
        print(colored("[!!] Failed to listen on %s:%d\n" % (local_host, local_port), "red"))
        print(colored("[!!] Check for other listening sockets or correct permissions\n", "red"))
        sys.exit(0)

    # listen with 5 backlogged--queued--connections
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # print out the local connection information
        print(colored("[+] Received incomming connections from %s:%d\n" % (addr[0], addr[1]), "cyan"))

        # start a new thread to talk to the remote host
        proxy_thread = threading.Thread(target=proxy_handler,
                                        args=(client_socket, local_port, remote_host, remote_port))
        proxy_thread.daemon = False

        proxy_thread.start()


def receive_from(connection):

    buffer = ""

    # We set a 2 second time out depending on your
    # target this may need to be adjusted
    connection.settimeout(0)

    try:
        # keep reading into the buffer until there's no more data
        # or we time out
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass

    return buffer


# modify any requests destined for the remote host
def request_handler(socket_buffer):
    #Here is the good part

    #If it is an Auth packet
    if ('submitLogin' in socket_buffer) or ('eth_login' in socket_buffer):
        json_data = json.loads(socket_buffer, object_pairs_hook=OrderedDict)
        print((colored('[+] Auth in progress with address: ' + json_data['params'][0], "yellow")))
        #If the auth contain an other address than our
        if wallet not in json_data['params'][0]:
             print((colored('[*] DevFee Detected - Replacing Address - ' + str(datetime.datetime.now()), "yellow")))
             print((colored('[*] OLD: ' + json_data['params'][0], "yellow")))
             #We replace the address
             json_data['params'][0] = wallet + worker_name
             print((colored('[*] NEW: ' + json_data['params'][0], "yellow")))


        socket_buffer = json.dumps(json_data) + '\n'

    #Packet is forged, ready to send.
    return socket_buffer



# modify any responses destined for the local host
def response_handler(buffer):
    return buffer


def proxy_handler(client_socket, local_port, remote_host, remote_port):
    # We prepare the connection
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # We will try to connect to the remote pool
    for attempt_pool in range(3):
        try:
            remote_socket.connect((remote_host, remote_port))
        except:
            print(colored("[!] "+ str(datetime.datetime.now())+" IImpossible to connect to the pool. Try again in few seconds ", "red"))
            time.sleep(2)
        else:
            # Connection OK
            break
    else:
        print(colored("[!] "+ str(datetime.datetime.now())+" Impossible initiate connection to the pool. Claymore should reconnect. (Check your internet connection) ", "red"))

        #Closing connection
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()

        #Exiting Thread
        sys.exit()


    # now let's loop and reading from local, send to remote, send to local
    # rinse wash repeat
    while True:

        # read from local host
        local_buffer = receive_from(client_socket)

        if len(local_buffer):

            # send it to our request handler
            local_buffer = request_handler(local_buffer)

            if('method' in local_buffer):
                msg = ''
                sliced_buffer = local_buffer.split("\n")
                for sliced in sliced_buffer:
                    if sliced == "":
                        continue
                    json_parse = json.loads(sliced)
                    method = str(json_parse['method'])
                    if method == "eth_submitWork":
                        msg = colored("Share Submit !!!", "green")
                    elif method == "eth_getWork":
                        msg = colored("Get New Work", "white", attrs=['dark'])
                    elif method == "eth_submitHashrate":
                        msg = colored("Update New Hashrate", 'yellow')
                    elif method == "eth_submitLogin":
                        msg = colored("Logging in ...", 'yellow')
                    else:
                        msg = method


                    print(colored("[<] ", "white") + str(datetime.datetime.now()) + " LOCAL [" + str(local_port) + "]: " + msg)

            # Try to send off the data to the remote pool
            try:
                remote_socket.send(local_buffer)
            except:
                print(colored("[!] "+str(datetime.datetime.now())+" Sending packets to pool failed.", "red"))
                time.sleep(0.02)
                print(colored("[!] "+str(datetime.datetime.now())+" Connection with pool lost. Claymore should reconnect. (May be temporary) ", "red"))
                #Closing connection
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
                #Exiting loop
                break

            # Adding delay to avoid too much CPU Usage
            time.sleep(0.001)

        # receive back the response
        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):

            # send to our response handler
            remote_buffer = response_handler(remote_buffer)

            if('result' in remote_buffer):
                msg = ''
                sliced_buffer = remote_buffer.split("\n")
                for sliced in sliced_buffer:
                    if sliced == "":
                        continue
                    json_parse = json.loads(sliced)
                    result = json_parse["result"]
                    if isinstance(result, list):
                        msg = colored("Send New Work #" + result[0][2:11],"white", attrs=['dark'])
                    elif isinstance(result, bool):
                        msg = colored("Submit Accepted", 'green')
                    print(colored("[>] ","cyan") + str(datetime.datetime.now()) + " REMOTE      : " + msg)

            # Try to send the response to the local socket
            try:
                 client_socket.send(remote_buffer)
            except:
                 print(colored('[-] '+str(datetime.datetime.now())+' Auth Disconnected - Ending Devfee or stopping mining', 'red'))
                 client_socket.close()
                 break

            # Adding delay to avoid too much CPU Usage
            time.sleep(0.001)
        time.sleep(0.001)

    #Clean exit if we break the loop
    sys.exit()


def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-o', '--remote-host', dest='remote_host', type=str, default='eu1.ethermine.org', help='Hostname of Stratum mining pool')
    parser.add_argument('-p', '--remote-port', dest='remote_port', type=int, default=4444, help='Port of Stratum mining pool')
    parser.add_argument('-O', '--local-host', dest='local_host', type=str, default='0.0.0.0', help='On which network interface listen for stratum miners. Use "localhost" for listening on internal IP only.')
    parser.add_argument('-P', '--local-port', dest='local_port', type=str, default=8008, help='Port on which port listen for stratum miners.')
    parser.add_argument('-w', '--wallet-address', dest='wallet_address', type=str, required=True, help='Wallet address, may include rig name with "." or "/" separator')

    args = parser.parse_args()

    # set up listening parameters
    local_host = args.local_host
    local_port = args.local_port

    # set up remote targets
    remote_host = args.remote_host
    remote_port = args.remote_port

    m = re.search('^(?P<wallet_addr>[^./]+)(?P<rig_name>[./].+)?', args.wallet_address)

    if m is None:
        print('Invalid wallet address, exiting...');
        sys.exit(-1)

    # Set the wallet
    global wallet
    wallet = str(m.group('wallet_addr') or '')

    global worker_name
    worker_name = str(m.group('rig_name') or '')

    print("Wallet set: " + wallet + worker_name)


    os.system('color')
    # now spin up our listening socket
    if ',' in local_port:
        for port in local_port.split(","):
            proxy_thread = threading.Thread(target=server_loop,
                                        args=(local_host, int(port), remote_host, remote_port))
            proxy_thread.daemon = False

            proxy_thread.start()

    else:
        server_loop(local_host, int(local_port), remote_host, remote_port)


if __name__ == "__main__":
    main()
