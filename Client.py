#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Fri Apr  5 22:09:33 2019

@author: ilm4zz4
"""

import re #regexp
import socket #Setup Socket
import threading
import time
import datetime

import logging
import sys
import json

import select


help_message="""
!help --> show the set of the commands
!connect <user> --> start a new chat with the specific user
!usersList --> get the list of the users from the server
!disconnect --> free the client from the current chat
!quit --> exit from application
"""

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Client(object):

    #Status of the client
    #0: the threads are in temination
    #1: the threads up, but not registered into TCP Server
    #2: the client is regitered into TCP Server
    #3: the client has started a UDP communication with other client
    status_states = {'quit': 0, 'unregitered':1, 'regitered':2, 'busy':3}

    def __init__(self, ip , port, nickname):

        self.status = self.status_states['unregitered']

        #logging.basicConfig(filename='Client-'+ str(port) +'.log',
        #                    format='%(asctime)s %(message)s',
        #                    datefmt='%m/%d/%Y %I:%M:%S %p',
        #                    filemode='w', level=logging.DEBUG)

        self.thr_rcv  = ""
        self.thr_term = ""
        self.nickname = nickname

        self.user_UDP_IP=""
        self.user_UDP_PORT=""

        self.UDP_IP = ip
        self.UDP_PORT = port

        self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_udp.bind((self.UDP_IP, self.UDP_PORT))
        self.sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_udp.settimeout(1) #The socker is not blocked, the exception need to be managed

        self.SERVER_TCP_IP = "127.0.0.1"
        self.SERVER_TCP_PORT = 3000

        if not self.getConnectionServer():
            self.printlog(bcolors.FAIL, "Any Sever is present at address: " + self.SERVER_TCP_IP + " and port: " + str(self.SERVER_TCP_PORT))
            self.sock_udp.close()
            exit (1)

        self.printlog(bcolors.OKGREEN, 'The Client is running on ip: ' + self.UDP_IP + ', port: ' + str(self.UDP_PORT) + '\n' +  help_message)
        self.updateIam()

    def updateIam(self):
        self.iam={"nickname":self.nickname, "ip":self.UDP_IP, "port":str(self.UDP_PORT)}

    def getTimestamp(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    def printlog(self, color, msg):
        if not isinstance(msg, basestring):
            msg = str(msg)
        print color + self.getTimestamp() + ' - ' + msg + bcolors.ENDC

    #Send message to TCP server
    #The connection is estabilished only to send the message after it will be closed
    #Every message sent, expected an answer from server
    def getConnectionServer(self):
        #self.printlog(bcolors.UNDERLINE, self.SERVER_TCP_IP + str(self.SERVER_TCP_PORT)
        try:
            self.sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_tcp.settimeout(6)
            self.sock_tcp.connect((self.SERVER_TCP_IP , self.SERVER_TCP_PORT))
            return True
        except  socket.error as e:
            self.printlog(bcolors.FAIL, e)


    def closeConnectionServer(self):
        self.sock_tcp.close()

    def sendMsgServer(self,msg):

        #----------Transmit Request-------------------
        try:
            self.sock_tcp.sendall(msg)
            #self.printlog(bcolors.OKBLUE, "control -->  " + self.SERVER_TCP_IP+ ":" + str(self.SERVER_TCP_PORT) + bcolors.HEADER + " | " + msg)

        except socket.error as e:
            self.printlog(bcolors.FAIL, "control -->  " + str(e))
            self.status = self.status_states['unregitered']

            return {'action':'signin', 'result':'ERR', 'comment':'Server could be unreachable'}

    ##################### Communication message with TCP server  #####################
    #To perform tthe login when the client starts
    def tcpServerSignIn(self):
        msg = str({"type":"control", "action": "sigin", "whoami":self.iam})
        data_raw = self.sendMsgServer(msg)
        return data_raw

    #To get the user which have done the SingIn into the server
    def tcpServerUsersList(self):
        msg = str({"type":"control", "action": "userslist", 'whoami':self.iam })
        data_raw = self.sendMsgServer(msg)
        #return data_raw

    #Notify to Server the switch off of the client
    def tcpServerLogout(self):
        msg = str({"type":"control", "action": "logout", 'whoami':self.iam })
        data_raw = self.sendMsgServer(msg)
        return data_raw

    #Ask to the server the info of the client (IP and port)
    def tcpServerUserConnect(self, user):
        msg = str({"type":"control", "action": "userconnect", "user":user, 'whoami':self.iam})
        data_raw = self.sendMsgServer(msg)
        return data_raw

    ##################### Communication message with Client  #####################
    def sendToClient(self, msg, ip = 'empty', port = 'empty'):
        #self.printlog(bcolors.OKGREEN, msg)
        if not isinstance(msg, basestring):
            msg = str(msg)
        if ip == 'empty':
            ip = self.user_UDP_IP
            port = self.user_UDP_PORT
        if ip :
            self.sock_udp.sendto(msg, (ip, int(port)))

    def disconnectFromUser(self):
        msg = {"type":"control",  "action": "disconnect", 'whoami':self.iam}
        self.sendToClient(msg)
        self.status = self.status_states['regitered']
        self.user_UDP_IP = ''
        self.user_UDP_PORT = ''
	self.printlog(bcolors.OKGREEN, "you are no longer connected with anyone")

    def closeClient(self):
        self.printlog(bcolors.OKGREEN, "Good Bye!")
        time.sleep(2)
        self.sock_udp.close()

    #Thread to receive the message from other clients
    def thread_receive(self):

        def connectionApproved(addr, data):
            msg = {"type":"control",  "action": "connect", "direction":"answ", "result":"OK", 'whoami':self.iam}
            self.status = self.status_states['busy']
            self.user_UDP_IP = addr[0]
            self.user_UDP_PORT = addr[1]
            self.sendToClient(msg)
            self.printlog(bcolors.OKGREEN, 'you are connected with ' + data['whoami']['nickname'] )


        #Loop will finish when the status is set with 'quit'
        while self.status:
            try:
                udp_data_raw, addr = self.sock_udp.recvfrom(1024)
                #self.printlog(bcolors.WARNING, udp_data_raw)
                data = eval (udp_data_raw.strip())

                if data['type'] == 'control':   #Control message

                    #The control messages have two direction: ask, and answer
                    #In case where the answer has not success a field 'comment' will be present
                    #Every message is composed of the indication 'whoami', to make uniform the messages, it is useful only to manage the requests of the clients outside the chat section
                    if data['action'] == 'connect' and data['direction'] == 'ask':

                        #Request to starrt the chat
                        if self.status != self.status_states['busy']:
                            confirm = raw_input(bcolors.WARNING + data['whoami']['nickname'] + " tries to connect with you, do you want? (yes/no) " + bcolors.ENDC).lower()
                            if not re.search(".*yes.*", confirm.strip()):
                                msg = {"type":"control",  "action": "connect", "direction":"answ", "result":"FAIL", 'comment':'The user is not available', 'whoami':self.iam}
                                self.sendToClient(msg, ip = addr[0], port = addr[1])
                                continue #Not accepted, still in the state 'regitered'
                            connectionApproved(addr, data)

                        else:
                            confirm = raw_input(bcolors.WARNING + data['whoami']['nickname'] + " tries to connect with you, do you want? (yes/no) " + bcolors.ENDC).lower()
                            if not re.search(".*yes.*", confirm.strip()):
                                msg = {"type":"control",  "action": "connect", "direction":"answ", "result":"FAIL", 'comment':'The user is busy in other conversation', 'whoami':self.iam}
                                self.sendToClient(msg, ip = addr[0], port = addr[1])
                            else:
                                self.disconnectFromUser()
                                connectionApproved(addr, data)

                    #Answer to connection request
                    elif data['action'] == 'connect' and data['direction'] == 'answ':

                        if data['result'] == 'OK':
                            self.printlog(bcolors.OKGREEN, "connection is ready with " + data['whoami']['nickname'])
                            self.status = self.status_states['busy']
                        elif data['result'] == 'FAIL':
                            self.printlog(bcolors.FAIL, data['comment'])
                        else:
                            self.printlog(bcolors.FAIL, 'the answer \"' + str(data) + '\" is not valid')

                    #Notify from client that make quit or disconnect
                    elif data['action'] == 'disconnect':
                        self.status = self.status_states['regitered']
                        self.user_UDP_IP = ''
                        self.user_UDP_PORT = ''
                        self.printlog(bcolors.WARNING, 'the user ' + data['whoami']['nickname'] + ' is disconnected by you')

                #The message received is a text message
                elif data['type'] == 'text':
                    self.printlog (bcolors.ENDC,  bcolors.OKBLUE + '[' + data['whoami']['nickname'] + ']' + bcolors.ENDC + ' - ' + data['msg'])

            #Exception due to the receive is not in blocking mode. To allow to the thread the shutdown
            except socket.error as e:
                #write to file or whatever
                if str(e) == "[Errno 35] Resource temporarily unavailable":
                    time.sleep(1)
                    continue
                elif str(e) == "timed out":
                    time.sleep(1)
                    continue

                else:
                    self.printlog(bcolors.WARNING, str(e))


    #Thread to manage the commands from SDTIN
    def thread_commands(self):
        while self.status != self.status_states['quit']:
            if self.status == self.status_states['unregitered']:
                self.tcpServerSignIn()
                time.sleep(3)



            i, o, e = select.select( [sys.stdin], [], [], 1 )

            if (i):
                data_string = sys.stdin.readline().strip()
            else:
              continue

            #To mange the command on STDIN
            if re.search("^!.*$", data_string):

                #Command set
                #------------------- HELP
                if data_string == '!help':
                    self.printlog(bcolors.OKGREEN, help_message)
                #------------------- CONNECT
                elif re.search("^!connect.*$", data_string):
                    user = data_string.strip().split(' ')[1]

                    if user != self.nickname:
                        if self.tcpServerUserConnect(user):
                            iam={"nickname":self.nickname, "ip":self.UDP_IP, "port":str(self.UDP_PORT)}
                            msg = {"type":"control", "direction":"ask", "action": "connect", "whoami":self.iam}
                            self.sendToClient(msg)

                    else:
                        self.printlog (bcolors.FAIL,"you con not connect with your self!")

                #------------------- DISCONNECT
                elif data_string == '!disconnect':
                    self.disconnectFromUser()

                #------------------- LIST
                elif data_string.lower() == '!usersList'.lower():
                    self.tcpServerUsersList()

                #------------------- QUIT
                elif data_string == '!quit':
                    if self.status== self.status_states['busy']:
                        self.disconnectFromUser()
                    self.tcpServerLogout()
                    self.status = self.status_states['quit']

                #------------------- OUT OF RANGE
                else:
                    self.printlog(bcolors.WARNING, "Command not valid\n")
                    self.printlog(bcolors.OKGREEN, help_message)

            #Catch all text which is not a command (chat Text)
            else:
                if self.status == self.status_states['busy']:
                    msg = ({"type":"text", 'msg': data_string ,'whoami':self.iam})
                    self.sendToClient(msg)
                else:
                    self.printlog(bcolors.FAIL, "Connect yourself with someone before write a message... ")

        self.closeClient()
        self.printlog(bcolors.OKGREEN, 'Client shutdown...')

    #Thread to manage the tcp connection
    def thread_tcp(self):

        while self.status != self.status_states['quit']:
            #----------Receive Answer-------------------
            try:
                data_raw = self.sock_tcp.recv(1024)

            except socket.error as e:
                print str(e)
                #self.printlog(bcolors.FAIL, "control -->  " + str(e))
                #data=str({'action':'signin', 'result':'ERR', 'comment':'Server could be unreachable'})
                self.status = self.status_states['unregitered']
            #return data
            if data_raw:
                data=eval(data_raw)
                if data['action'] == 'signin':
                    if data['result'] == 'OK':
                        #pass
                    #self.printlog(bcolors.OKGREEN, "OK")
                    #return True, "no comment"
                     #if status:

                         self.status = self.status_states['regitered']
                         self.printlog(bcolors.OKGREEN, "SignIn into server has been performed with success")
                     #elif comment == 'Server could be unreachable':
                        # self.printlog(bcolors.FAIL, comment)
                        # pass

                    #else:
                         #self.nickname = raw_input('Nickname \'' + self.nickname + '\'  already present.\nPlease, choose a different name: ')
                         #self.updateIam()
                         #continue
                #else:
                    #return False, eval(data_raw)['comment']

                if data['action'] == 'userslist' and data['result'] == 'OK':
                    str_answ = "\n"
                    for i in data['userslist'].iteritems():
                        i = re.search('\(\'(.*)\',', str(i)).group(1)
                        if not re.search(str(self.nickname), str(i)): #To remove the same user who has performed the request
                           str_answ += str(i) + '\n'
                    self.printlog(bcolors.OKGREEN, str_answ)
                    #return True


                if data['action'] == 'logout':
                    if data['result'] == 'OK':
                        pass
                    #self.printlog(bcolors.OKGREEN, "OK")
                    #return True
                    else:
                        self.printlog(bcolors.FAIL, "FAIL")
                    #return False

                if data['action'] == 'userconnect':
                    if data['result'] == 'OK':
                        field = data['user']
                        tup = field.split(':')
                        self.user_UDP_IP = tup[0]
                        self.user_UDP_PORT = int(tup[1])
                        #return True
                    else:
                        self.printlog(bcolors.FAIL, data['comment'])
                        #return False


    #Each client is composed of two thread:
    # - self.thr_rcv: listen the message on the UDP socket (message from other client)
    # - self.thr_cmd: Get string from STDIN (commands, chat text)
    def run(self):

        self.thr_rcv = threading.Thread(target=self.thread_receive)
        self.thr_rcv.daemon = True
        self.thr_rcv.start()

        self.thr_cmd = threading.Thread(target=self.thread_commands)
        self.thr_cmd.daemon = True
        self.thr_cmd.start()

        self.thr_tcp = threading.Thread(target=self.thread_tcp)
        self.thr_tcp.daemon = True
        self.thr_tcp.start()

        self.thr_rcv.join()
        self.thr_cmd.join()
        self.thr_tcp.join()



if __name__ == "__main__":

    nickname = ''
    port = 0
    ip = ''
    if len(sys.argv) == 4:
        nickname = str(sys.argv[1])
        ip = str(sys.argv[2])
        port = int(str(sys.argv[3]))
    else:
        print(bcolors.WARNING + 'Number of aguments not valid\n' + bcolors.ENDC)
        ip = raw_input("Please, give me the ip address: ")
        port = int(int(raw_input("Please, give me the port number: ")))
        nickname = raw_input("Please, give me the nickname: ")

    client = Client(ip, port, nickname)
    client.run()
