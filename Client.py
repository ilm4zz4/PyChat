#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Fri Apr  5 22:09:33 2019

@author: mrosellini
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
!help --> mostra l'elenco dei comandi disponibili
!connect user --> start a new chat with the specific user
!updateGroup namegroup user1 user2 ... userN --> create an user group
!leaveGroup namegroup --> leave the group
!connectGroup namegroup --> leave the group
!usersList --> get the list of user in the server
!disconnect --> free the client from the current chant
!quit --> terminazione
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

    status_states = {'quit': 0, 'unregitered':1, 'regitered':2, 'busy':3}

    def __init__(self, ip , port, nickname):

        self.status = self.status_states['unregitered'] #True app is UP, False app is closing

        logging.basicConfig(filename='Client-'+ str(port) +'.log',
                            format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p',
                            filemode='w', level=logging.DEBUG)

        self.UDP_IP = ip
        self.UDP_PORT = port

        self.user_UDP_IP=""
        self.user_UDP_PORT=""

        self.SERVER_TCP_IP = "127.0.0.1"
        self.SERVER_TCP_PORT = 3000
        self.thr_rcv  = ""
        self.thr_term = ""
        self.nickname = nickname

        self.iam={"nickname":self.nickname, "ip":self.UDP_IP, "port":str(self.UDP_PORT)}

        self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_udp.bind((self.UDP_IP, self.UDP_PORT))
        self.sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_udp.settimeout(1)

    def getTimestamp(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    def printlog(self, color, msg):
        if not isinstance(msg, basestring):
            msg = str(msg)
        print color + self.getTimestamp() + ' - ' + msg + bcolors.ENDC

    def sendMsgServer(self,msg):

        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_tcp.settimeout(2)

        #----------Transmit Request-------------------
        try:
            sock_tcp.connect((self.SERVER_TCP_IP , self.SERVER_TCP_PORT))
            sock_tcp.sendall(msg)
            self.printlog(bcolors.OKBLUE, "control -->  " + self.SERVER_TCP_IP+ ":" + str(self.SERVER_TCP_PORT) + bcolors.HEADER + " | " + msg)

        except socket.error as e:
            self.printlog(bcolors.FAIL, "control -->  " + str(e))
            return

        #----------Receive Answer-------------------
        try:
            data = sock_tcp.recv(1024)
        except socket.error as e:
            self.printlog(bcolors.FAIL, "control -->  " + str(e))
            data=""
        sock_tcp.close()
        return data


    def tcpServerSignIn(self):
        msg = str({"type":"control", "action": "sigin", "whoami":self.iam})
        data_raw = self.sendMsgServer(msg)
        if data_raw:
            data=eval(data_raw)
            if eval(data_raw)['action'] == 'signin' and eval(data_raw)['result'] == 'OK':
                self.printlog(bcolors.OKGREEN, "OK")
                return True
            else:
                return False
    def tcpServerGrousUpdate(self, goup):
        msg = str({"type":"control", "action": "updategroup", 'group': goup,'whoami':self.iam })
        data_raw = self.sendMsgServer(msg)
        if data_raw:
            data=eval(data_raw)
            if data['action'] == 'updategroup' and data['result'] == 'OK':
                return True
            else:
                return False

    def tcpServerUsersList(self):
        msg = str({"type":"control", "action": "userslist", 'whoami':self.iam })
        data_raw = self.sendMsgServer(msg)
        if data_raw:
            data=eval(data_raw)
            if data['action'] == 'userslist' and data['result'] == 'OK':
                str_answ = "\n"
                for i in data['userslist'].iteritems():
                    i = re.search('\(\'(.*)\',', str(i)).group(1)
                    if not re.search(str(self.nickname), str(i)):
                       str_answ += str(i) + '\n' 
                self.printlog(bcolors.OKGREEN, str_answ)
                return True

    def tcpServerGroupsList(self):
        msg = str({"type":"control", "action": "groupslist", 'whoami':self.iam })
        data_raw = self.sendMsgServer(msg)
        if data_raw:
            data=eval(data_raw)
            if data['action'] == 'groupslist' and data['result'] == 'OK':
                str_answ = "\n"
                for i in data['groupslist'].iteritems():
                    str_answ += str(i) + '\n'
                    self.printlog(bcolors.OKGREEN, str_answ)

                return data['groupslist']
    #def tcpServerConnectToGroup(self):
    #    list = tcpServerGroupsList()


    def tcpServerLogout(self):
        msg = str({"type":"control", "action": "logout", 'whoami':self.iam })
        data_raw = self.sendMsgServer(msg)
        if data_raw:
            data=eval(data_raw)
            if data['action'] == 'logout' and data['result'] == 'OK':
                self.printlog(bcolors.OKGREEN, "OK")

    def tcpServerUserConnect(self, user):
        msg = str({"type":"control", "action": "userconnect", "user":user, 'whoami':self.iam})
        data_raw = self.sendMsgServer(msg)
        if data_raw:
            data=eval(data_raw)
            if data['action'] == 'userconnect' and data['result'] == 'OK':
                field = data['user']
                tup = field.split(':')
                self.user_UDP_IP = tup[0]
                self.user_UDP_PORT = int(tup[1])
                return True
            else:
                self.printlog(bcolors.FAIL, data['comment'])
                return False

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


    def thread_receive(self):

        def connectionApproved(addr, data):
            msg = {"type":"control",  "action": "connect", "direction":"answ", "result":"OK", 'whoami':self.iam}
            self.status = self.status_states['busy']
            self.user_UDP_IP = addr[0]
            self.user_UDP_PORT = addr[1]
            self.sendToClient(msg)
            self.printlog(bcolors.OKGREEN, 'you are connected with ' + data['whoami']['nickname'] )



        while self.status:
            try:
                udp_data_raw, addr = self.sock_udp.recvfrom(1024)
                data = eval (udp_data_raw)
                #self.printlog(bcolors.WARNING, data)

                if data['type'] == 'control':
                    if data['action'] == 'connect' and data['direction'] == 'ask':

                        if self.status != self.status_states['busy']:
                            confirm = raw_input(bcolors.WARNING + data['whoami']['nickname'] + " tries to connect with you, do you want? (yes/no) " + bcolors.ENDC).lower()
                            if not re.search(".*yes.*", confirm.strip()):
                                msg = {"type":"control",  "action": "connect", "direction":"answ", "result":"FAIL", 'comment':'The user is not available', 'whoami':self.iam}
                                self.sendToClient(msg, ip = addr[0], port = addr[1])
                                continue
                            connectionApproved(addr, data)

                        else:
                            confirm = raw_input(bcolors.WARNING + data['whoami']['nickname'] + " tries to connect with you, do you want? (yes/no) " + bcolors.ENDC).lower()
                            if not re.search(".*yes.*", confirm.strip()):
                                msg = {"type":"control",  "action": "connect", "direction":"answ", "result":"FAIL", 'comment':'The user is busy in other conversation', 'whoami':self.iam}
                                self.sendToClient(msg, ip = addr[0], port = addr[1])
                            else:
                                self.disconnectFromUser()
                                connectionApproved(addr, data)




                    elif data['action'] == 'connect' and data['direction'] == 'answ':

                        if data['result'] == 'OK':
                            self.printlog(bcolors.OKGREEN, "connection is ready with " + data['whoami']['nickname'])
                            self.status = self.status_states['busy']
                        elif data['result'] == 'FAIL':
                            self.printlog(bcolors.FAIL, data['comment'])
                        else:
                            self.printlog(bcolors.FAIL, 'the answer \"' + str(data) + '\" is not valid')

                    elif data['action'] == 'disconnect':
                        self.status = self.status_states['regitered']
                        self.user_UDP_IP = ''
                        self.user_UDP_PORT = ''
                        self.printlog(bcolors.WARNING, 'the user ' + data['whoami']['nickname'] + ' is disconnected by you')

                    #if data['action'] == 'connect' and data['direction'] == 'answ' and self.status != self.status_states['busy']:
                        #self.status = self.status_states['busy']
                elif data['type'] == 'text':
                    self.printlog (bcolors.ENDC,  bcolors.OKBLUE + '[' + data['whoami']['nickname'] + ']' + bcolors.ENDC + ' - ' + data['msg'])

                    #if self.status == self.status_states['unregitered'] and  addr == self.SERVER_UDP_IP and data == "OK":
                    #        self.status = self.status_state['regitered']
                    #elif self.status == self.status_state['regitered'] and


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





    def thread_commands(self):
        while self.status != self.status_states['quit']:
            if self.status == self.status_states['unregitered']:
               if self.tcpServerSignIn():
                   self.status = self.status_states['regitered']
               else:
                   self.nickname = raw_input('Nickname \'' + self.nickname + '\'  already present.\nPlease, choose a different name: ')


            i, o, e = select.select( [sys.stdin], [], [], 1 )
            #data_string = raw_input("")

            if (i):
                data_string = sys.stdin.readline().strip()
            else:
              continue

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

                elif data_string.lower() == '!groupsList'.lower():
                        self.tcpServerGroupsList()
                    #------------------- UPDATE GROUP
                elif re.search("^!updateGroup.*$".lower(), data_string.lower()):
                        goup = (data_string.strip().split(' '))[1:]
                        goup.append(self.nickname)
                        self.tcpServerGrousUpdate(goup)



                #------------------- COONECT GROUP
                elif re.search("^!connectGroup.*$", data_string):
                    self.tcpServerConnectToGroup()

                #------------------- QUIT
                elif data_string == '!quit':
                    self.disconnectFromUser()
                    self.tcpServerLogout()
                    self.status = self.status_states['quit']

                #------------------- OUT OF RANGE
                else:
                    self.printlog(bcolors.WARNING, "Command not valid")
                    self.printlog(bcolors.OKGREEN, help_message)
            # chat Text
            else:
                if self.status == self.status_states['busy']:
                    msg = ({"type":"text", 'msg': data_string ,'whoami':self.iam})
                    self.sendToClient(msg)
                else:
                    self.printlog(bcolors.FAIL, "Connect yourself with someone before write a message... ")

        self.closeClient()
        self.printlog(bcolors.OKGREEN, 'Client shutdown...')


    def run(self):

        self.thr_rcv = threading.Thread(target=self.thread_receive)
        self.thr_rcv.daemon = True
        self.thr_rcv.start()

        self.thr_cmd = threading.Thread(target=self.thread_commands)
        self.thr_cmd.daemon = True
        self.thr_cmd.start()

        self.thr_rcv.join()
        self.thr_cmd.join()



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
