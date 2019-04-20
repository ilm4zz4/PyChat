#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Sat Apr  6 16:31:54 2019

@author: mrosellini
"""

import re #regexp
import socket #Setup Socket
import threading
import time
import logging
import datetime
import sys
import json

from thread import start_new_thread

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

help_message="""
Available Commands:
!help --> show the set of the commands
!reset username --> to remove from the register
!list --> List of active clients
!quit --> terminazione
"""

class Server(object):

    def __init__(self, ip , port, loglevel):

        self.register = dict()

        #logging.basicConfig(filename='Server.log',
        #                format='%(asctime)s %(message)s',
        #                datefmt='%m/%d/%Y %I:%M:%S %p',
        #                filemode='w', level=loglevel)

        self.status = True #True app is UP, False app is closing
        self.TCP_IP = ip
        self.TCP_PORT = port
        self.thr_acpt  = ""

        self.tcpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcpSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcpSock.bind((self.TCP_IP, self.TCP_PORT))
        self.tcpSock.listen(10)
        self.tcpSock.settimeout(5) #Not blocked

        self.printlog(bcolors.OKGREEN, 'The server is running on ip: ' + self.TCP_IP + ', port: ' + str(self.TCP_PORT) + '\n' +  help_message)
        print

    def getTimestamp(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    def printlog(self, color, msg):
        print color + self.getTimestamp() + ' - ' + msg + bcolors.ENDC


    def closeServer(self):
        print bcolors.OKGREEN + "Good bye!" + bcolors.ENDC
        self.printlog(bcolors.OKGREEN, 'Good bye!')

        time.sleep (2)
        self.tcpSock.shutdown()
        self.tcpSock.close()

    def thread_client(self,con,addr):

        ip = ""
        port = 0
        nickname = ""
        thread_status = True

        while self.status and thread_status:

############### START INNER FUNCTION  ##########################              

            #The logic to manage the massage received from the client
            def unpuck(data):

                #The client need to notify itself to Server
                if data['action'] == "sigin":
                    if nickname not in self.register:
                        self.register[nickname] = str(ip + ':' + port)
                        self.printlog(bcolors.OKGREEN, nickname + ' got in')
                        msg="{'action':'signin', 'result':'OK'}"
                    else:
                        msg="{'action':'signin', 'result':'ERR', 'comment':'user already present'}"

                #The client need to get the user registered 
                elif data['action'] == "userslist":
                    if len(self.register) > 0:
                        msg = str({'action':'userslist', 'result':'OK', 'userslist':self.register})
                    else:
                        msg = str({'action':'userslist', 'result':'FAIL', 'comment':'user list is empty'})

                #The client ask about a client info
                elif data['action'] == "userconnect":
                    if data['user'] != nickname:
                        try:
                            msg = str({'action':'userconnect', 'result':'OK', 'user':self.register[data['user']]})
                        except KeyError as e:
                            msg = str({'action':'userconnect', 'result':'FAIL', 'comment':'user not exist'})
                    else:
                        msg = str({'action':'userslist', 'result':'FAIL', 'comment':'you con not ask me about yourself!'})

                #The client notify he is in shutdown
                elif data['action'] == "logout":
                    del self.register[nickname]
                    self.printlog(bcolors.OKGREEN, nickname + ' got out')
                    msg="{'action':'logout', 'result':'OK'}"

                else:
                   self.printlog(bcolors.FAIL, "message not valid: " + str(data) )

                return msg

############### END INNER FUNCTION  ##########################              

            try:

                data = con.recv(1024)
                #self.printlog(bcolors.UNDERLINE,data)
                if data:
                    msg=eval(data)
                    ip = msg['whoami']['ip']
                    port = msg ['whoami']['port']
                    nickname = msg['whoami']['nickname']

                    msg = unpuck(msg)
                    self.printlog(bcolors.UNDERLINE, str(msg))
                    con.sendall(msg)

                    #The message is sent, we can terminate the process thread
                    if eval(msg)['action'] == 'logout':
                       thread_status = False


            #The socket is not blocked
            except socket.error as e:

                if str(e) == "[Errno 35] Resource temporarily unavailable":
                   time.sleep(1)
                   #continue
                elif str(e) == '[Errno 54] Connection reset by peer':
                    #self.printlog(bcolors.OKGREEN, nickname + " has gone")
                    thread_status = False
                else:
                   print "Excpetion on self.sock.recvfrom: " + str(e)
                   self.printlog(bcolors.FAIL, 'Excpetion on self.sock.recvfrom: ' + str(e))


            time.sleep(1) #Loop Protection when the client socket interruption is happend

        #self.printlog(bcolors.WARNING, 'The conection with Client: ' + nickname + ',' + ip + ':' + str(port) + ' is terminated')


    #Manage the incoming connection
    def thread_accept(self):

        while self.status:

            try:
                conn, addr = self.tcpSock.accept()
                #self.printlog(bcolors.OKGREEN, 'Connected with ' + addr[0] + ':' + str(addr[1]))
                start_new_thread(self.thread_client ,(conn,addr))

            except socket.timeout:
                pass
            except socket.error as e:

                print str(e)


    #To manage the command in STDIN
    def thread_commands(self):
        while self.status:

            data_string = raw_input("")

            if re.search("^!.*$", data_string):

                if data_string == '!help':
                    print (help_message)

                elif data_string == '!quit':
                    self.printlog(bcolors.WARNING, 'System in shutdown')
                    self.status = False

                elif re.search("^!reset.*$", data_string):
                    tmp = data_string.strip().split(' ')
                    try:
                        del self.register[tmp[1]]
                    except:
                        pass
                elif data_string == '!list':
                    self.printlog(bcolors.OKGREEN , 'List active clients')
                    if not len(self.register):
                        self.printlog(bcolors.OKGREEN, "The list is empty")
                    else:
                        str_tmp = "\n"
                        for i in self.register.iteritems():
                            str_tmp += str(i)+'\n'
                        self.printlog(bcolors.OKGREEN, str_tmp)

                else:
                    print bcolors.WARNING + 'Command not valid' + bcolors.ENDC
                    self.printlog(bcolors.WARNING, '\nCommand not valid\n')
                    self.printlog(bcolors.OKGREEN, help_message)
                    self.printlog(bcolors.OKGREEN, '\n')




        self.printlog(bcolors.WARNING, 'Command terminal is closed')

    #The server is composed at least of two threads:
    # - self.thr_acpt: to manage incoming connections
    # - self.thr_cmd: to manage tha command from STDIN
    def run(self):
        self.thr_acpt = threading.Thread(target=self.thread_accept)
        self.thr_acpt.daemon = True
        self.thr_acpt.start()

        self.thr_cmd = threading.Thread(target=self.thread_commands)
        self.thr_cmd.daemon = True
        self.thr_cmd.start()


        self.thr_acpt.join()
        self.thr_cmd.join()



if __name__ == "__main__":

    ip = ''
    port = 0
    if len(sys.argv) == 3:
        ip = str(sys.argv[1])
        port = int(str(sys.argv[2]))
    else:
        print(bcolors.WARNING + 'Number of aguments not valid\n' + bcolors.ENDC)

        ip = raw_input("Please, give me the ip address: ")
        port = int(raw_input("Please, give me the port number: "))


    print ''
    server = Server(ip, port, logging.DEBUG)
    server.run()
