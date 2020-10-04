#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import select
import sqlite3
import secrets
import time
from datetime import datetime
from time import strftime
from Crypto.Cipher import AES
import hashlib

#Affiche un message d'erreur sur le serveur, enregistre ce message dans un fichier log avec l'ip du client et la date et heure de connection
def message_erreur(client, message, envoie, recu): #client le socket du client, message le message d'erreur à enregistrer, envoie le booléen pour savoir si il faut envoyer le message au client, recu le messsage reçu venant du client
    erreur = datetime.now().strftime("%d-%m-%Y %H:%M:%S")+" -- "+str(client).split("raddr=")[1].split(">")[0]+": "+message+" - "+recu+"\n"
    print(erreur)
    with open('log.txt', 'a') as log:
        log.write(erreur)
    if envoie:
        fin_message(client, message)
    close_conn(client)

#Ferme la connection connection avec le socket client et le supprime de toute les listes dont il a pu faire parti
def close_conn(client):
    client.close()
    if client in clients_connectes:
        clients_connectes.remove(client)
    elif client in admins_connectes:
        admins_connectes.remove(client)
    elif client in bots_connectes:
        bots_connectes.remove(client)
    all_key.remove(get_key(client))
    all_sockets.remove(client)

#Retourne la clé de cryptage du client en fonction de la socket
def get_key(client):
    return all_key[all_sockets.index(client)]

#Encrypte le message avant de l'envoyer au client
def message_t(client, message):
    key = get_key(client)
    message = secrets.token_urlsafe(16)+ "fin_crypt" + message
    message = key.encrypt(message + (16 - len(message) % 16) * ' ')
    client.send(message)

def envoie_message(client, message):
    message = message + "fin_envoi"
    message_t(client, message)

def fin_message(client, message):
    message = message + "fin_connection"
    message_t(client, message)

def recv_message(client):
    key = get_key(client)
    msg_recu = client.recv(1024)
    #msg_recu est vide cela signifie que le client a crash
    if not msg_recu:
        message_erreur(client, "broken connection", False, "")
    else:
        try:
            msg_recu = key.decrypt(msg_recu).strip().decode()
        except:
            message_erreur(client, "unreadable message", True, "")
        else:
            if msg_recu.count("fin_crypt") != 0:
                msg_recu = msg_recu.split("fin_crypt", 1)[1]
    return msg_recu

clef, vecteur = "863&%L-hPtYf3pV,", ")Q9p_AW4H5vv3v->"
hote = ''
port = 12800
mdp = "ed8ee02b26d6d9d74dfbba583328860f000c0adf0444bc41cf83187186f43e463095f00c24416dabd9dcb469bbaeee1cac1913d032bbb421b3706e185306b7ee"

consql = sqlite3.connect('connection.db')

connexion_principale = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connexion_principale.bind((hote, port))
connexion_principale.listen(5)
print("The server is now listening on the port {}".format(port))


messadmin = "Help: \n"
messadmin += "- /help\n"
messadmin += "    - GET: list all commands\n"
messadmin += "- /host\n"
messadmin += "    - GET: list all hosts\n"
messadmin += "- /host/{name}\n"
messadmin += "    - GET: list of tokens for the host\n"
messadmin += "    - POST: create a new token for the host\n"
messadmin += "    - DELETE: remove a host (and all its tokens)\n"
messadmin += "- /host/{name}/{token}\n"
messadmin += "    - DELETE remove a token for the host\n"
messadmin += "- /log\n"
messadmin += "    - GET: show logs\n"
messadmin += "    - DELETE: Remove logs\n"
messadmin += "- /stop\n"
messadmin += "    - POST: stop the server\n"
messadmin += "- /exit\n"
messadmin += "    - POST: disconnect\n"

i = 0
serveur_lance = True
all_key = []
all_sockets = []
clients_connectes = []
bots_connectes = []
admins_connectes = []
while serveur_lance:
    # On va vérifier que de nouveaux clients ne demandent pas à se connecter
    # Pour cela, on écoute la connexion_principale en lecture
    # On attend maximum 50ms
    connexions_demandees, wlist, xlist = select.select([connexion_principale], [], [], 0.05)

    for connexion in connexions_demandees:
        connexion_avec_client, infos_connexion = connexion.accept()
        # On ajoute le socket connecté à la liste des clients
        clients_connectes.append(connexion_avec_client)
        # On ajoute le socket a un duo de liste socket/clé de cryptage
        all_sockets.append(connexion_avec_client)
        all_key.append(AES.new(clef, AES.MODE_CBC, vecteur))
    # Maintenant, on écoute les listes des clients connectés puis des bots puis des admins
    # Les sockets renvoyés par select sont ceux devant être lus (recv)
    # On attend là encore 50ms maximum
    # On enferme l'appel à select.select dans un bloc try
    # En effet, si la liste de sockets est vide, une exception peut être levée
    clients_premier_message = []
    bots_message = []
    admins_message = []
    # Bloc de code pour le premier message
    try:
        clients_premier_message, wlist, xlist = select.select(clients_connectes, [], [], 0.05)
    except select.error:
        pass
    else:
        for client in clients_premier_message:
            # Pour éviter de crash le serveur lorsque le client crash
            msg_recu = recv_message(client)
            if msg_recu:
                print("Received : {}".format(msg_recu))
                # Le client indique si il est un admin ou un bot
                # Sinon un message d'erreur est généré et enregistré dans le fichier log.txt
                if msg_recu != "admin" and  msg_recu != "bot":
                    message_erreur(client, "unknown user", True, msg_recu)
                else:
                    # Le socket et entré dans le tableau des admins
                    if msg_recu == "admin":
                        envoie_message(client, "password :")
                        msg_recu = recv_message(client)
                        if msg_recu:
                            if hashlib.sha512(msg_recu.encode()).hexdigest() == mdp:
                                envoie_message(client, messadmin)
                                admins_connectes.append(client)
                            else:
                                message_erreur(client, "incorrect password", True, "")

                    else:
                        # Le socket et entré dans le tableau des bots
                        bots_connectes.append(client)
                        envoie_message(client, "received")
                    # On supprime le socket de la liste des clients connectés
                    if client in clients_connectes:
                        clients_connectes.remove(client)

    # Bloc de code pour les bots
    try:
        bots_message, wlist, xlist = select.select(bots_connectes, [], [], 0.05)
    except select.error:
        pass
    else:
        for bot in bots_message:
            # Pour éviter de crash le serveur lorsque le client crash
            msg_recu = recv_message(bot)
            if msg_recu:
                print("Received : {}".format(msg_recu))
                try:
                    # On attend un message de type "GET /ip/{hostname}/{ip}?token=XXX" sinon on lève une exception
                    getinutile, ipinutile, hostname, reste = msg_recu.split("/", 3)
                    ip, reste = reste.split("?", 1)
                    tokeninutile, token = reste.split("=", 1)
                except:
                    message_erreur(client, "bot format error", True, msg_recu)
                else:
                    cur = consql.cursor()
                    # Syntaxe pour éviter les injections SQL
                    cur.execute('select token from identifiants where token = ? and host = ?', (token, hostname))
                    row = cur.fetchone()
                    tokenPresent = False
                    if row == None:
                        message_erreur(client, "unknown token", True, msg_recu)
                    else:
                        # TODO accès DNS google
                        envoie_message(bot, "done")
                        #fin_message(bot, "done")
                        #close_conn(bot) A VOIR: soit garder les bots connectés soit les connecter à chaque changement de DNS. On part sur la première option
                    cur.close()



    # Bloc de code pour les admins
    try:
        admins_message, wlist, xlist = select.select(admins_connectes, [], [], 0.05)
    except select.error:
        pass
    else:

        # On attend des commandes de type:
        # - /help
        #     - GET: list all commands
        # - /host
        #     - GET: list all hosts
        # - /host/{name}
        #     - GET: list of tokens for the host
        #     - POST: create a new token for the host
        #     - DELETE: remove a host (and all its tokens)
        # - /host/{name}/{token}
        #     - DELETE remove a token for the host
        # - /log
        #     - GET: show logs
        #     - DELETE: Remove logs
        # - /stop
        #     - POST: stop the server
        # - /exit
        #     - POST: disconnect

        for admin in admins_message:
            # Pour éviter de crash le serveur lorsque le client crash
            msg_recu = recv_message(admin)
            if msg_recu:
                print("Received : {}".format(msg_recu))
                # On sépare les commandes par le nombre de slash puis par l'action à effectué (GET, POST, DELETE)
                typecommande = msg_recu.count("/")
                if typecommande == 1:
                    action, commande = msg_recu.split("/", 1)
                    if action == "GET ":
                        if commande == "help":
                            envoie_message(admin, messadmin)
                        elif commande == "host":
                            cur = consql.cursor()
                            cur.execute('select host from identifiants')
                            tuples = cur.fetchall()
                            msg = ""
                            for tuple in tuples:
                                msg += str(tuple[0]) + "\n"
                            cur.close()
                            envoie_message(admin, msg)
                        elif commande == "log":
                            with open('log.txt', 'r') as log:
                                envoie_message(admin, log.read())
                        else:
                            envoie_message(admin, "incorrect order\n")
                    elif action == "POST ":
                        if commande == "stop":
                            serveur_lance = False
                        elif commande == "exit":
                            fin_message(admin, "")
                            close_conn(admin)
                        else:
                            envoie_message(admin, "incorrect order\n")
                    elif action == "DELETE ":
                        if commande == "log":
                            with open('log.txt', 'w') as log:
                                log.write(datetime.now().strftime("%d-%m-%Y %H:%M:%S")+" -- "+str(str(admin).split("raddr=")[1].split(">")[0])+": deleted logs \n")
                                envoie_message(admin, "deleted logs")
                        else:
                            envoie_message(admin, "incorrect order\n")
                    else:
                        envoie_message(admin, "incorrect order\n")
                elif typecommande == 2:
                    action, commande, host = msg_recu.split("/", 2)
                    if commande == "host":
                        if action == "GET ":
                            cur = consql.cursor()
                            cur.execute('select token from identifiants where host = ?', (host,))
                            tuples = cur.fetchall()
                            msg = ""
                            for tuple in tuples:
                                msg += str(tuple[0]) + "\n\n"
                            cur.close()
                            if msg == "":
                                msg = "Unknown host name\n"
                            envoie_message(admin, msg)
                        elif action == "POST ":
                            cur = consql.cursor()
                            cur.execute("insert into identifiants (token, host) values(?, ?)", (secrets.token_urlsafe(200), host))
                            consql.commit()
                            cur.close()
                            envoie_message(admin, "done")
                        elif action == "DELETE ":
                            cur = consql.cursor()
                            aux=cur.execute("delete from identifiants where host = ?", (host,))
                            consql.commit()
                            cur.close()
                            envoie_message(admin, "done")
                        else:
                            envoie_message(admin, "incorrect order\n")
                    else:
                        envoie_message(admin, "incorrect order\n")
                elif typecommande == 3:
                    action, commande, host, token = msg_recu.split("/", 3)
                    if action == "DELETE " and commande == "host":
                        cur = consql.cursor()
                        aux=cur.execute("delete from identifiants where host = ? and token = ?", (host,token))
                        consql.commit()
                        cur.close()
                        envoie_message(admin, "done")

                    else:
                        envoie_message(admin, "incorrect order\n")
                else:
                    envoie_message(admin, "incorrect order\n")
# On ferme la connection de tout les clients
print("Closing connections")
for admin in admins_connectes:
    fin_message(admin, "")
    close_conn(admin)
for bot in bots_connectes:
    fin_message(bot, "")
    close_conn(bot)
for client in clients_connectes:
    fin_message(client, "")
    close_conn(client)

connexion_principale.close()
consql.close()
