import socket
from Crypto.Cipher import AES
import secrets
from getpass import getpass

hote = "localhost" # ip du serveur
port = 12800
clef, vecteur = "863&%L-hPtYf3pV,", ")Q9p_AW4H5vv3v->"
key = AES.new(clef, AES.MODE_CBC, vecteur)

connexion_avec_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connexion_avec_serveur.connect((hote, port))
print("Connection established with the server on the port {}".format(port))

password = False
msg_a_envoyer = b""
msg_recu = ""
while msg_recu.count("fin_connection") == 0:
    msg_recu = ""
    msg_correct = False
    while not msg_correct:
        if password:
            password = False
            msg_a_envoyer = getpass("> ")
        else:
            msg_a_envoyer = input("> ")
        # Gestion du message vide
        if msg_a_envoyer =='':
            msg_a_envoyer = "é"
        if not password:
            msg_a_envoyer = secrets.token_urlsafe(16)+ "fin_crypt" + msg_a_envoyer
        try:
            msg_a_envoyer = key.encrypt(msg_a_envoyer + (16 - len(msg_a_envoyer) % 16) * ' ')
        except:
            print("forbidden characters")
        else:
            msg_correct = True
    # On envoie le message
    connexion_avec_serveur.send(msg_a_envoyer)
    while msg_recu.count("fin_envoi") == 0 and msg_recu.count("fin_connection") == 0:
        # Pour fermer la connection proprement lors d'un crash du serveur
        msg_recu = connexion_avec_serveur.recv(1024)
        if not msg_recu:
            msg_recu = "fin_connection"
        else:
            msg_recu = key.decrypt(msg_recu).strip().decode()
        # On coupe le message aavnt fin_crypt
        if msg_recu.count("fin_crypt") != 0:
            msg_recu = msg_recu.split("fin_crypt", 1)[1]
        # Au message fin_envoi on redonne la main au client
        if msg_recu.count("fin_envoi") != 0:
            print(msg_recu.split("fin_envoi", 1)[0])
        # Au message fin_connection on ferme le socket
        elif msg_recu.count("fin_connection") != 0:
            print(msg_recu.split("fin_connection", 1)[0])
        else:
            print(msg_recu)
        if msg_recu.count("password :") != 0:
            password = True

print("close connection")
connexion_avec_serveur.close()
