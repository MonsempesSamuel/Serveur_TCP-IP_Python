import socket
from Crypto.Cipher import AES
import secrets

def message_t(client, message):
    message = secrets.token_urlsafe(16)+ "fin_crypt" + message
    message = key.encrypt(message + (16 - len(message) % 16) * ' ')
    client.send(message)

def recv_message(client):
    msg_recu = client.recv(1024)
    msg_recu = key.decrypt(msg_recu).strip().decode()
    msg_recu = msg_recu.split("fin_crypt", 1)[1]
    return msg_recu

hote = "localhost"  # ip du serveur
port = 12800
clef, vecteur = "863&%L-hPtYf3pV,", ")Q9p_AW4H5vv3v->"
key = AES.new(clef, AES.MODE_CBC, vecteur)
ip = socket.gethostbyname(socket.gethostname())
hostname = socket.gethostbyaddr(ip)[0]
token = "xngmaKIAXWd2hVGt1uERLZ1yKvxipWJozDoATwawe-qBN1weZpEjFiigys7HzpHRdwOwFBIX1zrECenD7A9iUtERVr7ISZFF27cAIVK0Nf4ONC5Yh2IvvChKnlgRLSNoUi9XH7OfZdqA1_vB0ihzLByCNIaznHBpVcSoLXfTQB70E8CSbYaDh7vuv7rZvnsg9VHN8rMyBZVnDOrxRgaCdvgyKlcAuDFUTrSELynE9mGRpkug2g1vfOHE-i2cSZvwtXXLiikdEi0"
connexion_avec_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connexion_avec_serveur.connect((hote, port))
print("Connection established with the server on the port {}".format(port))

message_t(connexion_avec_serveur, "bot")
msg_recu = recv_message(connexion_avec_serveur)
while msg_recu.count("fin_connection") == 0:
    while socket.gethostbyname(socket.gethostname()) == ip:
        pass
    message_t(connexion_avec_serveur, "GET /ip/"+hostname+"/"+ip+"?token="+token)
    ip = socket.gethostbyname(socket.gethostname())
    msg_recu = recv_message(connexion_avec_serveur)
print("close connection")
connexion_avec_serveur.close()
