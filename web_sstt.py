# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors  # https://docs.python.org/3/library/selectors.html
import select
import types  # Para definir el tipo de datos data
import argparse  # Leer parametros de ejecución
import os  # Obtener ruta y extension
from datetime import datetime, timedelta  # Fechas de los mensajes HTTP
import time  # Timeout conexión
import sys  # sys.exit
import re  # Analizador sintáctico
import logging  # Para imprimir logs


BUFSIZE = 8192  # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 36  # Timout para la conexión persistente
MAX_ACCESOS_CONEXION = 5
MAX_ACCESOS_COOKIES = 10
MAX_ACCESOS_SERVER = 10

# Extensiones admitidas (extension, name in HTTP)
filetypes = {
    "gif": "image/gif",
    "jpg": "image/jpg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "ico": "image/ico",
    "htm": "text/htm",
    "html": "text/html",
    "css": "text/css",
    "js": "text/js",
}

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger()


def enviar_mensaje(cs, data):
    """Esta función envía datos (data) a través del socket cs
    Devuelve el número de bytes enviados.
    """
    return cs.send(data)


def recibir_mensaje(cs):
    """Esta función recibe datos a través del socket cs
    Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    return cs.recv(BUFSIZE)


def cerrar_conexion(cs):
    """Esta función cierra una conexión activa."""
    cs.close()


def process_cookies(headers, cookie_counter_7883):
    """Esta función procesa la cookie cookie_counter
    1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
    2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
    3. Si no se encuentra cookie_counter , se devuelve 1
    4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
    5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    for x in headers:
        cookie = re.match("Cookie:\s", x)
        if cookie:
            data = x.split(": ")[1].strip()
            existe = re.match("cookie_counter_7883=([0-9]+)", data)
            if existe:
                cookie_counter_7883 = int(existe.groups()[0])
                if cookie_counter_7883 == MAX_ACCESOS_COOKIES:
                    return MAX_ACCESOS_COOKIES
                return cookie_counter_7883 + 1
            break
    return 1

def enviar_error(cs, file, error):
    extension = os.path.basename(file).split(".")[1]
    tamaño = os.stat(file).st_size
    mensaje = (
        "HTTP/1.1 "
        + error
        + "\r\nDate: "
        + datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        + "\r\nServer: Apache/2.0.52 (CentOS)\r\nContent-Type: "
        + filetypes[extension]
        + "\r\nContent-Length: "
        + str(tamaño)
        + "\r\n\r\n"
    )
    f = open(file, "rb")
    buffer = f.read(BUFSIZE - len(mensaje)).decode()
    mensaje += buffer
    enviar_mensaje(cs, mensaje.encode())
    buffer = f.read(BUFSIZE).decode()
    while len(buffer):
        mensaje = buffer
        enviar_mensaje(cs, mensaje.encode())
        buffer = f.read(BUFSIZE).decode()
    f.close()

def process_web_request(cs, webroot):
    # Procesamiento principal de los mensajes recibidos.
    # Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)
    # Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()
    print("Se ha conectado un cliente\n")
    inputs = [cs]
    outputs = []
    num_accesos = 1
    cookie_counter_XXYY = 1
    while num_accesos < MAX_ACCESOS_SERVER:
        # Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
        # sin recibir ningún mensaje o hay datos. Se utiliza select.select
        readable, writable, exceptional = select.select(
            inputs, outputs, inputs, TIMEOUT_CONNECTION
        )
        if not readable:
            cerrar_conexion(cs)
            print("Salta timeout\n")
            return

        # Si no es por timeout y hay datos en el socket cs.
        else:
            # Leer los datos con recv.
            data = recibir_mensaje(cs)
            if not len(data):
                cerrar_conexion(cs)
                return
            # Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
            data = data.decode()
            linea = re.match("([A-Za-z]+)\s\/(.*[^\s])?\sHTTP\/([0-9|\.]*)\\r\\n", data)
            if linea:
                # Comprobar si la versión de HTTP es 1.1
                groups = linea.groups()
                if groups[2] != "1.1":
                    # devolver error
                    ruta = webroot + "/error505.html"
                    enviar_error(cs, ruta, "505 HTTP Version Not Supported")
                    return
                
                    
                # Comprobar si es un método GET. Si no devolver un error Error 405 "Method Not Allowed".
                if groups[0] == "POST":
                    correo = re.search("email=([^% \t\r\n]+%40um\.es)$", data)
                    if correo:
                        respuesta = (
                            "HTTP/1.1 200 OK\r\nDate: "
                            + datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
                            + "\r\nServer: Apache/2.0.52 (CentOS)\r\nConnection: Keep-Alive\r\nKeep-Alive: timeout="
                            + str(TIMEOUT_CONNECTION)
                            + ", max="
                            + str(MAX_ACCESOS_SERVER)
                            + "\r\nContent-Length: "
                            + str(os.stat(webroot + "/correo.html").st_size)
                            + "\r\nContent-Type: "
                            + filetypes["html"]
                            + "\r\n\r\n"
                        )
                        f = open(webroot + "/correo.html", "rb")
                        buffer = f.read(BUFSIZE - len(respuesta)).decode()
                        respuesta += buffer
                        enviar_mensaje(cs, respuesta.encode())
                        while len(buffer):
                            respuesta = buffer
                            buffer = f.read(BUFSIZE).decode()
                            respuesta = respuesta.encode()
                            enviar_mensaje(cs, respuesta)
                        f.close()
                    else:
                        ruta = webroot + "/error401.html"
                        enviar_error(cs, ruta, "401 Unauthorized")
                        
                elif groups[0] == "GET":
                    # Devuelve una lista con los atributos de las cabeceras.
                    # [A-Z]([A-Za-z]|-)*:(.*?)\\r\\n
                    lista = re.findall(r"([A-Z][A-Za-z|-]*:.*?\r\n)", data)
                    for x in lista:
                        print(x)
                    # Leer URL y eliminar parámetros si los hubiera
                    # Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
                    if groups[1] != None:
                        ruta = "/" + groups[1].split("?")[0]
                    else:
                        ruta = "/index.html"

                    # Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                    ruta = webroot + ruta
                    # Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
                    if not os.path.isfile(ruta):
                        # TODO mandar imagen 404 error
                        ruta = webroot + "/error404.html"
                        enviar_error(cs, ruta, "404 Not found")
                        continue
                    # Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                    # el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                    # Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                    cookie = ""
                    if ruta == webroot + "/index.html":
                        cookie_counter_XXYY = process_cookies(lista, cookie_counter_XXYY)
                        if cookie_counter_XXYY == MAX_ACCESOS_COOKIES:
                            ruta = webroot + "/error403.html"
                            enviar_error(cs, ruta, "403 Forbidden")
                            continue
                        else:
                            cookie = (
                                "Set-Cookie: cookie_counter_XXYY= " + str(cookie_counter_XXYY) + "; Max-Age=120\r\n"
                            )
                    # Obtener el tamaño del recurso en bytes.
                    tamaño = os.stat(ruta).st_size
                    # Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
                    extension = os.path.basename(ruta).split(".")[1]
                    # Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
                    # las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
                    # Content-Length y Content-Type.
                    
                    respuesta = (
                        "HTTP/1.1 200 OK\r\nDate: "
                        + datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
                        + "\r\nServer: Apache/2.0.52 (CentOS)\r\nConnection: Keep-Alive\r\nKeep-Alive: timeout="
                        + str(TIMEOUT_CONNECTION)
                        + ", max="
                        + str(MAX_ACCESOS_SERVER)
                        + "\r\n"
                        + cookie
                        + "Content-Length: "
                        + str(tamaño)
                    )

                    # Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
                    # Se abre el fichero en modo lectura y modo binario
                    # Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                    # Cuando ya no hay más información para leer, se corta el bucle
                    f = open(ruta, "rb")
                    if (
                        extension == "html"
                        or extension == "css"
                        or extension == "js"
                        or extension == "htm"
                    ):
                        respuesta += "\r\nContent-Type: " + filetypes[extension] + "\r\n\r\n"
                        buffer = f.read(BUFSIZE - len(respuesta)).decode()
                        respuesta += buffer
                        enviar_mensaje(cs, respuesta.encode())
                        buffer = f.read(BUFSIZE).decode()
                        while len(buffer):
                            respuesta = buffer
                            enviar_mensaje(cs, respuesta.encode())
                            buffer = f.read(BUFSIZE).decode()
                        f.close()
                        print("Archivo " + ruta + " enviado correctamente\n")
                    elif (
                        extension == "jpg"
                        or extension == "jpeg"
                        or extension == "gif"
                        or extension == "png"
                        or extension == "ico"
                    ):
                        respuesta += "\r\nContent-Type: " + filetypes[extension] + "\r\n\r\n"
                        respuesta = respuesta.encode()
                        buffer = f.read(BUFSIZE - len(respuesta))
                        respuesta += buffer
                        enviar_mensaje(cs, respuesta)
                        buffer = f.read(BUFSIZE)
                        while len(buffer):
                            respuesta = buffer
                            enviar_mensaje(cs, respuesta)
                            buffer = f.read(BUFSIZE)
                        f.close()
                        error = re.search("error", ruta)
                        if error:
                            print("Cerrar conexion, ha surgido un error controlado\n")
                            return
                        print("Archivo " + ruta + " enviado correctamente\n")
                    else:
                        ruta = webroot + "/error415.html"
                        enviar_error(cs, ruta, "415 Unsupported Media Type")
                else:
                    # devolver error
                    ruta = webroot + "/error405.html"
                    enviar_error(cs, ruta, "405 Method Not Allowed")
                    print("Cerrar conexion, metodo no reconocido\n")
                    return
            else:
                ruta = webroot + "/error400.html"
                enviar_error(cs, ruta, "400 Bad Request")
                print("Cerrar conexion, peticion mal formada\n")
                return
        num_accesos = num_accesos + 1
        
        # Si es por timeout, se cierra el socket tras el período de persistencia.
        # NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
    print("Conexion cerrada por maximo de accesos\n")
    cerrar_conexion(cs)


def main():
    """Función principal del servidor"""

    try:
        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-p", "--port", help="Puerto del servidor", type=int, required=True
        )
        parser.add_argument(
            "-ip", "--host", help="Dirección IP del servidor o localhost", required=True
        )
        parser.add_argument(
            "-wb",
            "--webroot",
            help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)",
        )
        parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="Incluir mensajes de depuración en la salida",
        )
        args = parser.parse_args()

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info(
            "Enabling server in address {} and port {}.".format(args.host, args.port)
        )

        logger.info("Serving files from {}".format(args.webroot))

        # Crea un socket TCP (SOCK_STREAM)
        socketPadre = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0)

        # Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
        socketPadre.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)

        # Vinculamos el socket a una IP y puerto elegidos
        socketPadre.bind((args.host, args.port))

        # Escucha conexiones entrantes
        socketPadre.listen(MAX_ACCESOS_CONEXION)

        # Bucle infinito para mantener el servidor activo indefinidamente
        while True:
            # Aceptamos la conexión
            socketHijo, address = socketPadre.accept()
            # Creamos un proceso hijo
            pid = os.fork()
            # Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()
            if pid == 0:
                cerrar_conexion(socketPadre)
                process_web_request(socketHijo, args.webroot)
                break

            # Si es el proceso padre cerrar el socket que gestiona el hijo.
            else:
                cerrar_conexion(socketHijo)

    except KeyboardInterrupt:
        True


if __name__ == "__main__":
    main()


# dudas -> extensiones en 174, keep alive 167, POST, num accesos 86