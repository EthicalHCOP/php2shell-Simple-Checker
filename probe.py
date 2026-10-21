#!/usr/bin/env python3
"""
Probe casero para PHP2Shell (CVE-2026-109618 / CVE-2026-109619).

Uso:  python3 probe.py https://localhost:8090/

Solo mide si la superficie de ataque esta abierta.
NO intenta explotar nada. Correlo solo contra servidores propios.
"""

import sys
import ssl
import uuid
import urllib.request
import urllib.error


def mandar(url, body=None, headers=None):
    """
    Manda una request HTTP (GET si no hay body, POST si hay body).
    Devuelve (codigo_de_respuesta, header_Server).
    Si falla la red, devuelve (None, mensaje_de_error).
    """
    metodo = "POST" if body else "GET"
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=metodo)
    ctx = ssl._create_unverified_context()  # para localhost con cert self-signed
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return r.status, r.headers.get("Server", "")
    except urllib.error.HTTPError as e:
        # 4xx / 5xx vienen como excepcion, pero tienen codigo util
        return e.code, (e.headers.get("Server", "") if e.headers else "")
    except Exception as e:
        return None, f"error: {e}"


def armar_multipart(campos):
    """
    Arma un cuerpo multipart/form-data con la lista de campos recibida.
    Cada campo es una tupla: (nombre, nombre_archivo_o_None, contenido_bytes).
    Devuelve (body_bytes, headers_dict).
    """
    boundary = "----probe" + uuid.uuid4().hex
    partes = []
    for nombre, archivo, contenido in campos:
        disp = f'form-data; name="{nombre}"'
        if archivo is not None:
            disp += f'; filename="{archivo}"'
        cabecera = f"--{boundary}\r\nContent-Disposition: {disp}\r\n\r\n"
        partes.append(cabecera.encode())
        partes.append(contenido)
        partes.append(b"\r\n")
    partes.append(f"--{boundary}--\r\n".encode())
    body = b"".join(partes)
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return body, headers


def main():
    if len(sys.argv) != 2:
        print("Uso: python3 probe.py <url>")
        sys.exit(2)

    url = sys.argv[1]
    if not url.endswith("/"):
        url += "/"

    print(f"Probing {url}\n")

    # ---- 1. GET baseline: ver que servidor hay ----
    codigo, server = mandar(url)
    print(f"[1] GET /                        -> {codigo}  (Server: {server!r})")

    # ---- 2. POST multipart limpio: llega al parser de PHP? ----
    body, headers = armar_multipart([("campo", None, b"hola")])
    codigo_mp, _ = mandar(url, body, headers)
    print(f"[2] POST multipart basico        -> {codigo_mp}")

    # ---- 3. POST con PHP_SESSION_UPLOAD_PROGRESS: trigger de CVE-2026-109619 ----
    body, headers = armar_multipart([
        ("PHP_SESSION_UPLOAD_PROGRESS", None, b"probe"),
        ("archivo", "test.bin", b"A" * 128),
    ])
    headers["Cookie"] = "PHPSESSID=probe0000000000000000000000"
    codigo_up, _ = mandar(url, body, headers)
    print(f"[3] POST con upload-progress     -> {codigo_up}")

    # ---- 4. Probes de tamanio: cuanto deja pasar? ----
    print("[4] Tamanios de subida:")
    tamanios = {}
    for mb in [1, 8, 32]:
        body, headers = armar_multipart([
            ("archivo", "blob.bin", b"A" * (mb * 1024 * 1024)),
        ])
        codigo, _ = mandar(url, body, headers)
        tamanios[mb] = codigo
        print(f"      {mb:>2} MB                       -> {codigo}")

    # ---- Veredicto ----
    print()
    if codigo_mp is None:
        print("VEREDICTO: no concluyente (error de red)")
    elif codigo_mp == 403:
        print("VEREDICTO: mitigado — el edge bloquea POSTs multipart (403)")
    elif codigo_up == 403:
        print("VEREDICTO: parcialmente mitigado — upload-progress bloqueado en edge")
    elif codigo_mp and codigo_up:
        print("VEREDICTO: EXPUESTO")
        print("  - PHP parsea cuerpos multipart de atacantes anonimos")
        print("  - el campo PHP_SESSION_UPLOAD_PROGRESS pasa sin bloqueo")
        print("  - CVE-2026-109618 / 109619 son alcanzables si el PHP no esta parcheado")
        print("  - verificar version con: php -v")
    else:
        print("VEREDICTO: no concluyente")


if __name__ == "__main__":
    main()
