#!/usr/bin/env python3
"""
tests/test_target_server.py

Servidor HTTP mínimo (sin dependencias) con endpoints de comportamiento
CONOCIDO Y CONTROLADO, para poder afirmar con certeza si un hallazgo del
escáner es un verdadero positivo, un falso positivo o un falso negativo.

Uso: python3 test_target_server.py <puerto> <perfil>
  perfil = secure   -> cabeceras de seguridad correctas, sin vulns
  perfil = insecure -> sin cabeceras de seguridad, con vulns conocidas
  perfil = slow_safe -> servidor lento (3.5s) SIN SQL de por medio, para
                        probar falsos positivos del check de SQLi ciego
"""
import html
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PROFILE = sys.argv[2] if len(sys.argv) > 2 else "insecure"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silenciar logs de acceso, solo nos interesa el resultado

    def _send(self, code, body, headers=None, content_type="text/html; charset=utf-8"):
        body_bytes = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        if PROFILE == "secure":
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        if self._send_body:
            self.wfile.write(body_bytes)

    def do_HEAD(self):
        # BaseHTTPRequestHandler no implementa HEAD por defecto (devolvería
        # 501), lo que rompería el módulo de headers del escáner (usa -I).
        # Lo implementamos igual que GET pero sin cuerpo, como haría
        # cualquier servidor real bien configurado.
        self._handle(send_body=False)

    def do_GET(self):
        self._handle(send_body=True)

    def _handle(self, send_body=True):
        self._send_body = send_body
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        q = qs.get("q", [""])[0]
        pid = qs.get("id", [""])[0]

        if PROFILE == "slow_safe":
            # Servidor deliberadamente lento SIEMPRE, sin SQL real de por
            # medio: sirve para comprobar si el check de "blind timing SQLi"
            # del motor da falso positivo ante latencia genuina no maliciosa.
            time.sleep(3.5)
            self._send(200, "<html><body>respuesta lenta pero segura</body></html>")
            return

        if path == "/" or path == "":
            self._send(200, "<html><body><h1>Home</h1><a href='/buscar?q=test'>buscar</a></body></html>")
            return

        if path == "/buscar":
            if PROFILE == "insecure":
                # VULNERABLE de verdad: si hay una comilla, se rompe la
                # "query" simulada y se refleja un error SQL real de MySQL.
                if "'" in q or '"' in q:
                    self._send(200,
                        f"<html><body>Error: You have an error in your SQL syntax; "
                        f"check the manual that corresponds to your MySQL server version "
                        f"for the right syntax to use near '{html.escape(q)}'</body></html>")
                else:
                    self._send(200, f"<html><body>Resultados para: {html.escape(q)}</body></html>")
            else:
                # SEGURO de verdad: consulta parametrizada simulada, nunca
                # refleja errores de motor SQL pase lo que pase en q.
                self._send(200, f"<html><body>Resultados para: {html.escape(q)}</body></html>")
            return

        if path == "/perfil":
            if PROFILE == "insecure":
                # XSS reflejado real: el parámetro se vuelca sin escapar.
                self._send(200, f"<html><body><h1>Perfil de {q}</h1></body></html>")
            else:
                # Seguro: se escapa correctamente.
                self._send(200, f"<html><body><h1>Perfil de {html.escape(q)}</h1></body></html>")
            return

        if path == "/login":
            user = q or qs.get("user", [""])[0]
            if PROFILE == "insecure":
                # Vulnerable a boolean-blind de verdad: NUNCA refleja
                # errores SQL (no lo pillaría el error-based antiguo),
                # pero el contenido cambia según si la condición
                # inyectada es verdadera o falsa — como un login real
                # con concatenación de SQL sin parametrizar.
                if "' OR '1'='1" in user or "OR 1=1" in user:
                    self._send(200, "<html><body>" + ("Bienvenido al panel. " * 40) + "</body></html>")
                else:
                    self._send(200, "<html><body>Usuario o contraseña incorrectos.</body></html>")
            else:
                # Seguro: siempre la misma respuesta, pase lo que pase.
                self._send(200, "<html><body>Usuario o contraseña incorrectos.</body></html>")
            return

        if path == "/reporte":
            pid_val = pid or qs.get("id", [""])[0]
            if PROFILE == "insecure":
                # Vulnerable a UNION-based: simulamos que la consulta
                # real subyacente tiene 3 columnas. ORDER BY 4 o más
                # rompe la consulta -> error SQL real de MySQL.
                m = re.search(r"ORDER BY (\d+)", pid_val, re.IGNORECASE)
                if m and int(m.group(1)) > 3:
                    self._send(200, "<html><body>Error: Unknown column '4' in 'order clause' - "
                                     "You have an error in your SQL syntax</body></html>")
                else:
                    self._send(200, "<html><body>Informe #1234</body></html>")
            else:
                self._send(200, "<html><body>Informe #1234</body></html>")
            return

        if path == "/dinamico":
            # Página "ruidosa" de forma LEGÍTIMA (contenido no determinista
            # en cada carga, como un banner rotativo), SIN ninguna vulnerabilidad
            # SQL real. Sirve para comprobar que el check boolean-based no
            # dispara un falso positivo por simple variabilidad de contenido.
            import random
            filler = "X" * random.randint(0, 500)
            self._send(200, f"<html><body>Contenido variable: {filler}</body></html>")
            return

        if path == "/.env":
            if PROFILE == "insecure":
                self._send(200, "DB_PASSWORD=supersecreto123\nAPI_KEY=abc123")
            else:
                self._send(404, "Not Found")
            return

        if path == "/admin":
            if PROFILE == "insecure":
                self._send(200, "<html><body>Panel de administración</body></html>")
            else:
                self._send(404, "Not Found")
            return

        # 404 genérico para todo lo demás (incluye rutas de otros módulos
        # como /wp-admin, /.git/config, etc. que no hemos modelado aquí)
        self._send(404, "<html><body>404 Not Found</body></html>")


if __name__ == "__main__":
    port = int(sys.argv[1])
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Servidor de pruebas '{PROFILE}' escuchando en 127.0.0.1:{port}", flush=True)
    server.serve_forever()
