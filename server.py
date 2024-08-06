import http.server
import socketserver
import netfilter_manipulation

PORT = 8002

class MyHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ip = client_ip = self.client_address[0]
        netfilter_manipulation.request_access(ip)
        # Отправляем ответ "Hello, World!" в браузер
        self.send_response(200)
        self.wfile.write(b"Ok!")

# Создаем сервер
netfilter_manipulation.init()
with socketserver.TCPServer(("", PORT), MyHttpRequestHandler) as httpd:
    print("Serving on port", PORT)
    httpd.serve_forever()
