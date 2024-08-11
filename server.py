import http.server
import threading
import signal
import socketserver
import netfilter_manipulation

PORT = netfilter_manipulation.REQUEST_PORT
SECRET_URL = '1jkzxz978uhi1z8'

class SigkillHandler:
  kill_now = False
  def __init__(self):
    signal.signal(signal.SIGINT, netfilter_manipulation.final)
    signal.signal(signal.SIGTERM, netfilter_manipulation.final)

  def exit_gracefully(self, signum, frame):
    self.kill_now = True

class MyHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != f'/{SECRET_URL}':
            self.wfile.write(b"404 Not Found")
            return

        ip = client_ip = self.client_address[0]
        threading.Thread(target=netfilter_manipulation.request_access, args=(ip,)).run()
        # netfilter_manipulation.request_access(ip)
        self.send_response(200)
        self.wfile.write(b"Ok!")

if __name__ == '__main__':
    killer = SigkillHandler()
    while not killer.kill_now:

        netfilter_manipulation.init()
        with socketserver.TCPServer(("", PORT), MyHttpRequestHandler) as httpd:
            print("Serving on port", PORT)
            httpd.serve_forever()
