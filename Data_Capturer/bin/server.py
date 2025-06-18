from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        print("\n====== Incoming Request ======")
        print(f"Path: {self.path}")
        print(f"Headers:\n{self.headers}")
        print("Body:\n", post_data.decode('utf-8'))
        print("================================")

        # Respond to client
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Received")

if __name__ == "__main__":
    server_address = ("", 8080)
    httpd = HTTPServer(server_address, SimpleHandler)
    print("Listening on port 8080...")
    httpd.serve_forever()