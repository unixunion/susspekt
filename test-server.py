import json
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Get the size of the incoming data
        content_length = int(self.headers['Content-Length'])
        # Read the incoming data
        post_data = self.rfile.read(content_length)

        # Try to parse the data as JSON
        try:
            data = json.loads(post_data.decode('utf-8'))
            print("Received POST request with JSON payload:")
            print(json.dumps(data, indent=4))
        except json.JSONDecodeError:
            print("Received POST request with non-JSON payload:")
            print(post_data.decode('utf-8'))

        # Send a simple response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Received POST data")

def run(server_class=HTTPServer, handler_class=RequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting HTTP server on port {port}")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
