import pydivert
import threading
import requests
import json
import uuid
from datetime import datetime
import re
import argparse

def send_to_api(api_key, data, is_request):
    payload = {
        'api_key': api_key,
        'the_request' if is_request else 'the_response': data
    }
   
    try:
        response = requests.post(
            'https://backend-new.apisecurityengine.com/api/v1/mirroredScans/sendRequestInfo',
            json=payload
        )
        response.raise_for_status()
        print('Information sent successfully to API')
    except requests.exceptions.RequestException as e:
        print(f'Error sending information to API: {e}')

def parse_http_data(data, host, port):
    # Find the start of the HTTP data
    http_start = re.search(r'(GET|POST|PUT|DELETE|HTTP/[\d.]+)', data)
    if not http_start:
        print("No HTTP data found")
        return None

    http_data = data[http_start.start():]
    lines = http_data.split('\r\n')
    first_line = lines[0].strip()
    print(f"First line: {first_line}")

    is_request = first_line.startswith(('GET', 'POST', 'PUT', 'DELETE'))
    headers = {}
    body = ""
    parsing_body = False

    for line in lines[1:]:
        if not line.strip():
            parsing_body = True
            continue
        if not parsing_body:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        else:
            body += line + '\r\n'

    if is_request:
        print(first_line)
        method, path, _ = first_line.split(' ', 2)
       
        if host:
            if port:
                full_url = f"http://{host}:{port}{path}"
            else:
                full_url = f"http://{host}{path}"
        else:
            full_url = path

        return {
            'requestId': str(uuid.uuid4()),
            'method': method,
            'url': full_url,
            'headers': headers,
            'body': body.strip(),
            'timestamp': datetime.now().isoformat(),
            'projectType': 'Python'
        }
    else:
        status_line = first_line.split(' ', 2)
        try:
            status_code = int(status_line[1]) if len(status_line) > 1 else None
        except ValueError:
            print(f"Invalid status code: {status_line}")
            status_code = None
        return {
            'requestId': str(uuid.uuid4()),
            'statusCode': status_code,
            'headers': headers,
            'body': body.strip(),
            'timestamp': datetime.now().isoformat()
        }

def capture_http_traffic(api_key, host, port):
    def capture_thread():
        with pydivert.WinDivert(f"tcp.DstPort == {port} or tcp.SrcPort == {port}") as w:
            for packet in w:
                if packet.tcp.payload:
                    data = packet.tcp.payload.decode('utf-8', errors='ignore')
                    print(data)
                    parsed_data = parse_http_data(data, host, port)
                    if parsed_data:
                        print("Parsed data:")
                        print(parsed_data)
                        send_to_api(api_key, parsed_data, 'method' in parsed_data)
                    else:
                        print("Failed to parse HTTP data")
                w.send(packet)

    capture_thread = threading.Thread(target=capture_thread)
    capture_thread.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping capture...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Capture HTTP traffic and send to API')
    parser.add_argument('--api_key', required=True, help='API key for sending data to API')
    parser.add_argument('--host', required=True, help='Host to capture HTTP traffic for')
    parser.add_argument('--port', required=True, type=int, help='Port to capture HTTP traffic on')
    args = parser.parse_args()

    capture_http_traffic(args.api_key, args.host, args.port)
