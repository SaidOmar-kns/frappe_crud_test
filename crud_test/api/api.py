import frappe
from frappe import _
from frappe.utils import cint
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import jwt
import datetime
import requests
    


import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP

from werkzeug.wrappers import Response


@frappe.whitelist(allow_guest=True)
def create_custom_doc():
    """Create a new custom document"""
    try:
        data = json.loads(frappe.request.data)
        
        # Create new doc
        doc = frappe.new_doc("My Custom Doc")
        doc.update(data)
        doc.save()
        
        return {
            "success": True,
            "message": "Document created successfully",
            "data": doc.as_dict()
        }
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), _("Failed to create document"))
        return {
            "success": False,
            "message": str(e)
        }
    
@frappe.whitelist(allow_guest=True)
def org_fhir(**kwargs):
        from fhir.resources.organization import Organization
        from fhir.resources.address import Address
        json_str = {"resourceType": "Organization",
            "id": "f001",
            "active": True,
            "name": "Acme Corporation",
            "address": [{"country": "Switzerland"}]
        }
        org = Organization(json_str)
        isinstance(org.address[0], Address)
        org.address[0].country == "Switzerland" 
        org.dict()['active'] is True
        return org






    
@frappe.whitelist(allow_guest=True)
def encrypt_pin(**kwargs):
        payload = kwargs
        payload.pop('cmd', None)

        agent = "AFYANGU-00030"

        public_pem = frappe.db.get_value("Identity Auth RSA Keys",dict(agent_id=agent, active=1),["public_key"])
        # Ensure the 'pin' is a string
        pin = str(payload.get('pin', ''))  # Ensure it's a string
        
        # Ensure the public key is in bytes, and replace escaped newlines
        if isinstance(public_pem, str):
            public_pem = public_pem.encode('utf-8')  # Convert to bytes
        
        encrypted_pin = encrypt_and_encode(pin, public_pem)
        print("Base64 encoded ciphertext:", encrypted_pin)
        
        # Return only the base64 encoded ciphertext
        return encrypted_pin

@frappe.whitelist(allow_guest=True)
def encrypt_data(**kwargs):
        payload = kwargs
        payload.pop('cmd', None)

        # Ensure the 'pin' is a string
        data = str(payload.get('data', ''))  # Ensure it's a string
        public_pem = str(payload.get('public_key', ''))  # Ensure it's a string

        
        # Ensure the public key is in bytes, and replace escaped newlines
        if isinstance(public_pem, str):
            public_pem = public_pem.encode('utf-8')  # Convert to bytes
        
        encrypted_data = encrypt_and_encode(data, public_pem)
        # Return only the base64 encoded ciphertext
        return encrypted_data

def encrypt_and_encode(message, public_key_pem):
        """
        Encrypts a PIN using RSA with the provided public key,
        converts the encrypted data to a binary string, and base64 encodes it.
        :param message: The plaintext message to encrypt (string)
        :param public_key_pem: The public key in PEM format (bytes)
        :return: A dictionary with base64 encoded ciphertext
        """
        # Load the public key
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        # Encrypt the message
        ciphertext = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        
        # Base64 encode the ciphertext
        base64_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        return base64_ciphertext

def decrypt_data(**kwargs):
    payload = kwargs
    payload.pop('cmd', None)

    # Ensure the 'encrypted_data' is a string
    encrypted_data = str(payload.get('encrypted_data', ''))  # Encrypted data should be base64 encoded string
    private_pem = str(payload.get('private_key', ''))  # Private key in PEM format

    # Ensure the private key is in bytes, and replace escaped newlines
    if isinstance(private_pem, str):
        private_pem = private_pem.encode('utf-8')  # Convert to bytes

    decrypted_data = decrypt_and_decode(encrypted_data, private_pem)
    return decrypted_data

def decrypt_and_decode(base64_ciphertext, private_key_pem):
    """
    Decrypts the base64 encoded ciphertext using RSA and the provided private key.
    :param base64_ciphertext: The base64 encoded ciphertext to decrypt
    :param private_key_pem: The private key in PEM format (bytes)
    :return: The decrypted plaintext message
    """
    # Decode the base64 encoded ciphertext
    ciphertext = base64.b64decode(base64_ciphertext)

    # Load the private key
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Decrypt the message using the private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # Return the decrypted message (as a string)
    return plaintext.decode('utf-8')


@frappe.whitelist(allow_guest=True)
def read_custom_doc(name=None):
    """Read custom document by name"""
    try:
        if not name:
            # List all documents
            docs = frappe.get_all("My Custom Doc", 
                                  fields=["name", "name_field", "age", "email", "creation"])
            return {
                "success": True,
                "data": docs
            }
        
        # Get specific document
        doc = frappe.get_doc("My Custom Doc", name)
        return {
            "success": True,
            "data": doc.as_dict()
        }
    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }

@frappe.whitelist(allow_guest=True)
def update_custom_doc():
    try:
        data = json.loads(frappe.request.data)
        name = data.pop('name', None)  # Extract and remove name from data
        
        if not name:
            frappe.throw("Document name is required")
            
        # Update existing doc
        doc = frappe.get_doc("My Custom Doc", name)
        doc.update(data)
        doc.save()
        
        return {
            "success": True,
            "message": "Document updated successfully",
            "data": doc.as_dict()
        }
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), _("Failed to update document"))
        return {
            "success": False,
            "message": str(e)
        }
    
@frappe.whitelist(allow_guest=True)
def delete_custom_doc(name):
    """Delete a custom document"""
    try:
        frappe.delete_doc("My Custom Doc", name)
        return {
            "success": True,
            "message": "Document deleted successfully"
        }
    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }


@frappe.whitelist(allow_guest=True)
def enctypt_test(**kwargs):
    payload = kwargs
    agent = payload.get('agent')
    
    
    public_key = load_client_public_key(agent)
    return public_key

    data = payload.get('data')
    
    
    from identity_auth.identity_auth.doctype.identity_auth_settings.identity_auth_settings import (DictionaryManager)
    

    pii_base64 = DictionaryManager(agent = agent,public_key_str=public_key).encrypt_data_v2(data)
    return pii_base64

hie_settings = frappe.get_doc("HIE Auth Settings")

def jwt_usr_token():
    """
    To use your token:
    
    Add it to the Authorization header
    Include it in all API requests
    Remember this token expires every 20 seconds, so you may need to generate a new token for every API request"""
    
    
    now = datetime.datetime.now()
    payload = {"key": hie_settings.get('key'),"iat": now,"exp": now + datetime.timedelta(seconds=20)}
    token = jwt.encode(payload, hie_settings.get('secret'), algorithm="HS256")
    return token

def load_client_public_key(agent):
    
    headers = {
            'Accept': 'application/json',
            'Authorization':jwt_usr_token()
        }
    
    url = f"{hie_settings.get('base_url')}/hixgate-fetch-keys-from-agent?agent={agent}"
    return url
    response = requests.get(url, headers)
    return response
    response_json = response.json()['data']
    return response
    
    # Get public key from the response
    public_key = str(response_json[0]['public_key'])
    return public_key


@frappe.whitelist(allow_guest=True)
def decrypt_response(**kwargs):
    payload = kwargsjwt_usr_token
    payload.pop('cmd', None)

    agent = payload.get('agent')
    encrypted_data = payload.get('encrypted_data')

    if not agent or not isinstance(agent, str) or not agent.strip():
            frappe.throw("Please provide your Agent ID provided during API onboarding.")

    if not encrypted_data or not isinstance(encrypted_data, str) or not encrypted_data.strip():
            frappe.throw("Please provide the encrypted data to decrypt.")

    private_key = frappe.db.get_value("Identity Auth RSA Keys",dict(agent_id=agent, active=1),["private_key"])

    # Combined base64 string from encryption
    combined_base64 = encrypted_data

    # Split the combined base64 string to get encrypted AES key, IV, and JSON data
    combined_string = base64.b64decode(combined_base64).decode()
    encrypted_aes_key, encrypted_iv, encrypted_json_data = combined_string.split(":")

    

    # Decrypt the AES key and IV using the RSA private key
    aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)
    iv = decrypt_with_rsa(private_key, encrypted_iv)

    

    # Decrypt the JSON data using the AES key and IV
    decrypted_json_data = decrypt_with_aes(encrypted_json_data, aes_key, iv)
    

    # Load the decrypted JSON data
    data = json.loads(decrypted_json_data)

    response = Response(json.dumps(data), content_type='application/json')
    response.status_code = 200
    return response

    
# Function to decrypt AES key using RSA private key
def decrypt_with_rsa(private_key, encrypted_data):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return base64.b64decode(decrypted_data)

# Function to decrypt AES-encrypted data
def decrypt_with_aes(encrypted_data, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size)
    return decrypted_data.decode()



