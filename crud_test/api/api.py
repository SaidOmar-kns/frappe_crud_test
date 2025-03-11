import frappe
from frappe import _
from frappe.utils import cint
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

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
        return {
            'base64_ciphertext': base64_ciphertext
        }


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