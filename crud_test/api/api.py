import frappe
from frappe import _
from frappe.utils import cint
import json

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