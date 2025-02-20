import frappe
from frappe import _
from frappe.utils import cint
import json

@frappe.whitelist()
def create_custom_personal_doc():
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