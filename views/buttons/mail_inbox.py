from storage.romeo_db import RomeoDB as DBConnection
from tools.fetch_inbox import fetchInbox
from tools.email_view import emailView

async def get_inbox(email: str) -> dict:
    
    emails = await fetchInbox(email)
    view = emailView(emails, email)

    return {
        "embed": view.getEmbed(), 
        "view": view
    }