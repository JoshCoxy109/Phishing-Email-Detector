# Phishing-Email-Detector
Script to detect phishing emails using JavaScript and IMAP in a Linux environment





Demo Video
[Watch the Demo Video](https://drive.google.com/file/d/1NkRaeZov0VDuGkcUVHb1v9onSxbEzgNJ/view?usp=drive_link)






Code Used


```python
import imaplib
import email
from email.header import decode_header

def is_phishing(subject, body, sender):
    phishing_words = ["urgent", "click here", "verify your account", "password reset", "suspicious activity"]
    
    if any(word in subject.lower() for word in phishing_words):
        return True
    if any(word in body.lower() for word in phishing_words):
        return True
    if "noreply@" in sender.lower():
        return True
    return False

def fetch_emails():
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login("your_email@gmail.com", "your_app_password")
    mail.select("inbox")
    
    status, messages = mail.search(None, "ALL")
    email_ids = messages[0].split()
    
    for email_id in email_ids[-5:]:
        status, msg_data = mail.fetch(email_id, "(RFC822)")
        
        for response in msg_data:
            if isinstance(response, tuple):
                msg = email.message_from_bytes(response[1])
                
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                
                sender, encoding = decode_header(msg.get("From"))[0]
                if isinstance(sender, bytes):
                    sender = sender.decode(encoding if encoding else "utf-8")
                
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        
                        if "attachment" not in content_disposition and content_type == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            break
                else:
                    body = msg.get_payload(decode=True).decode()
                
                if is_phishing(subject, body, sender):
                    print("Phishing alert!")
                    print(f"Subject: {subject}")
                    print(f"From: {sender}")
                    print(f"Snippet: {body[:100]}...")
                    print("-" * 50)
    
    mail.logout()

if __name__ == "__main__":
    fetch_emails()
