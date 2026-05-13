# backend/src/email_analysis/parser.py
# Parses raw .eml email files into structured Python dict
# Member: Giovanni
#
# SIMPLE EXPLANATION:
# .eml files are raw email files with headers and body
# Python's built-in 'email' library reads them
# BeautifulSoup finds all links inside HTML emails
#
# OUTPUT DICT:
#   subject     - email subject line
#   from        - who sent it
#   reply_to    - where replies go (may differ from 'from')
#   body_text   - plain text content
#   urls        - all links found
#   attachments - list of file names attached

import email
import re
from email import policy
from bs4 import BeautifulSoup  # finds links in HTML emails


def parse_email(raw_text):
    """Parse raw email text into structured dictionary."""
    # Python's email library handles complex .eml format
    msg = email.message_from_string(raw_text, policy=policy.default)

    result = {
        'subject':     msg.get('Subject', ''),
        'from':        msg.get('From', ''),      # sender address
        'reply_to':    msg.get('Reply-To', ''),  # replies go here
        'to':          msg.get('To', ''),
        'date':        msg.get('Date', ''),
        'headers':     dict(msg.items()),         # all headers as dict
        'body_text':   '',     # plain text body
        'body_html':   '',     # HTML body
        'urls':        [],     # all URLs found
        'attachments': [],     # attachment filenames
    }

    # Walk through all parts (emails can have multiple sections)
    for part in msg.walk():
        ctype = part.get_content_type()         # text/plain or text/html
        disp  = str(part.get('Content-Disposition', ''))

        if ctype == 'text/plain' and 'attachment' not in disp:
            # Plain text body
            result['body_text'] += part.get_content()

        elif ctype == 'text/html' and 'attachment' not in disp:
            # HTML body - extract and find all links
            html = part.get_content()
            result['body_html'] = html
            result['urls'] += _urls_from_html(html)

        elif 'attachment' in disp:
            # File attachment - save filename for safety check
            fn = part.get_filename()
            if fn:
                result['attachments'].append(fn)

    # Also find URLs in plain text body
    result['urls'] += _urls_from_text(result['body_text'])
    result['urls']  = list(set(result['urls']))  # remove duplicates
    return result


def _urls_from_html(html):
    """Find all href links in HTML using BeautifulSoup."""
    urls = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            if a['href'].startswith('http'):
                urls.append(a['href'].strip())
    except Exception:
        pass
    return urls


def _urls_from_text(text):
    """Find URLs in plain text using regex pattern matching."""
    return re.findall(r'https?://[^\s<>"\'()]+', text)
