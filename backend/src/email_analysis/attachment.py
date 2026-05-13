# backend/src/email_analysis/attachment.py
# Checks email attachments for dangerous file types
# Member: Giovanni
#
# SIMPLE EXPLANATION:
# Phishing emails attach malicious files to infect your computer
#
# DANGEROUS FILES (can run malicious code):
#   .exe .bat .cmd - programs that run directly
#   .js .vbs .ps1  - scripts that execute commands
#   .jar .scr      - Java and screensaver executables
#
# SUSPICIOUS FILES (might hide malware):
#   .zip .rar .7z  - compressed files that hide malicious content
#   .docm .xlsm    - Office files with macros enabled
#
# DOUBLE EXTENSION TRICK:
#   invoice.pdf.exe - looks like PDF but actually an executable!

# File types that execute malicious code directly
DANGEROUS = [
    '.exe', '.bat', '.cmd', '.com', '.js', '.vbs', '.vbe',
    '.wsf', '.ps1', '.jar', '.scr', '.pif', '.hta', '.dll', '.msi'
]

# File types that may hide or contain malware
SUSPICIOUS = [
    '.zip', '.rar', '.7z', '.tar', '.gz',   # compressed archives
    '.docm', '.xlsm', '.pptm',              # Office macros
    '.iso', '.img'                           # disk images
]


def check_attachments(attachments):
    """
    Check attachment filenames for dangerous types.
    Returns list of findings with filename, severity and reason.
    """
    findings = []
    for fn in attachments:
        fl = fn.lower()  # lowercase for comparison

        # Check if file is directly dangerous
        for ext in DANGEROUS:
            if fl.endswith(ext):
                findings.append({
                    'filename': fn,
                    'severity': 'HIGH',
                    'reason':   f'Executable file ({ext}) can run malicious code'
                })
                break  # found a match, stop checking

        else:
            # Check if file is suspicious but not immediately dangerous
            for ext in SUSPICIOUS:
                if fl.endswith(ext):
                    findings.append({
                        'filename': fn,
                        'severity': 'MEDIUM',
                        'reason':   f'Compressed/macro file ({ext}) may hide malware'
                    })
                    break

        # Check for double extension trick (invoice.pdf.exe)
        parts = fl.split('.')
        if len(parts) > 2 and f'.{parts[-1]}' in DANGEROUS:
            findings.append({
                'filename': fn,
                'severity': 'HIGH',
                'reason':   'Double extension detected - file disguised as safe type'
            })

    return findings
