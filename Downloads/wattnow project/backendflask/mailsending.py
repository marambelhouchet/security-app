# Email Configuration
from email.mime.image import MIMEImage  # For embedding images in emails
from email.mime.multipart import MIMEMultipart  # For creating multipart email messages
from email.mime.text import MIMEText  # For adding plain text and HTML content to emails
import logging  # For logging errors and information
import os  # For accessing environment variables and file paths
import re  # For processing and cleaning content
import smtplib  # For sending emails via SMTP

# SMTP Configuration
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')  # SMTP server address (default: Gmail)
SMTP_PORT = int(os.getenv('SMTP_PORT', 465))  # SMTP server port (default: 465 for SSL)
SMTP_EMAIL = os.getenv('SMTP_EMAIL')  # Sender email address (retrieved from environment variables)
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')  # Sender email password (retrieved from environment variables)
ALERT_RECIPIENTS = os.getenv('ALERT_RECIPIENTS', '').split(',')  # Default recipients (retrieved from environment variables)

# Function to clean LaTeX content
def clean_latex(content):
    """
    Convert LaTeX formatting to plain text and HTML-compatible representations.

    Parameters:
        content (str): The raw content containing LaTeX formatting.

    Returns:
        str: A cleaned version of the content with LaTeX formatting removed or converted.
    """
    # Remove equation environments (inline and block equations)
    content = re.sub(r'\$(.*?)\$', r'\1', content)  # Inline equations
    content = re.sub(r'\$\$(.*?)\$\$', r'\1', content, flags=re.DOTALL)  # Block equations

    # Remove <calculations>...</calculations> block entirely
    content = re.sub(r'<calculations>.*?</calculations>', '', content, flags=re.DOTALL)

    # Replace common LaTeX symbols with their Unicode equivalents
    replacements = {
        r'\\alpha': 'α', r'\\beta': 'β', r'\\gamma': 'γ', r'\\delta': 'δ',
        r'\\epsilon': 'ε', r'\\zeta': 'ζ', r'\\eta': 'η', r'\\theta': 'θ',
        r'\\iota': 'ι', r'\\kappa': 'κ', r'\\lambda': 'λ', r'\\mu': 'μ',
        r'\\nu': 'ν', r'\\xi': 'ξ', r'\\pi': 'π', r'\\rho': 'ρ',
        r'\\sigma': 'σ', r'\\tau': 'τ', r'\\upsilon': 'υ', r'\\phi': 'φ',
        r'\\chi': 'χ', r'\\psi': 'ψ', r'\\omega': 'ω',
        r'\\times': '×', r'\\div': '÷', r'\\pm': '±', r'\\leq': '≤',
        r'\\geq': '≥', r'\\neq': '≠', r'\\approx': '≈', r'\\infty': '∞',
        r'\\sqrt': '√', r'\\cdot': '·', r'\\to': '→', r'\\circ': '°',
        r'\\prime': '′', r'\\sum': 'Σ', r'\\prod': 'Π', r'\\int': '∫'
    }
    for pattern, replacement in replacements.items():
        content = re.sub(pattern, replacement, content)

    # Convert fractions and special formats
    content = re.sub(r'\\frac\{(.*?)\}\{(.*?)\}', r'\1/\2', content)  # Fractions
    content = re.sub(r'\\sqrt\{(.*?)\}', r'√\1', content)  # Square roots
    content = re.sub(r'\\text\{(.*?)\}', r'\1', content)  # Text commands

    # Remove remaining LaTeX commands and clean special characters
    content = re.sub(r'\\([a-zA-Z]+)', r'\1', content)  # Remove LaTeX commands
    content = re.sub(r'[\{\}]', '', content)  # Remove braces
    return content

# Function to format content into HTML
def format_html_content(content):
    """
    Convert cleaned content to HTML with proper formatting and preserved tags.

    Parameters:
        content (str): The cleaned content.

    Returns:
        str: HTML-formatted content.
    """
    # Convert newlines to <br> for HTML formatting
    html = content.replace('\n', '<br>')

    # Handle superscripts and subscripts
    html = re.sub(r'\^(\w+)', r'<sup>\1</sup>', html)  # Superscripts
    html = re.sub(r'_(\w+)', r'<sub>\1</sub>', html)  # Subscripts

    # Convert bold patterns (**bold**) to <strong> tags
    html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)

    # Handle headers (lines starting with ###)
    html = re.sub(r'<br>###\s*(.+?)<br>', r'<br><strong>\1</strong><br>', html)
    html = re.sub(r'^###\s*(.+?)<br>', r'<strong>\1</strong><br>', html)  # Line start case

    return html
LOGO_PATH = r'C:\Users\user\Downloads\wattnow project\logo.png'

# Function to send alert emails
def send_alert_email(subject, content, recipients=None, lang='en'):
    """
    Send multilingual alert email with LaTeX normalization.

    Parameters:
        subject (str): The email subject.
        content (str): The email content (raw text with LaTeX formatting).
        recipients (list): A list of recipient email addresses (defaults to ALERT_RECIPIENTS).
        lang (str): The language for the email content ('en', 'fr', or 'ar').

    Raises:
        Exception: If email sending fails.
    """
    try:
        if not recipients:
            recipients = ALERT_RECIPIENTS  # Use default recipients if none are provided

        # Clean LaTeX content
        cleaned_content = clean_latex(content)

        # Define language-specific content
        lang_content = {
            'en': {
                'intro': "Dear Customer,",
                'outro': "For further information or assistance, please visit our dashboard or contact our technical support team.",
                'auto': "This is an automated alert from WattNow Monitoring System"
            },
            'fr': {
                'intro': "Cher Client,",
                'outro': "Pour davantage d'informations ou assistance, veuillez consulter notre tableau de bord ou contacter notre équipe de support technique.",
                'auto': "Ceci est une alerte automatique du système de surveillance WattNow"
            },
            'ar': {
                'intro': "عزيزي العميل،",
                'outro': "لمزيد من المعلومات أو المساعدة، يرجى زيارة لوحة التحكم الخاصة بنا أو الاتصال بفريق الدعم الفني لدينا.",
                'auto': "هذا تنبيه تلقائي من نظام مراقبة WattNow"
            }
        }
        lc = lang_content.get(lang, lang_content['en'])  # Default to English if language not found

        # Create plain text and HTML versions of the email
        text = f"""
{lc['intro']}

{cleaned_content}

{lc['outro']}
<div style="margin-top: 20px; display: flex; align-items: center; gap: 20px;">
    <img src="cid:logo@wattnow" alt="WattNow Logo" style="max-width: 200px; height: auto;">
    <div style="line-height: 1.6;">
        <p style="margin: 0;">
            
WattNow Energy Assistant<br>
            Mobile: +21658725305<br>
            Website: <a href="http://www.wattnow.io" style="color: #0066cc; text-decoration: none;">www.wattnow.io</a><br>
        </p>
    </div>
</div>
<p><em>{lc['auto']}</em></p>
"""
        html_content = format_html_content(cleaned_content)
        html = f"""<html>
          <body>
            <p>{lc['intro']}</p>
            <div>{html_content}</div>
            <p>{lc['outro']}</p>
          </body>
        </html>"""

        # Create MIME message
        msg = MIMEMultipart('related')
        msg['Subject'] = subject
        msg['From'] = SMTP_EMAIL
        msg['To'] = ", ".join(recipients)

        # Attach plain text and HTML versions
        alternative = MIMEMultipart('alternative')
        alternative.attach(MIMEText(text, 'plain', 'utf-8'))
        alternative.attach(MIMEText(html, 'html', 'utf-8'))
        msg.attach(alternative)

        # Send email via SMTP
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, recipients, msg.as_string())
            logging.info(f"Alert email sent to {recipients}")

    except Exception as e:
        logging.error(f"Email failed: {str(e)}")
        raise

# Function to extract alert information
def extract_alert_info(alert):
    """
    Extract structured data from alert JSON.

    Parameters:
        alert (dict): The alert JSON object.

    Returns:
        dict: A dictionary containing extracted alert information.
    """
    try:
        # Extract basic alert details
        alert_type = alert.get("type", {}).get("type") or alert.get("alert_type")
        device_label = alert.get("device", {}).get("label")
        details = alert.get("type", {}).get("details", {})
        measured_value = details.get("measuredValue")
        threshold = details.get("threshold")

        # Compute overrun percentage if applicable
        overrun_pct = None
        if isinstance(measured_value, (int, float)) and isinstance(threshold, (int, float)) and threshold != 0:
            overrun_pct = round(((measured_value - threshold) / threshold) * 100, 2)

        # Build base alert information
        base_info = {
            "type": alert_type,
            "device_label": device_label,
            "unit": details.get("unit"),
            "value": details.get("Value"),
            "threshold": threshold,
            "measured_value": measured_value,
            "overrun_pct": overrun_pct,
            "timestamp": alert.get("timestamp")
        }

        # Add specific fields for certain alert types
        if alert_type == "ElectricityCuts":
            base_info.update({"hold_on": details.get("hold_on")})
        elif alert_type == "CurrentDayVsLastDay":
            base_info.update({
                "today": details.get("Value"),
                "yesterday": details.get("yesterday_consumption"),
                "threshold": details.get("threshold"),
                "site": alert.get("site")
            })
        elif alert_type == "SubscribedPower":
            base_info.update({
                "measured_value": measured_value,
                "threshold": threshold
            })

        return base_info
    except Exception as e:
        logging.error(f"Error extracting alert info: {e}")
        return None
