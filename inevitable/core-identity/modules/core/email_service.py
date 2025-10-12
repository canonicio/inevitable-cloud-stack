"""
Email service for Platform Forge applications
Supports SMTP, SendGrid, AWS SES, and more
"""
import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
import aiosmtplib
from pydantic import BaseModel, EmailStr

from .config import settings
from .database import get_db
from ..auth.models import User

logger = logging.getLogger(__name__)


class EmailConfig(BaseModel):
    """Email configuration"""
    provider: str = "smtp"  # smtp, sendgrid, ses, mailgun
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    from_email: str = "noreply@platformforge.dev"
    from_name: str = "Platform Forge"
    api_key: Optional[str] = None  # For API-based providers
    
    class Config:
        from_attributes = True


class EmailTemplate(BaseModel):
    """Email template data"""
    subject: str
    template_name: str
    context: Dict[str, Any] = {}
    attachments: List[Dict[str, Any]] = []


class EmailService:
    """Unified email service supporting multiple providers"""
    
    def __init__(self, config: Optional[EmailConfig] = None):
        self.config = config or self._load_config()
        self.template_env = self._setup_templates()
        self._setup_provider()
    
    def _load_config(self) -> EmailConfig:
        """Load email configuration from environment"""
        return EmailConfig(
            provider=os.getenv("EMAIL_PROVIDER", "smtp"),
            smtp_host=os.getenv("SMTP_HOST", "localhost"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_username=os.getenv("SMTP_USERNAME"),
            smtp_password=os.getenv("SMTP_PASSWORD"),
            smtp_use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
            from_email=os.getenv("EMAIL_FROM", "noreply@platformforge.dev"),
            from_name=os.getenv("EMAIL_FROM_NAME", "Platform Forge"),
            api_key=os.getenv("EMAIL_API_KEY")
        )
    
    def _setup_templates(self) -> Environment:
        """Setup Jinja2 template environment"""
        template_dir = Path(__file__).parent.parent / "templates" / "emails"
        
        # Create default template directory if it doesn't exist
        template_dir.mkdir(parents=True, exist_ok=True)
        
        # Create default templates if they don't exist
        self._create_default_templates(template_dir)
        
        return Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def _create_default_templates(self, template_dir: Path):
        """Create default email templates"""
        # Base template
        base_template = template_dir / "base.html"
        if not base_template.exists():
            base_template.write_text('''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Platform Forge{% endblock %}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f8f9fa; }
        .footer { text-align: center; padding: 20px; color: #6c757d; font-size: 0.9em; }
        .button { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ company_name | default('Platform Forge') }}</h1>
        </div>
        <div class="content">
            {% block content %}{% endblock %}
        </div>
        <div class="footer">
            {% block footer %}
            <p>&copy; {{ current_year }} {{ company_name | default('Platform Forge') }}. All rights reserved.</p>
            {% endblock %}
        </div>
    </div>
</body>
</html>''')
        
        # Welcome email template
        welcome_template = template_dir / "welcome.html"
        if not welcome_template.exists():
            welcome_template.write_text('''{% extends "base.html" %}
{% block title %}Welcome to Platform Forge{% endblock %}
{% block content %}
<h2>Welcome, {{ user.name }}!</h2>
<p>Thank you for joining Platform Forge. Your account has been created successfully.</p>
<p>To get started, please verify your email address by clicking the button below:</p>
<p style="text-align: center; margin: 30px 0;">
    <a href="{{ verification_url }}" class="button">Verify Email Address</a>
</p>
<p>Or copy and paste this link into your browser:</p>
<p style="word-break: break-all; color: #007bff;">{{ verification_url }}</p>
<p>This link will expire in 24 hours.</p>
<p>Best regards,<br>The Platform Forge Team</p>
{% endblock %}''')
        
        # Password reset template
        reset_template = template_dir / "password_reset.html"
        if not reset_template.exists():
            reset_template.write_text('''{% extends "base.html" %}
{% block title %}Reset Your Password{% endblock %}
{% block content %}
<h2>Password Reset Request</h2>
<p>Hi {{ user.name }},</p>
<p>We received a request to reset your password. Click the button below to create a new password:</p>
<p style="text-align: center; margin: 30px 0;">
    <a href="{{ reset_url }}" class="button">Reset Password</a>
</p>
<p>Or copy and paste this link into your browser:</p>
<p style="word-break: break-all; color: #007bff;">{{ reset_url }}</p>
<p>This link will expire in 1 hour.</p>
<p>If you didn't request this password reset, please ignore this email.</p>
<p>Best regards,<br>The Platform Forge Team</p>
{% endblock %}''')
        
        # MFA code template
        mfa_template = template_dir / "mfa_code.html"
        if not mfa_template.exists():
            mfa_template.write_text('''{% extends "base.html" %}
{% block title %}Your Security Code{% endblock %}
{% block content %}
<h2>Your Security Code</h2>
<p>Hi {{ user.name }},</p>
<p>Your security code for Platform Forge is:</p>
<div style="text-align: center; margin: 30px 0;">
    <div style="display: inline-block; padding: 20px; background: white; border: 2px solid #007bff; border-radius: 5px;">
        <h1 style="margin: 0; color: #007bff; letter-spacing: 5px;">{{ code }}</h1>
    </div>
</div>
<p>This code will expire in 10 minutes.</p>
<p>If you didn't request this code, please secure your account immediately.</p>
<p>Best regards,<br>The Platform Forge Team</p>
{% endblock %}''')
    
    def _setup_provider(self):
        """Setup email provider client"""
        if self.config.provider == "sendgrid":
            try:
                import sendgrid
                self.sg_client = sendgrid.SendGridAPIClient(api_key=self.config.api_key)
            except ImportError:
                logger.warning("SendGrid not installed, falling back to SMTP")
                self.config.provider = "smtp"
        
        elif self.config.provider == "ses":
            try:
                import boto3
                self.ses_client = boto3.client('ses', region_name=os.getenv("AWS_REGION", "us-east-1"))
            except ImportError:
                logger.warning("Boto3 not installed, falling back to SMTP")
                self.config.provider = "smtp"
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        reply_to: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> bool:
        """Send email using configured provider"""
        try:
            # Log email send attempt
            logger.info(f"Sending email to {to_email} with subject: {subject}")
            
            if self.config.provider == "smtp":
                return await self._send_smtp(
                    to_email, subject, html_content, text_content,
                    attachments, cc, bcc, reply_to
                )
            elif self.config.provider == "sendgrid":
                return await self._send_sendgrid(
                    to_email, subject, html_content, text_content,
                    attachments, cc, bcc, reply_to
                )
            elif self.config.provider == "ses":
                return await self._send_ses(
                    to_email, subject, html_content, text_content,
                    attachments, cc, bcc, reply_to
                )
            else:
                logger.error(f"Unknown email provider: {self.config.provider}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    async def _send_smtp(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        reply_to: Optional[str] = None
    ) -> bool:
        """Send email via SMTP"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.from_name} <{self.config.from_email}>"
            msg['To'] = to_email
            
            if cc:
                msg['Cc'] = ', '.join(cc)
            if reply_to:
                msg['Reply-To'] = reply_to
            
            # Add text and HTML parts
            if text_content:
                msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Add attachments
            if attachments:
                for attachment in attachments:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment['content'])
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename={attachment["filename"]}'
                    )
                    msg.attach(part)
            
            # Send email
            async with aiosmtplib.SMTP(
                hostname=self.config.smtp_host,
                port=self.config.smtp_port,
                use_tls=self.config.smtp_use_tls
            ) as smtp:
                if self.config.smtp_username and self.config.smtp_password:
                    await smtp.login(self.config.smtp_username, self.config.smtp_password)
                
                recipients = [to_email]
                if cc:
                    recipients.extend(cc)
                if bcc:
                    recipients.extend(bcc)
                
                await smtp.send_message(msg, recipients=recipients)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"SMTP send failed: {e}")
            return False
    
    async def _send_sendgrid(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        reply_to: Optional[str] = None
    ) -> bool:
        """Send email via SendGrid"""
        from sendgrid.helpers.mail import Mail, Email, To, Content
        
        message = Mail(
            from_email=Email(self.config.from_email, self.config.from_name),
            to_emails=To(to_email),
            subject=subject,
            html_content=Content("text/html", html_content)
        )
        
        if text_content:
            message.add_content(Content("text/plain", text_content))
        
        try:
            response = self.sg_client.send(message)
            return response.status_code < 300
        except Exception as e:
            logger.error(f"SendGrid send failed: {e}")
            return False
    
    async def _send_ses(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None,
        reply_to: Optional[str] = None
    ) -> bool:
        """Send email via AWS SES"""
        try:
            destination = {'ToAddresses': [to_email]}
            if cc:
                destination['CcAddresses'] = cc
            if bcc:
                destination['BccAddresses'] = bcc
            
            message = {
                'Subject': {'Data': subject},
                'Body': {'Html': {'Data': html_content}}
            }
            
            if text_content:
                message['Body']['Text'] = {'Data': text_content}
            
            response = self.ses_client.send_email(
                Source=f"{self.config.from_name} <{self.config.from_email}>",
                Destination=destination,
                Message=message,
                ReplyToAddresses=[reply_to] if reply_to else []
            )
            
            return 'MessageId' in response
        except Exception as e:
            logger.error(f"SES send failed: {e}")
            return False
    
    async def send_template_email(
        self,
        to_email: str,
        template: EmailTemplate,
        tenant_id: Optional[str] = None
    ) -> bool:
        """Send email using template"""
        try:
            # Add default context
            context = {
                'current_year': datetime.now().year,
                'company_name': settings.APP_NAME,
                **template.context
            }
            
            # Render template
            html_template = self.template_env.get_template(f"{template.template_name}.html")
            html_content = html_template.render(**context)
            
            # Try to render text version
            text_content = None
            try:
                text_template = self.template_env.get_template(f"{template.template_name}.txt")
                text_content = text_template.render(**context)
            except:
                pass
            
            # Send email
            return await self.send_email(
                to_email=to_email,
                subject=template.subject,
                html_content=html_content,
                text_content=text_content,
                attachments=template.attachments,
                tenant_id=tenant_id
            )
            
        except Exception as e:
            logger.error(f"Template email failed: {e}")
            return False
    
    # Convenience methods for common emails
    
    async def send_welcome_email(self, user: User, verification_url: str) -> bool:
        """Send welcome email with verification link"""
        template = EmailTemplate(
            subject="Welcome to Platform Forge",
            template_name="welcome",
            context={
                'user': user,
                'verification_url': verification_url
            }
        )
        return await self.send_template_email(user.email, template, user.tenant_id)
    
    async def send_password_reset_email(self, user: User, reset_url: str) -> bool:
        """Send password reset email"""
        template = EmailTemplate(
            subject="Reset Your Password",
            template_name="password_reset",
            context={
                'user': user,
                'reset_url': reset_url
            }
        )
        return await self.send_template_email(user.email, template, user.tenant_id)
    
    async def send_mfa_code_email(self, user: User, code: str) -> bool:
        """Send MFA code email"""
        template = EmailTemplate(
            subject="Your Security Code",
            template_name="mfa_code",
            context={
                'user': user,
                'code': code
            }
        )
        return await self.send_template_email(user.email, template, user.tenant_id)
    
    async def send_billing_email(
        self,
        user: User,
        subject: str,
        template_name: str,
        context: Dict[str, Any]
    ) -> bool:
        """Send billing-related email"""
        template = EmailTemplate(
            subject=subject,
            template_name=template_name,
            context={
                'user': user,
                **context
            }
        )
        return await self.send_template_email(user.email, template, user.tenant_id)


# Global email service instance
email_service = EmailService()