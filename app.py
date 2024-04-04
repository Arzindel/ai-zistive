from flask import Flask, jsonify, Response, render_template, request, redirect, url_for, session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import os
import pickle
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import requests
import re  # Import the re module
from googleapiclient.errors import HttpError
import threading
import time
from datetime import datetime

# Define the base directory relative to the current file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
port = os.getenv('PORT', '8080')

app = Flask(__name__)
app.secret_key = 'P@ssw0rd'

client_secrets_file = os.path.join(BASE_DIR, 'auth', 'client_secret.json')
scopes = ['https://www.googleapis.com/auth/gmail.modify']
redirect_uri = f'http://localhost:{port}/oauth2callback'

def get_gmail_service():
    with open('auth/token.pickle', 'rb') as token:
        creds = pickle.load(token)
    return build('gmail', 'v1', credentials=creds)

@app.route('/')
def index():
    credentials = None
    try:
        with open('auth/token.pickle', 'rb') as token:
            credentials = pickle.load(token)
    except FileNotFoundError:
        pass

    if credentials and credentials.valid:
        return 'Credentials are already valid. Ready to make Gmail API calls!'
    elif credentials and credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        with open('auth/token.pickle', 'wb') as token:
            pickle.dump(credentials, token)
        return 'Credentials refreshed successfully!'
    else:
        flow = Flow.from_client_secrets_file(client_secrets_file, scopes=scopes, redirect_uri=redirect_uri)
        authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
        session['state'] = state
        return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('state')
    flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file, scopes=scopes, state=state, redirect_uri=redirect_uri)
    flow.fetch_token(authorization_response=request.url)
    with open('auth/token.pickle', 'wb') as token:
        pickle.dump(flow.credentials, token)
    return 'OAuth flow completed successfully! Credentials saved.'

def clean_email_body(body):
    pattern = re.compile(r"On\s+\w{3},\s+\w{3}\s+\d{1,2},\s+\d{4}\s+at")
    match = pattern.search(body)
    return body[:match.start()].strip() if match else body.strip()

@app.route('/fetch_emails')
def fetch_emails():
    service = get_gmail_service()
    results = service.users().messages().list(userId='me', q='is:unread', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])
    
    if not messages:
        return "No unread emails found."
    
    oldest_message = messages[-1]
    thread_id = oldest_message['threadId']
    session['thread_id'] = thread_id  # Store thread ID in session

    thread = service.users().threads().get(userId='me', id=thread_id).execute()
    messages = sorted(thread['messages'], key=lambda msg: int(msg['internalDate']))
    formatted_messages, subject = [], "No Subject"
    for message in messages:
        msg_details = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
        headers = {header['name']: header['value'] for header in msg_details['payload']['headers']}
        sender = headers.get("From", "Unknown Sender")
        if 'Subject' in headers and not subject:
            subject = headers['Subject']
        body = "Message body not available"
        if 'parts' in msg_details['payload']:
            for part in msg_details['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    body_data = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    body = clean_email_body(body_data)
                    break
        formatted_messages.append(f"--From: {sender}--\n{body}\n--Next Message--")
    response_content = f"Subject: {subject}\n--Next Message--\n" + "\n".join(formatted_messages)
    return Response(response_content, mimetype='text/plain')

def fetch_unread_emails(service):
    results = service.users().messages().list(userId='me', q='is:unread', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])
    if not messages:
        return []
    # Get the current date and time
    current_date_time = datetime.now()

    # Format the date and time in a specific format
    formatted_date_time = current_date_time.strftime("%Y-%m-%d %H:%M:%S")

    print("\nEmail received " + formatted_date_time)
    
    return messages

@app.route('/configuration', methods=['GET', 'POST'])
def configuration():
    config_file_path = os.path.join(BASE_DIR, 'config.json')
    os.makedirs(os.path.dirname(config_file_path), exist_ok=True)
    
    try:
        with open(config_file_path, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        config = {}

    if request.method == 'POST':
        config.update({
            'temperature': request.form.get('temperature'),
            'max_tokens': request.form.get('max_tokens'),
            'instruction_prompt': request.form.get('instruction_prompt'),
            'auto_process_emails': request.form.get('auto_process_emails') == 'on', # New setting
        })
        with open(config_file_path, 'w') as f:
            json.dump(config, f)
        return redirect(url_for('configuration'))
    
    return render_template('configuration.html', config=config)


@app.route('/ai-input')
def ai_input():
    if 'thread_id' not in session:
        return "Error: No thread ID found. Please fetch emails first."
    
    email_content = get_email_content()
    config_file_path = os.path.join(BASE_DIR, 'config.json')
    with open(config_file_path, 'r') as file:
        config = json.load(file)
    
    ai_input_content = {
        "prompt": "### Instructions:\n" + config.get("instruction_prompt", "") + "\n### User:\nConversation Start:\n" + email_content + "\n--From: AI Zistive <email_address>--\n\n### Assistant:\n",
        "max_tokens": config.get("max_tokens", 1024),
        "temperature": config.get("temperature", 0.5),
        "stop": [", AI Zistive Inc.","--Next Message--","--From","###", "AI Zistive Inc"],
    }
    return jsonify(ai_input_content)

@app.route('/ai-output', methods=['GET', 'POST'])
def ai_output():
    if 'thread_id' not in session:
        return "Error: No thread ID found. Please fetch emails first."
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create_draft':
            ai_text = request.form.get('ai_text')
            thread_id = session.get('thread_id')
            
            if not thread_id:
                return "Error: No thread ID found."
            
            service = get_gmail_service()
            subject, sender_email, recipient_email = get_email_details(service, thread_id)
            create_gmail_draft(service, 'me', ai_text, thread_id, sender_email, recipient_email, subject)
            return render_template('draft_created.html')
        
        elif action == 'send_to_ai':
            # Logic for sending input to AI and getting a response
            config_file_path = os.path.join(BASE_DIR, 'config.json')
            with open(config_file_path, 'r') as file:
                config = json.load(file)

            email_content = get_email_content()

            ai_input_content = {
                "prompt": "### Instructions:\n" + config.get("instruction_prompt", "") + "\n### User:\nConversation Start:\n" + email_content + "\n--From: AI Zistive <email_address>--\n\n### Assistant:\n",
                "max_tokens": config.get("max_tokens", 1024),
                "temperature": config.get("temperature", 0.5),
                "stop": [", AI Zistive Inc.","--Next Message--","--From","###", "AI Zistive Inc"],
            }

            ai_api_url = 'http://127.0.0.1:5000/v1/completions'
            response = requests.post(ai_api_url, json=ai_input_content)

            if response.status_code == 200:
                ai_response = response.json()
                return render_template('ai_output.html', ai_response=ai_response)
            else:
                return f"Error: Unable to get a response from AI API. Status code: {response.status_code}"
    else:
        # For GET request, show the submission form
        return render_template('submit_ai_input.html')


@app.route('/send-draft', methods=['POST'])
def send_draft():
    if 'thread_id' not in session or 'draft_id' not in session:
        return "Error: No draft or thread ID found."
    
    service = get_gmail_service()
    draft_id = session['draft_id']
    thread_id = session['thread_id']
    
    try:
        service.users().drafts().send(userId='me', body={'id': draft_id}).execute()
        mark_thread_as_read(service, thread_id)  # Mark the thread as read after sending the draft
        return redirect(url_for('draft_sent_confirmation'))
    except HttpError as error:
        # Extract more detailed error information if available
        error_details = error._get_reason()
        return f"An error occurred while sending the draft: {error_details}"
    except Exception as e:
        return f"An error occurred: {str(e)}"

def mark_thread_as_read(service, thread_id):
    try:
        # This is the API call to modify the thread's labels
        service.users().threads().modify(
            userId='me',
            id=thread_id,
            body={'removeLabelIds': ['UNREAD']}
        ).execute()
        print(f"Email Thread marked as read")
    except Exception as e:
        print(f"An error occurred: {e}")


@app.route('/draft-sent-confirmation')
def draft_sent_confirmation():
    return "<h2>Draft Sent Successfully</h2><p>The draft has been sent and the thread is marked as read.</p>"


def get_email_details(service, thread_id):
    thread = service.users().threads().get(userId='me', id=thread_id, format='metadata').execute()
    messages = thread['messages']
    headers = messages[0]['payload']['headers']
    subject = next((header['value'] for header in headers if header['name'].lower() == 'subject'), "No Subject")
    sender_email = next((header['value'] for header in headers if header['name'].lower() == 'from'), None)
    recipient_email = next((header['value'] for header in headers if header['name'].lower() == 'to'), None)
    message_id = next((header['value'] for header in headers if header['name'].lower() == 'message-id'), None)
    return subject, sender_email, recipient_email, message_id


def create_gmail_draft(service, user_id, message_text, thread_id, sender_email, recipient_email, subject):
    print("Creating response draft")
    message = MIMEMultipart()
    message['to'] = sender_email  # Use the dynamically determined recipient
    message['from'] = recipient_email
    message['subject'] = "Re: " + subject
    message.attach(MIMEText(message_text, 'plain'))

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    draft_body = {
        'message': {
            'raw': raw_message,
            'threadId': thread_id
        }
    }

    draft = service.users().drafts().create(userId=user_id, body=draft_body).execute()
    print(f"Draft created: {draft['id']}")
    # Store draft ID in session
    session['draft_id'] = draft['id']

def send_email(service, user_id, message_text, thread_id, sender_email, recipient_email, subject, previous_message_id):
    message = MIMEMultipart()
    message['to'] = sender_email
    message['from'] = recipient_email
    message['subject'] = subject
    message['In-Reply-To'] = previous_message_id
    message['References'] = previous_message_id
    message.attach(MIMEText(message_text, 'plain'))

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message_body = {'raw': raw_message, 'threadId': thread_id}
    print("Sending email")
    try:
        sent_message = service.users().messages().send(userId=user_id, body=message_body).execute()
        print(f"Email sent successfully")
    except Exception as e:
        print(f"An error occurred: {str(e)}")



def get_email_content(service, thread_id):
    print("Fetching email data")
    thread = service.users().threads().get(userId='me', id=thread_id).execute()
    messages = sorted(thread['messages'], key=lambda msg: int(msg['internalDate']))
    formatted_messages = []
    subject = "No Subject"
    for message in messages:
        msg_details = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
        headers = {header['name']: header['value'] for header in msg_details['payload']['headers']}
        sender = headers.get("From", "Unknown Sender")
        if 'Subject' in headers:
            subject = headers['Subject']
        body = "Message body not available"
        if 'parts' in msg_details['payload']:
            for part in msg_details['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    body_data = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    body = clean_email_body(body_data)
                    break
        formatted_messages.append(f"--From: {sender}--\n{body}\n--Next Message--")
    return f"Subject: {subject}\n--Next Message--\n" + "\n".join(formatted_messages)


def process_email_thread(service, thread_id, config):
    email_content = get_email_content(service, thread_id)
    ai_response = send_to_ai(email_content, config)
    if ai_response:
        subject, sender_email, recipient_email, message_id = get_email_details(service, thread_id)
        send_email(service, 'me', ai_response, thread_id, sender_email, recipient_email, subject, message_id)
        mark_thread_as_read(service, thread_id)

def auto_email_processing():
    while True:
        time.sleep(5)  # Check every 30 seconds
        try:
            config_file_path = os.path.join(BASE_DIR, 'config.json')
            with open(config_file_path, 'r') as file:
                config = json.load(file)

            if not config.get('auto_process_emails'):
                print("Automatic email processing is disabled. Waiting...")
                continue

            service = get_gmail_service()
            unread_emails = fetch_unread_emails(service)
            for message in unread_emails:
                thread_id = message['threadId']
                process_email_thread(service, thread_id, config)
        except Exception as e:
            print(f"An error occurred in the email processing loop: {e}")

def send_to_ai(email_content, config):
    
    ai_input_content = {
        "prompt": "### Instructions:\n" + config.get("instruction_prompt", "") + "\n### User:\nConversation Start:\n" + email_content + "\n--From: AI Zistive <email_address>--\n\n### Assistant:\n",
        "max_tokens": config.get("max_tokens", 1024),
        "temperature": config.get("temperature", 0.5),
        "stop": [", AI Zistive Inc.","--Next Message--","--From","###", "AI Zistive Inc"],
    }
    print(ai_input_content)
    print("Sending data to AI API and waiting response generation")
    ai_api_url = 'http://127.0.0.1:5000/v1/completions'
    response = requests.post(ai_api_url, json=ai_input_content)
    
    if response.status_code == 200:
        ai_response = response.json()
        print(ai_response)
        # Adjusting the path to extract 'text' based on the provided API response format
        if 'choices' in ai_response and len(ai_response['choices']) > 0:
            generated_text = ai_response['choices'][0].get('text')
            return generated_text
        else:
            print("Unexpected response structure:", ai_response)
            return None
    else:
        print(f"Error: Unable to get a response from AI API. Status code: {response.status_code}")
        return None


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    if not os.environ.get("BACKGROUND_THREAD_STARTED"):
        os.environ["BACKGROUND_THREAD_STARTED"] = "1"
        email_thread = threading.Thread(target=auto_email_processing, daemon=True)
        email_thread.start()
    app.run(debug=True, port=port)