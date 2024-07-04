import datetime
import json
import requests
from flask import render_template, redirect, request, url_for, flash, jsonify,session
from app import app

app.secret_key = 'XA\xef\xd3g\\\xfd\xa3\xd3\xad\xd0\x94I.\x0b{odv[\xda{\x04Z'
CONNECTED_NODE_ADDRESS = "http://127.0.0.1:8000"

posts = []

def fetch_posts():
    get_chain_address = f"{CONNECTED_NODE_ADDRESS}/chain"
    try:
        response = requests.get(get_chain_address)
        response.raise_for_status()
    
        content = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["previous_hash"] = block["previous_hash"]
                tx["current_hash"] = block["hash"]
                tx["transactions"] = json.dumps(tx)
                content.append(tx)

        global posts
        posts = sorted(content, key=lambda k: k['timestamp'], reverse=True)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching posts: {e}")
        posts = []
def trigger_consensus():
    consensus_address = f"{CONNECTED_NODE_ADDRESS}/consensus"
    try:
        response = requests.get(consensus_address)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error triggering consensus: {e}")
@app.route('/')
def index():
    fetch_posts()
    return render_template('index.html',
                           title='Invoice Registration Portal',
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string,
                           datetime=datetime)

@app.route('/submit', methods=['POST'])
def submit_textarea():
    post_object = {
        'document_type': request.form["document_type"],
        'document_number': request.form["document_number"],
        'gst_no': request.form["gst_no"],
        'document_date': request.form["document_date"],
        'seller': request.form["seller"],
        'buyer': request.form["buyer"],
        'financial_year': request.form.get('financial_year')
    }

    new_tx_address = f"{CONNECTED_NODE_ADDRESS}/new_transaction"

    try:
        response = requests.post(new_tx_address, json=post_object, headers={'Content-type': 'application/json'})
        response.raise_for_status()
        if response.status_code == 201:
            irn_hash = response.json().get('irn_hash')
            flash(f"Transaction submitted successfully. Generated IRN: {irn_hash}", "success")
            trigger_consensus()
        else:
            flash(f"Error: {response.text}", "error") 
    except requests.exceptions.RequestException as e:
        flash(f"Error submitting transaction : 2150 : IRN already exists", "error")

    return redirect('/')

@app.route('/cancel', methods=['GET'])
def cancel_page():
    return render_template('cancel.html')

@app.route('/process_cancellation', methods=['POST'])
def process_cancellation():
    irn_hash = request.form.get('irn_hash')
    reason = request.form.get('reason')
    
    if not irn_hash or not reason:
        flash("Invalid input. Please provide both IRN hash and reason.", "error")
        return redirect(url_for('cancel_page'))

    cancel_address = f"{CONNECTED_NODE_ADDRESS}/cancel_invoice"
    try:
        response = requests.post(cancel_address, json={'irn_hash': irn_hash, 'reason': reason})
        response.raise_for_status()
        if response.status_code == 200:
            flash("Invoice cancelled successfully", "success")
            trigger_consensus()
        else:
            flash(f"Error: {response.json().get('message', 'Unknown error')}", "error")
    except requests.exceptions.RequestException as e:
        flash(f"Error cancelling invoice: Invoice already cancelled", "error")
    
    return redirect(url_for('index'))

@app.route('/transactions')
def transactions():
    fetch_posts()
    return render_template('transactions.html',
                           title='Transaction History',
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string,
                           datetime=datetime)

@app.route('/resync', methods=['POST'])
def resync():
    trigger_consensus()
    fetch_posts()
    return jsonify({'posts': posts})

def timestamp_to_string(epoch_time):
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%H:%M')