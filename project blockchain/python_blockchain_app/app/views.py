import datetime
import json

import requests
from flask import render_template, redirect, request,url_for
from flask import flash

from app import app

# The node with which our application interacts, there can be multiple
# such nodes as well.
app.secret_key = 'XA\xef\xd3g\\\xfd\xa3\xd3\xad\xd0\x94I.\x0b{odv[\xda{\x04Z'
CONNECTED_NODE_ADDRESS = "http://127.0.0.1:8000"

posts = []

    
def fetch_posts():
    """
    Function to fetch the chain from a blockchain node, parse the
    data and store it locally.
    """
    get_chain_address = "{}/chain".format(CONNECTED_NODE_ADDRESS)
    try:
        response = requests.get(get_chain_address)
        response.raise_for_status()
    
        content = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["previous_hash"] = block["previous_hash"]
                tx["current_hash"] = block["hash"]  # Add this line
                tx["transactions"] = json.dumps(tx)
                content.append(tx)

        global posts
        posts = sorted(content, key=lambda k: k['timestamp'],
                       reverse=True)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching posts: {e}")
        posts = []


@app.route('/')
def index():
    fetch_posts()
    return render_template('index.html',
                           title='Invoice Registration Portal',
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string,datetime=datetime)


@app.route('/submit', methods=['POST'])
def submit_textarea():
    """
    Endpoint to create a new transaction via our application.
    """
    document_type = request.form["document_type"]
    document_number = request.form["document_number"]
    gst_no = request.form["gst_no"]
    document_date = request.form["document_date"]
    seller = request.form["seller"]
    buyer = request.form["buyer"]
    financial_year = request.form.get('financial_year')

    post_object = {
        'document_type': document_type,
        'document_number': document_number,
        'gst_no': gst_no,
        'document_date': document_date,
        'seller': seller,
        'buyer': buyer,
        'financial_year': financial_year
    }

    # Define new_tx_address here, before using it in the try block:
    new_tx_address = "{}/new_transaction".format(CONNECTED_NODE_ADDRESS) 

    try:
        response = requests.post(new_tx_address, json=post_object, headers={'Content-type': 'application/json'})
        response.raise_for_status()  # Raise an exception for bad status codes 
        if response.status_code == 201:
            irn_hash = response.json().get('irn_hash')
            flash(f"Transaction submitted successfully. Generated IRN: {irn_hash}", "success")
        else:
            flash(f"Error: {response.text}", "error") 
    except requests.exceptions.RequestException as e:
        flash(f"Error submitting transaction: {str(e)}", "error")

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
        else:
            flash(f"Error: {response.json().get('message', 'Unknown error')}", "error")
    except requests.exceptions.RequestException as e:
        flash(f"Error cancelling invoice: {str(e)}", "error")
    
    return redirect(url_for('index'))
    

def timestamp_to_string(epoch_time):
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%H:%M')

