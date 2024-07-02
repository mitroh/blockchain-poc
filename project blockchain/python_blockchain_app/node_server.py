import os
import sys
import signal
import atexit
from hashlib import sha256
import json
import time
import threading
import hashlib

from flask import Flask, request, jsonify, Response
import requests


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        """
        A function that return the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()
class UniqueChecker:
  
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            print('Creating the object')
            cls._instance = super(UniqueChecker, cls).__new__(cls)
            cls._instance.irn_hashes = set()
        return cls._instance

    def generate_irn_hash(self, data):
       
        if data.get('type') == 'cancellation':# Use original_irn_hash if it's a cancellation transaction
            irn = data['original_irn_hash'] 
        else:
            irn = f"{data['gst_no']}{data['financial_year']}{data['document_type']}{data['document_number']}"
        return hashlib.sha256(irn.encode()).hexdigest()
    def check_unique(self, data):
        irn_hash = self.generate_irn_hash(data)
        
        print(f"Checking uniqueness for IRN hash: {irn_hash}")

        if irn_hash in self.irn_hashes:
            print("IRN hash already exists.")
            return False, "Error: Transaction with this IRN already exists."
        else:
            self.irn_hashes.add(irn_hash)
            print("Data added successfully.")    
            return True, "Data added successfully."
class Blockchain:
    # difficulty of our PoW algorithm
    difficulty = 2

    def __init__(self, chain=None):
        self.unconfirmed_transactions = []
        self.chain = chain
        self.unique_checker = UniqueChecker()  # Initialize the UniqueChecker
        if self.chain is None:
            self.chain = []
            self.create_genesis_block()

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """
        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * Checking if the proof is valid.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            raise ValueError("Previous hash incorrect")

        if not Blockchain.is_valid_proof(block, proof):
            raise ValueError("Block proof invalid")

        block.hash = proof
        self.chain.append(block)
        print(block.__dict__)

    @staticmethod
    def proof_of_work(block):
    
        return block.compute_hash()
    def add_new_transaction(self, transaction):
        
        consensus()  # Ensure we have the most up-to-date chain
        self.update_unique_checker()  # Update the unique checker with all transactions in the chain
        transaction['status'] = 'Active'
        success, message = self.unique_checker.check_unique(transaction)
        if not success:
            return message, 400, None
        self.unconfirmed_transactions.append(transaction)
        irn_hash = self.unique_checker.generate_irn_hash(transaction)
        return "Success", 201,irn_hash
    
    def cancel_invoice(self, irn_hash, reason):
        
        current_time = time.time()
        for block in self.chain:
            for transaction in block.transactions:
                if self.unique_checker.generate_irn_hash(transaction) == irn_hash:
                    if transaction.get('status') == 'Cancelled':
                        return False, "Invoice is already cancelled"

                    if current_time - transaction['timestamp'] <= 24 * 3600: 
                        cancellation_transaction = {
                            'type': 'cancellation',
                            'original_irn_hash': irn_hash,
                            'reason': reason,
                            'timestamp': current_time,
                            'status': 'Cancelled',
                            'seller': "N/A", 
                            'buyer': "N/A"  
                        }
                        self.unconfirmed_transactions.append(cancellation_transaction)
                        return True, "Cancellation transaction created successfully"
                    else:
                        return False, "Cancellation period has expired (more than 24 hours)"

        return False, "Invoice not found"
    def update_unique_checker(self):
        self.unique_checker = UniqueChecker()  # Reset the unique checker
        for block in self.chain:
            for transaction in block.transactions:
                self.unique_checker.check_unique(transaction)  # Add all existing transactions to the checker

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        
        return True
    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            # remove the hash field to recompute the hash again
            # using `compute_hash` method.
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break
            for transaction in block.transactions:
                if not cls.is_valid_transaction(transaction):
                    result = False
                    break

            block.hash, previous_hash = block_hash, block_hash
            
            if not result:
                break

        return result
    
    @staticmethod
    def is_valid_transaction(transaction):
        required_fields = ["document_type", "document_number", "gst_no", "document_date", "financial_year", "timestamp"]
        return all(field in transaction for field in required_fields)

    def mine(self):
        
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        new_block.previous_hash = self.last_block.hash
        self.add_block(new_block, proof)
        
        for transaction in self.unconfirmed_transactions:
            if transaction.get('type') == 'cancellation':
                self.update_invoice_status(transaction['original_irn_hash'], 'Cancelled')

        self.unconfirmed_transactions = []

        return True

    def update_invoice_status(self, irn_hash, status):
        for block in self.chain:
            for transaction in block.transactions:
                if self.unique_checker.generate_irn_hash(transaction) == irn_hash:
                    transaction['status'] = status
                    return
                
    def get_invoice_status(self, irn_hash):
        
        for block in reversed(self.chain):
            for transaction in reversed(block.transactions):
                if transaction.get('type') == 'cancellation' and transaction['original_irn_hash'] == irn_hash:
                    return 'Cancelled', transaction['reason'] # Return a tuple
                elif self.unique_checker.generate_irn_hash(transaction) == irn_hash:
                    return transaction.get('status', 'Active'), None  # Return a tuple
        return 'Not Found', None  # Return a tuple

app = Flask(__name__)

# the node's copy of blockchain
blockchain = None

# the address to other participating members of the network
peers = set()
last_block_index = 0


@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["document_type", "document_number", "gst_no", "document_date","financial_year"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 404

    tx_data["timestamp"] = time.time()

    message, status_code, irn_hash=blockchain.add_new_transaction(tx_data)

    response_data = {
        'message': message,
        'irn_hash': irn_hash # Include irn_hash in response
    }
    
    return json.dumps(response_data), status_code


chain_file_name = os.environ.get('DATA_FILE')


def create_chain_from_dump(chain_dump):
    
    generated_blockchain = Blockchain()
    # generated_blockchain.chain = []
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            continue  # skip genesis block
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        generated_blockchain.add_block(block, proof)
        # # Update UniqueChecker
        for tx in block_data["transactions"]:
            generated_blockchain.unique_checker.check_unique(tx)
    return generated_blockchain

@app.route('/chain', methods=['GET'])
def get_chain():
    print("Get chain")
    chain_data = []
    for block in blockchain.chain:
        
        block_dict = {
            'index': block.index,
            'transactions': block.transactions,
            'timestamp': block.timestamp,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'nonce': block.nonce
        }
        for transaction in block_dict['transactions']:
            if transaction.get('type') != 'cancellation':
                irn_hash = blockchain.unique_checker.generate_irn_hash(transaction)
                # transaction['status']= blockchain.get_invoice_status(irn_hash)
                status, cancellation_reason = blockchain.get_invoice_status(irn_hash) # Unpack both values
                transaction['status'] = status
                transaction['cancellation_reason'] = cancellation_reason  # Add cancellation reason
        chain_data.append(block_dict)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})


def save_chain():
    if chain_file_name is not None:
        with open(chain_file_name, 'a') as chain_file:
            chain_file.write(get_chain())


def exit_from_signal(signum, stack_frame):
    sys.exit(0)


atexit.register(save_chain)
signal.signal(signal.SIGTERM, exit_from_signal)
signal.signal(signal.SIGINT, exit_from_signal)


if chain_file_name is None:
    data = None
else:
    with open(chain_file_name, 'r') as chain_file:
        raw_data = chain_file.read()
        if raw_data is None or len(raw_data) == 0:
            data = None
        else:
            data = json.loads(raw_data)

if data is None:
    # the node's copy of blockchain
    blockchain = Blockchain()
else:
    blockchain = create_chain_from_dump(data['chain'])
    peers.update(data['peers'])


@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    
    print("Mining here")
    result = blockchain.mine()
    if not result:
        return "No transactions to mine"
    else:
        
        # Making sure we have the longest chain before announcing to the network
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            # announce the recently mined block to the network
            announce_new_block(blockchain.last_block)
        
        return "Block #{} is mined.".format(blockchain.last_block.index)
    



    
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Add the node to the peer list
    peers.add(node_address)
    return get_chain()

@app.route('/cancel_invoice', methods=['POST'])
def cancel_invoice():
    data = request.get_json()
    irn_hash = data.get('irn_hash')
    reason = data.get('reason')
    
    if not irn_hash or not reason:
        return jsonify({"message": "Invalid data"}), 400

    success, message = blockchain.cancel_invoice(irn_hash, reason)
  
    if success:
        # Trigger mining to include the cancellation transaction
        mine_unconfirmed_transactions()
        return jsonify({"message": message}), 200
    else:
        return jsonify({"message": message}), 400

@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    # Make a request to register with remote node and obtain information
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        # update chain and the peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        return "Registration successful", 200
    else:
        # if something goes wrong, pass it on to the API response
        return response.content, response.status_code

@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    print("testing 1")
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    try:
        blockchain.add_block(block, proof)
    except ValueError as e:
        return "The block was discarded by the node: " + str(e), 400

    return "Block added to the chain", 201

@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)


def consensus():
   
    global blockchain
    

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
     
        response = requests.get(f'{node}/chain')
        if response.status_code == 200:
            length = response.json()['length']
            chain_data = response.json()['chain']

            # Convert chain_data to a list of Block objects
            chain = []
            for block_data in chain_data:
                block = Block(block_data["index"],
                            block_data["transactions"],
                            block_data["timestamp"],
                            block_data["previous_hash"],
                            block_data["nonce"])
                block.hash = block_data['hash']  # Set the hash
                chain.append(block) 
            
            if length > current_len and Blockchain.check_chain_validity(chain):
                current_len = length
                longest_chain = chain
       

    if longest_chain:
        blockchain.chain = longest_chain # Directly update blockchain.chain
        
        return True
    return False

def announce_new_block(block):
   
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        try:
            response = requests.post(url,
                                     data=json.dumps(block.__dict__, sort_keys=True),
                                     headers=headers)
            if response.status_code == 400:
                # The block was not accepted by the peer. Request the full blockchain from the peer.
                response = requests.get('{}chain'.format(peer))
                print("check1")
                if response.status_code == 200:
                    global blockchain
                    print("check2")
                    chain_dump = response.json()['chain']
                    blockchain = create_chain_from_dump(chain_dump)
        except Exception as e:
            print(f"Error: {e}. Could not send block to peer: {peer}")

def periodic_sync():
    while True:
        consensus()
        time.sleep(10)  # Sync every 10 seconds

sync_thread = threading.Thread(target=periodic_sync)
sync_thread.daemon = True
sync_thread.start()

if __name__ == "__main__":
    last_block_index = blockchain.last_block.index  # Initialize after blockchain is loaded
    app.run(host='0.0.0.0', debug=True, port=8000)

