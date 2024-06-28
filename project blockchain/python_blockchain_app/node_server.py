import os
import sys
import signal
import atexit
from hashlib import sha256
import json
import time
import threading
import hashlib

from flask import Flask, request, jsonify
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
    # _instance = None

    # def __new__(cls):
    #     if cls._instance is None:
    #         print('Creating the object')
    #         cls._instance = super(UniqueChecker, cls).__new__(cls)
    #         cls._instance.data_set = set()
    #         cls._instance.gst_set = set()  # Add a new set to store GST_No
    #     return cls._instance

    # def check_unique(self, data):
    #     data_string = json.dumps(data, sort_keys=True)
    #     gst_no = data.get('gst_no')  # Get the GST_No from the data
        
    #     print(f"Checking uniqueness for data: {data_string} and GST_No: {gst_no}")

    #     if data_string in self.data_set:
    #         print("Data already exists.")
    #         return False, "Error: Data already exists."
    #     elif gst_no and gst_no in self.gst_set:  # Check if GST_No already exists
    #         print("GST_No already exists.")
    #         return False, "Error: GST_No already exists."
    #     else:
    #         self.data_set.add(data_string)
    #         if gst_no:
    #             self.gst_set.add(gst_no)  # Add the GST_No to the set
    #         print("Data added successfully.")    
    #         return True, "Data added successfully."
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            print('Creating the object')
            cls._instance = super(UniqueChecker, cls).__new__(cls)
            cls._instance.irn_hashes = set()
        return cls._instance

    def generate_irn_hash(self, data):
        # irn = f"{data['gst_no']}{data['financial_year']}{data['document_type']}{data['document_number']}"
        # return hashlib.sha256(irn.encode()).hexdigest()
        if data.get('type') == 'deactivation':# Use original_irn_hash if it's a deactivation transaction
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
        """
        Function that tries different values of nonce to get a hash
        that satisfies our difficulty criteria.
        """
        # block.nonce = 0

        # computed_hash = block.compute_hash()
        # while not computed_hash.startswith('0' * Blockchain.difficulty):
        #     block.nonce += 1
        #     computed_hash = block.compute_hash()

        # return computed_hash
        return block.compute_hash()
    def add_new_transaction(self, transaction):
        # consensus()
        # success, message = self.unique_checker.check_unique(transaction)  # Check the uniqueness of the transaction
        # if not success:
        #     return message, 400  # Return an error message if the transaction is not unique
        # self.unconfirmed_transactions.append(transaction)
        # return "Success", 201
        consensus()  # Ensure we have the most up-to-date chain
        self.update_unique_checker()  # Update the unique checker with all transactions in the chain
        transaction['status'] = 'Active'
        success, message = self.unique_checker.check_unique(transaction)
        if not success:
            return message, 400
        self.unconfirmed_transactions.append(transaction)
        irn_hash = self.unique_checker.generate_irn_hash(transaction)
        return "Success", 201,irn_hash
    
    def deactivate_invoice(self, irn_hash, reason):
        # current_time = time.time()
        # for block in self.chain:
        #     for transaction in block.transactions:
        #         if self.unique_checker.generate_irn_hash(transaction) == irn_hash:
        #             if transaction.get('status') == 'Inactive':
        #                 return False, "Invoice is already inactive"
                    
        #             if current_time - transaction['timestamp'] <= 24 * 3600:  # 24 hours in seconds
        #                 deactivation_transaction = {
        #                 'type': 'deactivation',
        #                 'original_irn_hash': irn_hash,
        #                 'reason': reason,
        #                 'timestamp': current_time,
        #                 'status': 'Inactive',
        #                 'seller': "N/A", # Add dummy seller
        #                 'buyer': "N/A"  # Add dummy buyer
        #             }
        #             self.unconfirmed_transactions.append(deactivation_transaction)
        #             return True, "Deactivation transaction created successfully"
        #         else:
        #             return False, "Deactivation period has expired (more than 24 hours)"
        # return False, "Invoice not found"
        # def deactivate_invoice(self, irn_hash, reason):
        current_time = time.time()
        for block in self.chain:
            for transaction in block.transactions:
                if self.unique_checker.generate_irn_hash(transaction) == irn_hash:
                    if transaction.get('status') == 'Inactive':
                        return False, "Invoice is already inactive"

                    if current_time - transaction['timestamp'] <= 24 * 3600: 
                        deactivation_transaction = {
                            'type': 'deactivation',
                            'original_irn_hash': irn_hash,
                            'reason': reason,
                            'timestamp': current_time,
                            'status': 'Inactive',
                            'seller': "N/A", 
                            'buyer': "N/A"  
                        }
                        self.unconfirmed_transactions.append(deactivation_transaction)
                        return True, "Deactivation transaction created successfully"
                    else:
                        return False, "Deactivation period has expired (more than 24 hours)"

        return False, "Invoice not found"
    def update_unique_checker(self):
        self.unique_checker = UniqueChecker()  # Reset the unique checker
        for block in self.chain:
            for transaction in block.transactions:
                self.unique_checker.check_unique(transaction)  # Add all existing transactions to the checker

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        """
        Check if block_hash is valid hash of block and satisfies
        the difficulty criteria.
        """
        # return (block_hash.startswith('0' * Blockchain.difficulty) and
        #         block_hash == block.compute_hash())
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
        """
        This function serves as an interface to add the pending
        transactions to the blockchain by adding them to the block
        and figuring out Proof Of Work.
        """
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
            if transaction.get('type') == 'deactivation':
                self.update_invoice_status(transaction['original_irn_hash'], 'Inactive')

        self.unconfirmed_transactions = []

        return True

    def update_invoice_status(self, irn_hash, status):
        for block in self.chain:
            for transaction in block.transactions:
                if self.unique_checker.generate_irn_hash(transaction) == irn_hash:
                    transaction['status'] = status
                    return
                
    def get_invoice_status(self, irn_hash):
        # for block in reversed(self.chain):
        #     for transaction in reversed(block.transactions):
        #         if transaction.get('type') == 'deactivation' and transaction.get('original_irn_hash') == irn_hash:
        #             return 'Inactive'
        #         elif self.unique_checker.generate_irn_hash(transaction) == irn_hash:
        #             return transaction.get('status', 'Active')
        # return 'Not Found'
        for block in reversed(self.chain):
            for transaction in reversed(block.transactions):
                if transaction.get('type') == 'deactivation' and transaction['original_irn_hash'] == irn_hash:
                    return 'Inactive', transaction['reason'] # Return a tuple
                elif self.unique_checker.generate_irn_hash(transaction) == irn_hash:
                    return transaction.get('status', 'Active'), None  # Return a tuple
        return 'Not Found', None  # Return a tuple

app = Flask(__name__)

# the node's copy of blockchain
blockchain = None

# the address to other participating members of the network
peers = set()


# endpoint to submit a new transaction. This will be used by
# our application to add new data (posts) to the blockchain
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
    # generated_blockchain.chain=[]
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

        for tx in block_data["transactions"]:
            generated_blockchain.unique_checker.check_unique(tx)
    return generated_blockchain


# endpoint to return the node's copy of the chain.
# Our application will be using this endpoint to query
# all the posts to display.
@app.route('/chain', methods=['GET'])
def get_chain():
    print("Get chain")
    chain_data = []
    for block in blockchain.chain:
        # chain_data.append(block.__dict__)
        # block_dict = block.__dict__
        # block_dict['index'] = block.index
        # block_dict['transactions'] = block.transactions
        # block_dict['timestamp'] = block.timestamp
        # block_dict['previous_hash'] = block.previous_hash
        # block_dict['hash'] = block.hash 
        # chain_data.append(block_dict)
        block_dict = {
            'index': block.index,
            'transactions': block.transactions,
            'timestamp': block.timestamp,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'nonce': block.nonce
        }
        for transaction in block_dict['transactions']:
            if transaction.get('type') != 'deactivation':
                irn_hash = blockchain.unique_checker.generate_irn_hash(transaction)
                # transaction['status']= blockchain.get_invoice_status(irn_hash)
                status, deactivation_reason = blockchain.get_invoice_status(irn_hash) # Unpack both values
                transaction['status'] = status
                transaction['deactivation_reason'] = deactivation_reason  # Add deactivation reason
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


# endpoint to request the node to mine the unconfirmed
# transactions (if any). We'll be using it to initiate
# a command to mine from our application itself.
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


# endpoint to add new peers to the network.
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Add the node to the peer list
    peers.add(node_address)

    # Return the consensus blockchain to the newly registered node
    # so that he can sync
    return get_chain()

@app.route('/deactivate_invoice', methods=['POST'])
def deactivate_invoice():
    data = request.get_json()
    irn_hash = data.get('irn_hash')
    reason = data.get('reason')
    
    if not irn_hash or not reason:
        return jsonify({"message": "Invalid data"}), 400

    success, message = blockchain.deactivate_invoice(irn_hash, reason)
    if success:
        # Trigger mining to include the deactivation transaction
        mine_unconfirmed_transactions()
        return jsonify({"message": message}), 200
    else:
        return jsonify({"message": message}), 400

@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to
    register current node with the node specified in the
    request, and sync the blockchain as well as peer data.
    """
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


# endpoint to add a block mined by someone else to
# the node's chain. The block is first verified by the node
# and then added to the chain.
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


# endpoint to query unconfirmed transactions
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)




def consensus():
    """
    Our naive consnsus algorithm. If a longer valid chain is
    found, our chain is replaced with it.
    """
    # global blockchain

    # longest_chain = None
    # current_len = len(blockchain.chain)

    # for node in peers:
    #     response = requests.get('{}chain'.format(node))
    #     length = response.json()['length']
    #     chain = response.json()['chain']
    #     if length > current_len and blockchain.check_chain_validity(chain):
    #         current_len = length
    #         longest_chain = chain

    # if longest_chain:
    #     blockchain = longest_chain
    #     return True

    # return False
    
    # global blockchain
    # longest_chain = None
    # current_len = len(blockchain.chain)
    # for node in peers:
    #     response = requests.get(f'{node}/chain')
    #     if response.status_code == 200:
    #         length = response.json()['length']
    #         chain = response.json()['chain']
    #         if length > current_len and Blockchain.check_chain_validity(chain):
    #             current_len = length
    #             longest_chain = chain
    # if longest_chain:
    #     blockchain = create_chain_from_dump(longest_chain)
    #     return True
    # return False
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
    """
    A function to announce to the network once a block has been mined.
    Other blocks can simply verify the proof of work and add it to their
    respective chains.
    """
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

# Uncomment this line if you want to specify the port number in the code

def periodic_sync():
    while True:
        consensus()
        time.sleep(10)  # Sync every 60 seconds

sync_thread = threading.Thread(target=periodic_sync)
sync_thread.daemon = True
sync_thread.start()

if __name__ == "__main__":
    app.run(host ='0.0.0.0', debug=True, port=8000)
