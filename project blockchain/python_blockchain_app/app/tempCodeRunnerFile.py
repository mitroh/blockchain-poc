import os
import sys
import signal
import atexit
from hashlib import sha256
import time

from flask import Flask, request
import requests