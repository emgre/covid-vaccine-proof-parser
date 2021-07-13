# Proof of COVID-19 vaccination parser for Québec
# https://www.quebec.ca/en/health/health-issues/a-z/2019-coronavirus/progress-of-the-covid-19-vaccination/proof-covid-19-vaccination
# 
# Copyright 2021 Émile Grégoire

import base64
import cv2
import json
from pyzbar import pyzbar
import zlib

im = cv2.imread('vaccin.png')

barcodes = pyzbar.decode(im)

if not barcodes:
    print('No QR code detected')
    exit(-1)

for barcode in barcodes:
    data = barcode.data
    print(f'QR code payload: {data}\n')

    if not data.startswith(b'shc:/'):
        print('QR code does not contain SMART Health Card data')
        exit(-1)

    # There's a chunk algorithm, but I didn't bothered to implement it.
    # My QR code has a single chunk of data
    payload = data[5:]

    jws_token = ''
    # Group by two to recreate the ASCII value
    it = iter(payload)
    for x, y in zip(it, it):
        # Recreate the ASCII value
        ascii_value = chr(x) + chr(y)
        
        # Parse the ASCII value
        value = int(ascii_value)

        # Convert it to base64
        base64_value = chr(value + 45)

        # Append it to the base64 payload
        jws_token += base64_value
    
    print(f'JWT token: {jws_token}\n')

    # Parse the JWS token
    [header, payload, signature] = jws_token.split('.')

    # Pad the different part of the JWT token
    def padded_base64(data):
        return data + "=" * (4 - divmod(len(payload),4)[1])

    header = padded_base64(header)
    payload = padded_base64(payload)
    signature = padded_base64(payload)

    print(f'JWS header: {base64.urlsafe_b64decode(header)}\n')
    print(f'JWS signature: {base64.urlsafe_b64decode(signature)}\n')

    # Decode the base64 value
    compressed_payload = base64.urlsafe_b64decode(payload)

    # Uncompress the data
    dc = zlib.decompressobj(-15)
    raw_payload = dc.decompress(compressed_payload)

    # Parse the string
    str_payload = raw_payload.decode('utf-8')

    # Parse the value as JSON to pretty-print it
    json_payload = json.loads(str_payload)
    print(json.dumps(json_payload, indent=2))
