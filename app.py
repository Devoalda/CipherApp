import io
import base64

from flask import Flask, render_template, request, jsonify

from Ciphers.CaesarCipher.CaesarCipher import CaesarCipher

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('base.html')


@app.route('/b64', methods=['POST'])
def b64():
    if 'b64_plaintext_input' in request.form:
        text = request.form['b64_plaintext_input']
        ciphertext_input = False
    elif 'b64_ciphertext_input' in request.form:
        text = request.form['b64_ciphertext_input']
        ciphertext_input = True
    else:
        return jsonify({'error': 'No input provided'})

    result = {}
    if ciphertext_input:
        base64_bytes = text.encode("ascii")
        sample_string_bytes = base64.b64decode(base64_bytes)
        result['cleartext'] = str(sample_string_bytes, "ascii")
    else:
        sample_string_bytes = text.encode("ascii")
        base64_bytes = base64.b64encode(sample_string_bytes)
        # print(f'Encoded string: {base64_bytes.decode("ascii")}')
        result['ciphertext'] = str(base64_bytes.decode("ascii"))

    return jsonify(result)


@app.route('/encrypt_decrypt', methods=['POST'])
def encrypt_decrypt():
    if 'plaintext_input' in request.form:
        text = request.form['plaintext_input']
        ciphertext_input = False
    elif 'ciphertext_input' in request.form:
        text = request.form['ciphertext_input']
        ciphertext_input = True
    else:
        return jsonify({'error': 'No input provided'})

    key = int(request.form['key'])

    result = {}
    if ciphertext_input:
        pad_file = request.files.get('pad_file')
        if pad_file:
            pad = io.StringIO(pad_file.stream.read().decode('utf-8'))
            cipher = CaesarCipher(shift=key, use_pad=True, file=pad)
        else:
            cipher = CaesarCipher(shift=key, use_pad=False)

        result['cleartext'] = cipher.decrypt(text)

        if pad_file:
            pad.seek(0)
            new_cipher = CaesarCipher(shift=key, use_pad=True, file=pad)
            encrypted_text = new_cipher.encrypt(result['cleartext'])
        else:
            new_cipher = CaesarCipher(shift=key, use_pad=False)
            encrypted_text = new_cipher.encrypt(result['cleartext'])

        result['ciphertext'] = encrypted_text
    else:
        pad_file = request.files.get('pad_file')
        if pad_file:
            pad = io.StringIO(pad_file.stream.read().decode('utf-8'))
            cipher = CaesarCipher(shift=key, use_pad=True, file=pad)
        else:
            cipher = CaesarCipher(shift=key, use_pad=False)

        result['ciphertext'] = cipher.encrypt(text)

        if pad_file:
            pad.seek(0)
            new_cipher = CaesarCipher(shift=key, use_pad=True, file=pad)
            decrypted_text = new_cipher.decrypt(result['ciphertext'])
        else:
            new_cipher = CaesarCipher(shift=key, use_pad=False)
            decrypted_text = new_cipher.decrypt(result['ciphertext'])

        result['cleartext'] = decrypted_text

    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
