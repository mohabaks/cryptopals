#!/usr/bin/python
# Author:       https://github.com/mohabaks
# Description:  Cryptopals crypto challenges solutions
import binascii


def hex_to_base64(hex_string):
    """Convert hex to base64
    This function convert hex to base64

    Parameters
    ----------
    string : str
        hex string to be converted

    Returns
    -------
    base64_string
        A base64 string

    """
    unhexlify = binascii.unhexlify(hex_string)
    base64_string = binascii.b2a_base64(unhexlify)

    return base64_string


def fixed_xor(string1, string2):
    """Fixed XOR
    This function takes two equal-length buffers and produces their XOR
    combination.

    Parameters
    ----------
    string1 : str
        1st hex string buffer
    string2 : str
        2nd hex string buffer

    Returns
    -------
    xor_result
        Return XOR of two hex strings.

    """
    if len(string1) != len(string2):
        print("Two hex strings are not of equal-length")
        exit(1)
    else:
        unhexlify_string1 = binascii.unhexlify(string1)
        unhexlify_string2 = binascii.unhexlify(string2)
        xor_result = bytes(a ^ b for a, b in zip(unhexlify_string1,
                                                 unhexlify_string2))

        return binascii.hexlify(xor_result)


def single_byte_xor_cipher(string, key):
    """Sigle byte XOR cipher
    This function take a string and XOR'd against a single character.

    Parameters
    ----------
    string : str
        hex string to be xor
    key : int
        key used to XOR'd

    Return
    ------
    xor_result
        Return XOR'd string

    """
    xor_result = b''
    unhexlify_string = binascii.unhexlify(string)
    for byte in unhexlify_string:
        xor_result += bytes([byte ^ key])

    return xor_result


def english_frequency_score(input_bytes):
    """Compare each input byte to a character frequency
    This function returns the score of a message based on the relative
    frequency; the characters that occurs in the English language

    Parameters
    ----------
    input_bytes : bytes
        Input bytes to be compared with character frequency

    Returns
    -------
    score
        Return score of the input bytes

    """
    char_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

    scores = sum([char_frequencies.get(chr(byte), 0) for byte in input_bytes
                  .lower()])

    return scores


def brute_single_byte_xor_cipher(string):
    """Break single byte XOR cipher
    This function break single byte XOR cipher by brute-focing the key using
    frequency analysis.

    Parameters
    ----------
    string : str
        The cipher text

    Returns
    -------
    key
        Return the key used to create the cipher text
    message
        Return decrypted message

    """
    potential_msg = [] # list of potential messages
    for key in range(1, 256):
        msg = single_byte_xor_cipher(string, key)
        score = english_frequency_score(msg)
        xor_result = {
            'plaintext': msg,
            'score': score,
            'key': key
        }
        potential_msg.append(xor_result)

    # get best score by
    # sorting the list of potential messages
    best_score = sorted(potential_msg, key=lambda k: k['score'], reverse=True)\
        [0]
    key = chr(best_score.get('key')) # Character used for XOR'd
    score = best_score.get('score')
    message = best_score.get('plaintext') # decrypted message

    return [message, key, score]


def detect_single_char_xor(input_file):
    """Detect single character XOR
    This function detect a single character XOR cipher in a file

    Parameters
    ----------
    input_file : bytes
        File with encrypted strings

    Returns
    --------
    message
        Return decrypted message
    key
        Return key used to encrypt the message
    cipher
        Return the single-character XOR cipher from the file

    """
    # open the file with encrypted strings
    # input_file e.g 4.txt
    with open(input_file) as lines:
        ciphers = lines.read().splitlines() # store ciphers

    potential_msg = []
    for cipher in ciphers:
        # store results in a dic
        cipher_result = {
            'message': brute_single_byte_xor_cipher(cipher)[0],
            'key': brute_single_byte_xor_cipher(cipher)[1],
            'score': brute_single_byte_xor_cipher(cipher)[2],
            'cipher': cipher
        }
        potential_msg.append(cipher_result)

    # get the best score from potential_msg
    best_score = sorted(potential_msg, key=lambda x: x['score'], reverse=True)\
        [0]
    message = best_score.get('message')
    key = best_score.get('key')
    cipher = best_score.get('cipher')

    return [message, key, cipher]


def repeating_key_xor(input_file, key):
    """Repeating key XOR
    This function encrypt a file contents using a repeating-key XOR by
    sequentially applying the byte of the key

    Parameters
    ----------
    input_file : bytes
        bytes to be XOR'd
    key : str
        XOR key

    Returns
    -------
    cipher
        Return the XOR'd cipher

    """
    # read the file with contents
    # to be encrypted
    with open(input_file) as lines:
        data = lines.read().rstrip('\n')
    # initialized variables
    cipher = b'' # encrypted message
    index = 0 # key index
    data = bytes(data, 'utf-8') # convert str to bytes
    key = bytes(key, 'utf-8') # convert str to bytes
    for byte in data:
        cipher += bytes([byte ^ key[index]])
        # reset the key index
        if (index + 1) == len(key):
            index = 0
        else:
            index += 1
    cipher = binascii.hexlify(cipher)

    return cipher


def decrypt_repeating_key_xor(cipher_msg, key):
    """Decrypt repeating key XOR
    This function decrypt a cipher encrypted using a repeating XOR key

    NOTE: This function is not part of the cryptopals crypto challenges.

    Parameters
    ----------
    cipher_msg : str
        cipher message to be decrypted
    key : str
        key used to encrypt the message

    Returns
    -------
    plaintext
        Return the plaintext message

    """
    key = bytes(key, 'utf-8')
    index = 0 # key index
    plaintext = b''
    for byte in binascii.unhexlify(cipher_msg):
        plaintext += bytes([byte ^ key[index]])
        if (index + 1) == len(key):
            index = 0
        else:
            index += 1
    plaintext = plaintext.decode('ascii')

    return plaintext


def hamming_distance(str1, str2):
    """ Compute hamming distance
    This function compute the hamming distance between two strings. The
    hamming distance is the number of bit position in which the two bits
    are different.

    Parameters
    ----------
    str1 : str
        1st string
    str2 : str
        2nd string

    Returns
    -------
    hamming_distance
        Return hamming distance
    """
    if len(str1) != len(str2):
        exit(1)
    else:
        # convert strings to binary
        binary_str1 = bin(int(binascii.hexlify(bytes(str1, 'utf-8')), 16))[2:]
        binary_str2 = bin(int(binascii.hexlify(bytes(str2, 'utf-8')), 16))[2:]
        # calculate hamming distance
        # total number of 1s gives the hamming distance
        hamming_distance = bin(int(binary_str1, 2) ^ int(binary_str2, 2))[2:]\
                .count('1')

    return hamming_distance


if __name__ == '__main__':
    pass
