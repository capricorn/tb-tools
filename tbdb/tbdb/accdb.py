from Crypto.Hash import SHA1
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad 
from Crypto.Util.Padding import unpad as removepad
import base64

'''
The only reason we must add padding is that the python
library does not transparently handle it; java does,
which is why we don't have to manually add or strip padding.
'''

# For some reason, doesn't seem to use standard padding?
# One approach is just to handle last !!
def unpad(data):
    for i in range(len(data)-1, 0, -1):
        #print(i)
        if data[i] == ord('!') and data[i-1] == ord('!'):
            return data[0:i+1]

    return data

def read_account_db(filename, password=None):
    data = ''
    with open(filename, 'rb') as f:
        data = f.read()

    if password:
        return decrypt_pass(data, password)

    return decrypt_nopass(data)

def decrypt_nopass(data):
    salt = '584E07C4BGqO3alR9zSQtda3uChdbRZLNd'
    key = SHA1.new(salt.encode('utf-8')).digest()[0:16]
    # Only requires a key, nothing else.
    # (Next, try it with an added password)
    plaintext = AES.new(key, AES.MODE_ECB).decrypt(data)
    #print(f'plaintext: {plaintext}')
    return unpad(plaintext).decode('utf-8')

# Maybe there is something wrong with my decrypt pass code.. (has to be)
# Otherwise, no way java would nicely strip padding
def decrypt_pass(data, password):
    '''
    You would think that, if we first encrypt with password, and
    then encrypt with hash, that we would want to decrypt first with
    hash, and then with the password?
    '''
    #print(len(data))
    salt = '584E07C4BGqO3alR9zSQtda3uChdbRZLNd'

    key = SHA1.new(password.encode('utf-8')).digest()[0:16]
    round1 = AES.new(key, AES.MODE_ECB).decrypt(data)
    #print(f'round1: {round1}')

    # Remove padding here?
    round1 = removepad(round1, 16)

    key = SHA1.new(salt.encode('utf-8')).digest()[0:16]
    round2 = AES.new(key, AES.MODE_ECB).decrypt(round1)

    # Remove padding here..? And then repad?
    round2 = removepad(round2, 16)
    #print(round2)
    #round1 = pad(round1, 16)

    

    # 18 bytes appended to data.. sounds familiar

    return round2.decode('utf-8')
    #return round2[:-18].decode('utf-8')
    #return unpad(round2).decode('utf-8')

# list of these
# entries = { 'username': 'password': , 'pin': , 'world':, 'skill' }
'''
def add_entry(db, entries):
    pass

def delete_entry(db, entries):
    pass
'''

# Next, try to write the password protected version. Should be password applied,
# and then hash applied.
# However, decryption seems to work by first decrypting with the pass,
# and then decrypting with the hash.. (see java code)
# Everything writes properly with the hash only pass; just need to fix applying
# a password
# Would be best if extension is handled by you (append .dat2 if password encrypted)
def write_entries(db, filename, password=None):
    salt = '584E07C4BGqO3alR9zSQtda3uChdbRZLNd'

    accounts = [ (acc['username'], acc['password'], acc['pin'], acc['world'], acc['skill']) for acc in db ]

    encoded_db = '!!'
    for acc in accounts:
        encoded_db += '@@'.join([ base64.b64encode(entry.encode('utf8')).decode('utf8') for entry in acc ]) + '!!'

    #print(encoded_db)
    #print(len(encoded_db))
    # Adding an extra block I guess.. (maybe this is a requirement of the standard anyways?)
    encoded_db = pad(encoded_db.encode('utf8'), 16)
    #print(encoded_db)
    #encoded_db += (16 - (len(encoded_db)%16)) * 'A'
    #print(len(encoded_db))
    data = encoded_db

    key = SHA1.new(salt.encode('utf-8')).digest()[0:16]
    data = AES.new(key, AES.MODE_ECB).encrypt(data)

    if password:
        data = pad(data, 16)
        key = SHA1.new(password.encode('utf-8')).digest()[0:16]
        data = AES.new(key, AES.MODE_ECB).encrypt(data)

    with open(filename, 'wb') as f:
        f.write(data)

def parse_db(db):
    data = db
    #print(data)
    # Maybe there is a beginning entry that is 
    # unnecessary?
    data = data.split('!!')[1:-1]   # Not sure whether this holds all the time

    for account in data:
        entries = account.split('@@')
        for entry in entries:
            print(base64.b64decode(entry))
        print('')

if __name__ == '__main__':
    #db = read_account_db('501141-accounts.dat')
    db = read_account_db('501141-accounts.dat2', 'greentoad')
    #db = read_account_db('test.dat2', 'greentoad')
    print(db)
    #db = read_account_db('test.dat')
    parse_db(db)

    # Write entries in this format
    new_db = [
        {
            'username': 'example@gmail.com',
            'password': 'pass123',
            'pin':  '1414',
            'world': '1',
            'skill': 'Mining'
        }
    ]
