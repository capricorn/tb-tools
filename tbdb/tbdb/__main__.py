import argparse

import tbdb

#print(tbdb.read_account_db)
# Maybe just option for decrypting db?
# Future could take csv and convert to db too
# (--decrypt and --encrypt)
parser = argparse.ArgumentParser()
parser.add_argument('database', 
        help='Specify the database to decrypt',
        type=str)
parser.add_argument('password', 
        help='Specify the database password ('' ifnot applicable)',
        type=str)
args = parser.parse_args()

#print(args.database)
#print(args.password == '')
data = tbdb.read_account_db(args.database, 
        None if args.password == '' else args.password)
print(tbdb.parse_db(data))
