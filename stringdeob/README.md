# TRiBot deobfuscation / RE

This project contains utilities for decrypting strings in the
TRiBot jar, and also code that demonstrates how user databases
are decrypted.

### String deobfuscation

The TRiBot client, at least at the time of writing this program,
used an obfuscator that encrypted all strings in the jar classes.

##### How strings are obfuscated

The encryption itself is fairly naive. Any time a string appears,
the obfuscator replaces the string with the encrypted version. 
Next, the obfuscator replaces any references to this string
with a static method call, which takes the encrypted string
as input and returns the decrypted string as output. Now, the constant
pool is full of encrypted strings, which makes it a little more difficult to 
obtain information about the class.

##### How to deobfuscate strings

The deobfuscator I wrote works as follows. First, locate all static methods 
with the method signature `(Ljava/lang/Object;)Ljava/lang/String;`. This is
the signature used for string encryption routines. An implementation is
found in `CustomClassVisitor`. Next, iterate through every method in every 
class. Look for the following bytecode sequence:

```
LDC string_idx
INVOKESTATIC ...
```

If the `invokestatic` arguments happen to match one of the static methods
located initially, then use reflection to call the method. I did this by
creating a classloader that loads and finds methods from the TRiBot jar. For
example, you can do

```java
ClassLoader tbLoader;
...
Method m = tbLoader.getDeclaredMethod(decryptMethodName, Object.class);
String decrypted = m.invoke(null, encryptedString);
```

At this point, the decrypted string can be printed or written back to the
class. Overwriting (and printing) is implemented in 
`Main.removeEncryptedStrings`.


### Database decryption

TRiBot offers the ability to store bot credentials in a database. This
database can optionally be created with a password, which adds an extra
layer of protection. Note the following was only verified on my client; it
is possible the presented key is different.

The goal was to understand the database implementation so the database
could be updated programmatically.

##### Database types

TRiBot uses two file extensions for its databases. Here is what they mean:

```
.dat  = not password protected
.dat2 = password protected
```

##### Decrypted database format

Here is the basic grammar for the decrypted database:

```
file  -> !!entry
entry -> entryentry
entry -> base64(username)@@base64(password)@@base64(pin)@@base64(world)@@base64(skill)!!
```

Entries in the database are delimited by `!!`. An entry represents an account. The
columns in an entry are `username, password, pin, world, skill`. All of these are strings, so
`skill` would be `Mining`, for example. Entry columns are delimited by `@@`. Every entry
column is base64 encoded.

##### Decryption / Encryption

For an implementation, see `accdb.py`. Here is how it works, in python-like pseudocode.
Note that the TRiBot client at the time used the ECB cipher for operation. It is possible
that this could vary from machine to machine, since the encryption routines seem to
depend on the java implementation.. so you may have to experiment with that if things
don't work.

##### Padding

Data is padded before encryption, and hence contains padding after decryption. Padding doesn't appear to use a standard method (or at least I have the wrong method). Issue is in python.

Right now, just stripping any data the follows after the last `!!`. This is not a problem with java.

I am worried tribot will not accept my encrypted input if it uses a different padding scheme..

##### Decryption

Without a password:

```python
hash = 584E07C4BGqO3alR9zSQtda3uChdbRZLNd
key = sha1(utf8(hash))[0:16]
data = aes128(key, ECB).decrypt(encrypted_data)
data = unpad(data, 'pkcs7')
```

With a password (encrypted twice):

```python
hash = 584E07C4BGqO3alR9zSQtda3uChdbRZLNd

key = sha1(utf8(password))[0:16]
data = aes128(key, ECB).decrypt(encrypted_data)
data = unpad(data, 'pkcs7')

key = sha1(utf8(hash))[0:16]
data = aes128(key, ECB).decrypt(data)
data = unpad(data, 'pkcs7')
```

##### Encryption

Without a password:

```
hash = 584E07C4BGqO3alR9zSQtda3uChdbRZLNd
encoded_string = 'your encoded account data'

data = pad(encoded_string, 'pkcs7')
key = sha1(utf8(hash))[0:16]
encrypted_data = aes128(key, ECB).encrypt(data)
```

With a password:

```
hash = 584E07C4BGqO3alR9zSQtda3uChdbRZLNd
encoded_string = 'your encoded account data'

data = pad(encoded_string, 'pkcs7')
key = sha1(utf8(hash))[0:16]
encrypted_data = aes128(key, ECB).encrypt(data)

encrypted_data = pad(encrypted_data, 'pkcs7')
key = sha1(utf8(password))[0:16]
encrypted_data = aes128(key, ECB).encrypt(encrypted_data)
```
