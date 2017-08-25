# coding: utf-8
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import division

import hashlib

from Crypto.Cipher import ARC4, AES


def _rc4_encrypt(key, text):
    rc4 = ARC4.ARC4Cipher(key)
    return rc4.encrypt(text)

def _rc4_decrypt(key, text):
    rc4 = ARC4.ARC4Cipher(key)
    return rc4.decrypt(text)

def _aes_encrypt(key, text, iv):
    p = (16 - len(text) % 16)
    text = text + bytes(bytearray([p for _ in range(p)]))
    aes = AES.AESCipher(key, AES.MODE_CBC, iv)
    return aes.encrypt(text)

def _aes_decrypt(key, text, iv):
    aes = AES.AESCipher(key, AES.MODE_CBC, iv)
    d = aes.decrypt(text)
    try:
        return d[:-d[-1]]
    except:
        return d[:-ord(d[-1])]


_encryption_padding = b'\x28\xbf\x4e\x5e\x4e\x75\x8a\x41\x64\x00\x4e\x56' + \
        b'\xff\xfa\x01\x08\x2e\x2e\x00\xb6\xd0\x68\x3e\x80\x2f\x0c' + \
        b'\xa9\xfe\x64\x53\x69\x7a'


def _padding(text):
    return (text + _encryption_padding)[:32]


class Encryption:
    def __init__(self, encryption_dict, first_id_entry):
        self.entries = {k: encryption_dict[k] for k in encryption_dict}
        self.id_entry = first_id_entry
        self._keys = {}
        self._authed_password = None
        self._method = "/V2"  # RC4
        self._check_crypt_method()

    def is_encrypted(self):
        return len(self.entries) != 0

    def is_metadata_encrypted(self):
        if not self.is_encrypted():
            return False
        enc_metadata = self.entries.get("/EncryptMetadata")
        if not enc_metadata:
            return True
        return enc_metadata.value

    def has_key(self):
        return bool(self._authed_password is not None)

    def _check_crypt_method(self):
        if not self.is_encrypted():
            return
        if self.entries["/Filter"] != '/Standard':
            raise NotImplementedError("only Standard PDF encryption handler is available")
        cf = self.entries.get("/CF")
        if cf:
            std_cf = cf.get("/StdCF")
            if not std_cf:
                raise NotImplementedError("only StdCF Crypt Filter handler is available")
            cfm = std_cf["/CFM"]
            self._method = cfm


    def decrypt_data(self, data, idnum, generation):
        import struct
        pack1 = struct.pack("<i", idnum)[:3]
        pack2 = struct.pack("<i", generation)[:2]

        n = 5 if self.entries["/V"] == 1 else self.entries["/Length"] // 8
        key_data = self._keys[self._authed_password][:n] + pack1 + pack2
        key_hash = hashlib.md5(key_data)
        if self._method == "/AESV2":
            key_hash.update(b"sAlT")
        key_hash_digest = key_hash.digest()[:min(n + 5, 16)]

        if self._method == "/AESV2":
            return _aes_decrypt(key_hash_digest, data[16:], data[:16])
        else:
            return _rc4_decrypt(key_hash_digest, data)

    def computing_encryption_key(self, password):
        """

        :param password:
        :return:
        """
        password = bytes(password)
        if password in self._keys:
            return self._keys[password]
        """
            Algorithm 3.2 Computing an encryption key
            """
        """1. Pad or truncate the password string to exactly 32 bytes. If the password string is
        more than 32 bytes long, use only its first 32 bytes; if it is less than 32 bytes long,
        pad it by appending the required number of additional bytes from the beginning
        of the following padding string:
            < 28 BF 4E 5E 4E 75 8A 41 64 00 4E 56 FF FA 01 08
            2E 2E 00 B6 D0 68 3E 80 2F 0C A9 FE 64 53 69 7A >
        That is, if the password string is n bytes long, append the first 32 − n bytes of the
        padding string to the end of the password string. If the password string is empty
        (zero-length), meaning there is no user password, substitute the entire padding
        string in its place."""
        password_pad = _padding(password)
        """2. Initialize the MD5 hash function and pass the result of step 1 as input to this function."""
        ps_hash = hashlib.md5(password_pad)
        """3. Pass the value of the encryption dictionary’s O entry to the MD5 hash function."""
        ps_hash.update(self.entries["/O"])
        """4. Treat the value of the P entry as an unsigned 4-byte integer and pass these bytes to
        the MD5 hash function, low-order byte first."""
        import struct
        p_entry = struct.pack('<i', self.entries["/P"])
        ps_hash.update(p_entry)
        """5. Pass the first element of the file’s file identifier array (the value of the ID entry in
        the document’s trailer dictionary; see Table 3.13 on page 97) to the MD5 hash function."""
        ps_hash.update(self.id_entry)
        rev = self.entries["/R"]
        """6. (Revision 4 or greater) If document metadata is not being encrypted, pass 4 bytes
        with the value 0xFFFFFFFF to the MD5 hash function."""
        if rev >= 4 and not self.is_metadata_encrypted():
            ps_hash.update(b"\xff\xff\xff\xff")
        """7. Finish the hash."""
        ps_hash_digest = ps_hash.digest()
        """8. (Revision 3 or greater) Do the following 50 times: Take the output from the previous
        MD5 hash and pass the first n bytes of the output as input into a new MD5
        hash, where n is the number of bytes of the encryption key as defined by the value
        of the encryption dictionary’s Length entry."""
        hash_len = 5
        if rev >= 3:
            hash_len = self.entries["/Length"] // 8
            for _ in range(50):
                ps_hash_digest = hashlib.md5(ps_hash_digest[:hash_len]).digest()
        """9. Set the encryption key to the first n bytes of the output from the final MD5 hash,
        where n is always 5 for revision 2 but, for revision 3 or greater, depends on the value of 
        the encryption dictionary’s Length entry."""
        key = ps_hash_digest[:hash_len]
        self._keys[password] = key
        return key


    def computer_owner_value(self, user_password, owner_password=None):
        """

        :param user_password:
        :param owner_password:
        :return:
        """
        """
        Algorithm 3.3 Computing the encryption dictionary’s O (owner password) value
        """
        """1. Pad or truncate the owner password string as described in step 1 of Algorithm 3.2.
        If there is no owner password, use the user password instead."""
        if not owner_password:
            owner_password = user_password
        owner_password = _padding(owner_password)
        """2. Initialize the MD5 hash function and pass the result of step 1 as input to this function."""
        ps_hash_digest = hashlib.md5(owner_password).digest()
        ps_key_len = 5
        """3. (Revision 3 or greater) Do the following 50 times: Take the output from the previous
        MD5 hash and pass it as input into a new MD5 hash."""
        rev = self.entries["/R"]
        if rev >= 3:
            for _ in range(50):
                ps_hash_digest = hashlib.md5(ps_hash_digest).digest()
            ps_key_len = self.entries["/Length"]
        """4. Create an RC4 encryption key using the first n bytes of the output from the final
        MD5 hash, where n is always 5 for revision 2 but, for revision 3 or greater, depends
        on the value of the encryption dictionary’s Length entry."""
        ps_key = ps_hash_digest[:ps_key_len]
        """5. Pad or truncate the user password string as described in step 1 of Algorithm 3.2."""
        user_password = _padding(user_password)
        """6. Encrypt the result of step 5, using an RC4 encryption function with the encryption key obtained in step 4."""
        value = _rc4_encrypt(ps_key, user_password)
        """7. (Revision 3 or greater) Do the following 19 times: Take the output from the previous
        invocation of the RC4 function and pass it as input to a new invocation of the
        function; use an encryption key generated by taking each byte of the encryption
        key obtained in step 4 and performing an XOR (exclusive or) operation between
        that byte and the single-byte value of the iteration counter (from 1 to 19)."""
        if rev >= 3:
            for i in range(1, 20):
                new_key = bytes(bytearray([x ^ i for x in bytearray(ps_key)]))
                value = _rc4_encrypt(new_key, value)
        """8. Store the output from the final invocation of the RC4 function as the value of
        the O entry in the encryption dictionary."""
        return value


    def computer_user_value(self, user_password):
        """

        :param user_password:
        :return:
        """
        """
        Algorithm 3.4 Computing the encryption dictionary’s U (user password) value (Revision 2)
        1. Create an encryption key based on the user password string, as described in Algorithm 3.2.
        2. Encrypt the 32-byte padding string shown in step 1 of Algorithm 3.2, using an
            RC4 encryption function with the encryption key from the preceding step.
        3. Store the result of step 2 as the value of the U entry in the encryption dictionary.

        Algorithm 3.5 Computing the encryption dictionary’s U (user password) value (Revision 3or greater)
        1. Create an encryption key based on the user password string, as described in Algorithm 3.2.

        """
        key = self.computing_encryption_key(user_password)
        rev = self.entries["/R"]
        if rev == 2:
            value = _rc4_encrypt(key, _encryption_padding)
            return value

        """2. Initialize the MD5 hash function and pass the 32-byte padding string shown in step 1
        of Algorithm 3.2 as input to this function."""
        ps_hash = hashlib.md5(_encryption_padding)
        """3. Pass the first element of the file’s file identifier array (the value of the ID entry in
        the document’s trailer dictionary; see Table 3.13 on page 97) to the hash function and finish the hash."""
        ps_hash.update(self.id_entry)
        ps_hash_digest = ps_hash.digest()
        """4. Encrypt the 16-byte result of the hash, using an RC4 encryption function with the encryption key from step 1."""
        data = _rc4_encrypt(key[:16], ps_hash_digest[:16])
        """5. Do the following 19 times: Take the output from the previous invocation of the
        RC4 function and pass it as input to a new invocation of the function; use an encryption
        key generated by taking each byte of the original encryption key (obtained in step 1) and
        performing an XOR (exclusive or) operation between that byte and the single-byte value of
        the iteration counter (from 1 to 19)."""
        for i in range(1, 20):
            new_key = bytes(bytearray([x ^ i for x in bytearray(key)]))
            data = _rc4_encrypt(new_key, data)
        """6. Append 16 bytes of arbitrary padding to the output from the final invocation of the RC4 function
         and store the 32-byte result as the value of the U entry in the encryption dictionary."""
        value = _padding(data)
        return value

    def authenticating_user_password(self, user_password):
        """

        :param user_password:
        :return:
        """
        """
        Algorithm 3.6 Authenticating the user password
        1. Perform all but the last step of Algorithm 3.4 (Revision 2) or Algorithm 3.5
            (Revision 3 or greater) using the supplied password string.
        2. If the result of step 1 is equal to the value of the encryption dictionary’s U entry
            (comparing on the first 16 bytes in the case of Revision 3 or greater), the password
            supplied is the correct user password. The key obtained in step 1 (that is, in the
            first step of Algorithm 3.4 or 3.5) can be used to decrypt the document using Algorithm 3.1 on page 119.
        """
        u_value = self.computer_user_value(user_password)
        u_entry = self.entries["/U"]
        rev = self.entries["/R"]
        if rev >= 3:
            u_value = u_value[:16]
            u_entry = u_entry[:16]
        if u_value == u_entry:
            self._authed_password = user_password
            return True
        return False


    def authenticating_owner_password(self, owner_password):
        """

        :param owner_password:
        :return:
        """
        """
        Algorithm 3.7 Authenticating the owner password
        1. Compute an encryption key from the supplied password string, as described in steps 1 to 4 of Algorithm 3.3.
        2. (Revision 2 only) Decrypt the value of the encryption dictionary’s O entry, using
            an RC4 encryption function with the encryption key computed in step 1.
            (Revision 3 or greater) Do the following 20 times: Decrypt the value of the encryp-tion
            dictionary’s O entry (first iteration) or the output from the previous iteration
            (all subsequent iterations), using an RC4 encryption function with a different en-
            cryption key at each iteration. The key is generated by taking the original key (ob-tained in step 1)
            and performing an XOR (exclusive or) operation between each
            byte of the key and the single-byte value of the iteration counter (from 19 to 0).
        3. The result of step 2 purports to be the user password. Authenticate this user password
            using Algorithm 3.6. If it is correct, the password supplied is the correct owner password.
        """
        key = self.computing_encryption_key(owner_password)
        o_entry = self.entries["/O"]
        rev = self.entries["/R"]
        if rev == 2:
            password = _rc4_decrypt(key, o_entry)
        else:
            for i in range(19, -1, -1):
                new_key = bytes(bytearray([x ^ i for x in bytearray(key)]))
                o_entry = _rc4_decrypt(new_key, o_entry)
            password = o_entry
        return self.authenticating_user_password(password)
