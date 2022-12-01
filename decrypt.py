def decryption(msg):                        # encryption -> decryption
    pt = []                                 # ct -> pt (plain text)
    for char in msg:
        char = char - 18                    # chall.py pricitalo + 18
        char = 179 * char % 256            
        pt.append(char)
    return bytes(pt)

with open("msg.enc") as f:  
    ct = bytes.fromhex(f.read())
    
pt = decryption(ct)
print(pt)

