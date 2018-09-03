from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from randcrack import RandCrack
from libnum.ranges import Ranges
from Crypto.Util.number import inverse
from pwn import *
rem = remote('crypto.chal.ctf.westerns.tokyo', 5643)
e = 65537
rng=Ranges()
key=0

def pad(x):
	if(len(x)%2):
		return '0'+x
	else: return x

def oracle(CT):
	rem.sendline('2')
	rem.sendlineafter('input hexencoded cipher text:',pad(hex(CT)[2:].strip('L')))
	rem.recvuntil('RSA: ')
	PT=int(rem.recvline().strip('\n'),16)
	#print PT	
	return PT%2

def spec_oracle(CT):
	rem.sendline('2')
	rem.sendlineafter('input hexencoded cipher text:',pad(hex(CT)[2:].strip('L')))
	rem.recvuntil('RSA: ')
	PT=int(rem.recvline().strip('\n'),16)
	#print PT	
	return PT%256

def get_aeskey():
	rng=Ranges((0,n-1))
	rem.sendline('4')
	rem.recvuntil('here is encrypted key :)\n')
	C= int(rem.recvline().strip('\n'),16)
	C2=C
	end=spec_oracle(C)
	p2=pow(2,e,n)
	C=p2*C%n
	a,b=(0,n-1)
	for i in range(1024-128):
		b=(a+b)/2
		C=p2*C%n
	rng=Ranges((a,b))
	while(rng.len>256):
		a,b=rng.segments[0]
		c=(a+b)/2
		if(oracle(C)):
			rng=Ranges((c,b))
		else: rng=Ranges((a,c))		
		C=C*p2%n
	
	for x in rng:
		if(x%256==end):
			key=x
	return key

def get_IV():
	rem.sendline('1')
	rem.sendlineafter('input plain text: ','')
	rem.recvuntil('AES: ')
	x=int(rem.recvline().strip('\n')[:32],16)
	return x

def get_encflag():
	rem.sendline('3')
	rem.recvuntil('another bulldozer is coming!\n')
	x=int(rem.recvline().strip('\n')[32:],16)
	return x

def get_aesIV():
	rc=RandCrack()
	for i in range(156):
		x=get_IV()
		for j in range(4):
			rc.submit(x%(2**32))
			x=x>>32
	return rc

def gcd(a,b):
    while b!=0:
        r=a%b
        a=b
        b=r
    return  a

def unpad(s):
    n = ord(s[-1])
    return s[:-n]

def decrypt(key,iv,ct):
    iv = long_to_bytes(iv)
    key = long_to_bytes(key)
    ct = long_to_bytes(ct)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(ct))

def testn():
	x=pow(2,e,n)
	rem.sendline('1')
	rem.sendlineafter('input plain text: ','\x02')
	d=int(rem.recvline().strip().split()[-1],16)
	if(d==x):
		print "Hah! I got your N.\n\nN =",n,'\n\n'

def testkey():
	rem.sendline('4')
	rem.recvuntil('here is encrypted key :)\n')
	x= int(rem.recvline().strip('\n'),16)

	rem.sendline('1')
	rem.sendlineafter('input plain text: ',pad(hex(key)[2:]).decode('hex'))
	d=int(rem.recvline().strip().split()[-1],16)
	if(d==x):
		print "Hah! I got your key.\n\nkey =",key,'\n\n'

def testIV():
	x=get_IV()
	if(R.predict_getrandbits(128)==x):
		print 'Hah! I got your IV.\n\n'


rem.sendline('1')
rem.sendlineafter('input plain text: ','\x02')
d=rem.recvline().strip().split()[-1]
n=2**e-int(d,16)
i=3
while(len(bin(n)[2:])>1024):
	rem.sendline('1')
	rem.sendlineafter('input plain text: ',chr(i))
	d=rem.recvline().strip().split()[-1]
	n=gcd(n,i**e-int(d,16))
	i+=1

print "They see me rollin\'...\n"

testn()

key=get_aeskey()

testkey()

R=get_aesIV()

testIV()
IV=R.predict_getrandbits(128)

enc=get_encflag()
x=decrypt(key,IV,enc)
print "Hah! I got your flag!!\n\n",x[x.find("TWCTF{"):],"\n\nThey hatin\'\n"
