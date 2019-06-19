from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox as ms
import sqlite3
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from random import randrange
from tkinter import *

filetypee=""
def get_u_r(num):
    u = 0
    num -= 1

    while True:
        u += 1
        num //= 2
        if u != 0 and num % 2 != 0:
            break

    return (u, num)

def modular_pow(base, exponent, modulus): #square and multiply
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 0:
        if (exponent % 2 == 1):
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def miller_rabin(p, s):
    if p == 2:
        return True
    if p % 2 == 0:
        return False

    u, r = get_u_r(p)
    for i in range(s):
        a = randrange(2, p - 1)
        z = modular_pow(a, r, p)

        if z != 1 and z != (p - 1):
            for j in range(u):
                z = modular_pow(z, 2, p)
                if z == p - 1:
                    break
                else:
                    return False

    return True

def get_rand_prime(nbits=16):
    while True:
        p = randrange(2 ** nbits, 2 * 2 ** nbits)
        # print(p)
        if miller_rabin(p, 100):
            return p

def inverse(ra, rb):
    if rb > ra:
        ra, rb = rb, ra

    modulos = ra
    mult = [(1, 0), (0, 1)]
    i = 2
    while True:
        # print(str(ra) + " = " + str(rb) + "*", end='')
        mod = ra % rb
        q = (ra - mod) // rb
        # print(str(q)+" + " + str(mod))
        ra = rb
        rb = mod
        mult = [
            (mult[1][0], mult[1][1]),
            ((-q * mult[1][0]) + mult[0][0], (-q * mult[1][1]) + mult[0][1])
        ]
        if mod == 0:
            # print("GCD = " + str(ra))
            if ra == 1:
                return mult[0][1] % modulos
            else:
                return -1

def CRT(y, d, p, q):
    n = p * q

    # 1- Convert to CRT domain
    yp = y % p
    yq = y % q
    # print("(yp, yq) = ", str((yp, yq)))

    # 2- Do the computations
    dp = d % (p - 1)
    dq = d % (q - 1)
    # print("(dp, dq) = ", str((dp, dq)))

    xp = pow(yp, dp, p)
    xq = pow(yq, dq, q)
    # print("(xp, xq) = ", str((xp, xq)))

    # 3- Inverse transform
    inv = inverse(p, q)
    #print(inv)
    cp = pow(q, p - 2, p)
    cq = pow(p, q - 2, q)
    # print(cq == pow(p, q-2, q))
    # print("(cp, cq) = ", str((p, q)))

    x = ((q * cp * xp) + (p * cq * xq)) % n
    # print("x = ", x, "mod " + str(n))
    return x


def msg_to_int(msg):
    int_msg = ""
    for ch in msg:
        pre = "{0:b}".format(ord(ch))
        if len(pre) < 7:
            pre = "0" * (7 - len(pre)) + pre
        int_msg += pre

    return int(int_msg, 2)


def int_to_msg(i):
    bin_format = "{0:7b}".format(i)
    msg = ""

    for b in range(0, len(bin_format), 7):
        msg += chr(int(bin_format[b:b + 7], 2))

    return msg


def encryption(msg, e, n):
    #print(msg)
    int_msg = msg_to_int(msg)
    encrypted = modular_pow(int_msg, e, n)
    # print(setuptime + '\n Encrypted Message = ', encrypted)
    return str(encrypted)



def decryption(msg, d, p, q):
    decrypted = CRT(int(msg), d, p, q)
    # print('\nMessage = ', int_to_msg(decrypted))
    return int_to_msg(decrypted)


def RSA_Init(nbits=1024):  # setup
    p = get_rand_prime(nbits)
    q = get_rand_prime(nbits)
    while p == q:
        q = get_rand_prime(nbits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = randrange(2 ** 16, 2 ** 17)
    d = inverse(phi, e)
    while d == -1:
        e = randrange(2 ** 16, 2 ** 17)
        d = inverse(phi, e)

    return {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e": e,
        "d": d
    }


RSAparams = RSA_Init(1024)

window = Tk()
window.title("File Encryption System")
window.geometry("400x300")

Username=StringVar()
Password=StringVar()
filenamee=""
uname=""
passw=""

def iencrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = "(encrypted)" + filenamee
    filesize = str(os.path.getsize(filenamee)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filenamee, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))
    os.remove(filenamee)


def idecrypt(key, filenamee):
    chunksize = 64 * 1024
    outputFile = filenamee[11:]

    with open(filenamee, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)

def tencrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = "(encrypted)" + filenamee
    filesize = str(os.path.getsize(filenamee)).zfill(16)
    IV = Random.new().read(16)

    #encryptor = AES.new(key, AES.MODE_CBC, IV)
    charr= [ch for ch in open(filenamee).read()]
    #chunk = infile.read(chunksize)
    with open(outputFile, 'w') as outfile:
        outfile.write(encryption(charr,RSAparams['e'], RSAparams['n']))
    os.remove(filenamee)


def tdecrypt(key, filenamee):
    chunksize = 64 * 1024
    outputFile = filenamee[11:]
    charr= [ch for ch in open(filenamee).read()]
    st1=''.join(charr)
    #chunk = infile.read(chunksize)
    with open(outputFile, 'w') as outfile:
        outfile.write(decryption(st1,RSAparams['d'], RSAparams['p'], RSAparams['q']))
        #outfile.truncate(filesize)


def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def Main(choice):
    global passw, filetypee
    if choice == 'E' or choice == 'e':
        if filetypee=='t':
            tencrypt(getKey(passw), filenamee)
            filetypee=""
            print("Done.")
        elif filetypee=='i':
            iencrypt(getKey(passw), filenamee)
            filetypee=""
            print("Done.")
    elif choice == 'D' or choice == 'd':
        if filetypee=='t':
            tdecrypt(getKey(passw), filenamee)
            filetypee=""
            print("Done.")
        elif filetypee=='i':
            idecrypt(getKey(passw), filenamee)
            filetypee=""
            print("Done.")
    else:
        print("No Option selected, closing...")

def ienbutton():
    global filetypee
    choice='e'
    filetypee='i'
    Main(choice)
    
def idebutton():
    global filetypee
    filetypee='i'
    choice='d'
    Main(choice)
    
def tenbutton():
    global filetypee
    filetypee='t'
    choice='e'
    Main(choice)
    
def tdebutton():
    global filetypee
    filetypee='t'
    choice='d'
    Main(choice)
    
def iwin():
    window1= Tk()
    window1.title("Encrypt/Decrypt")
    window1.geometry("300x300")
    en=Button(window1, text="Encrypt file",width=15, command=ienbutton,background='grey')
    en.grid(row=3, column=0)
    de=Button(window1, text="Decrypt file",width=15, command=idebutton,background='grey')
    de.grid(row=3, column=1)
    lf=Label(window1,text="Choose file",font=("bold",13))
    lf.grid(row=0,column=0)
    cb=Button(window1, text="Browse", width=13,command=fd,background='grey')
    cb.grid(row=0,column=1)
def twin():
    window2= Tk()
    window2.title("Encrypt/Decrypt")
    window2.geometry("300x300")
    en2=Button(window2, text="Encrypt file",width=15, command=tenbutton,background='grey')
    en2.grid(row=3, column=0)
    de2=Button(window2, text="Decrypt file",width=15, command=tdebutton,background='grey')
    de2.grid(row=3, column=1)
    lf2=Label(window2,text="Choose file",font=("bold",13))
    lf2.grid(row=0,column=0)
    cb2=Button(window2, text="Browse", width=13,command=fd,background='grey')
    cb2.grid(row=0,column=1)
    
def fd():
    filename=filedialog.askopenfilename(initialdir="/", title="Select a file", filetype=(("jpeg","*.jpg"),("All Files", "*.*")))
    i=len(filename)
    global filenamee
    filenamee=filename[20:i]
    print(filenamee)
    
def loginbutton():
    global uname, passw
    uname=Text1.get()
    passw=Text2.get()
    conn = sqlite3.connect('Form.db')
    with conn:
      cursor=conn.cursor()
    find_user=('SELECT * FROM User WHERE Username=? AND Password=?')
    cursor.execute(find_user,[(uname),(passw)])
    results= cursor.fetchall()
    if results:
        ms.showinfo("Logged in!")
        typew=Tk()
        typew.title("File type")
        gh=Label(typew,text="Choose file type to encrypt/decrypt",font=("bold",10))
        gh.grid(row=0,column=1)
        ibut=Button(typew, text="Image file",width=15, command=iwin,background='grey')
        ibut.grid(row=1,column=0)
        tbut=Button(typew, text="Text file",width=15, command=twin,background='grey')
        tbut.grid(row=1,column=2)
        
        
    else:
        ms.showerror("Wrong username or password!")
        
    
    
def registerbutton():
   uuname=Text3.get()
   ppassw=Text4.get()
   conn = sqlite3.connect('Form.db')
   with conn:
      cursor=conn.cursor()
   find_user=('SELECT * FROM User WHERE Username=?')
   cursor.execute(find_user,[uuname])
   results= cursor.fetchall()
   if results:
       ms.showerror("Sorry! Username already taken!")
   else:
        cursor.execute('CREATE TABLE IF NOT EXISTS User (Username, Password)')
        cursor.execute('INSERT INTO User (Username, Password) VALUES(?,?)',(uuname, ppassw))
        conn.commit()
        ms.showinfo("Registered successfully!")
#window.configure(background='white')
label1 = Label(window, text="Login or Register",font=("bold", 15))
label1.grid(row=0,column=1)

label1 = Label(window, text="Login",font=("bold", 13))
label1.grid(row=2,column=1)

label1 = Label(window, text="Username")
label1.grid(row=3,column=0)

label1 = Label(window, text="Password")
label1.grid(row=4,column=0)

Text1=StringVar()
t1=Entry(window, textvariable=Text1)
t1.grid(row=3,column=1)

Text2=StringVar()
t2=Entry(window, textvariable=Text2)
t2.grid(row=4,column=1)

label1 = Label(window, text="Register",font=("bold", 13))
label1.grid(row=6,column=1)

label1 = Label(window, text="Username")
label1.grid(row=7,column=0)

label1 = Label(window, text="Password")
label1.grid(row=8,column=0)

Text3=StringVar()
t3=Entry(window, textvariable=Text3)
t3.grid(row=7,column=1)

Text4=StringVar()
t4=Entry(window, textvariable=Text4)
t4.grid(row=8,column=1)

b1=Button(window, text="Login",width=10, background='grey')
b1.grid(row=5, column=1)
b1.config(command=loginbutton)

b2=Button(window, text="Register",width=10,background='grey')
b2.grid(row=9, column=1)
b2.config(command=registerbutton)



window.mainloop()
