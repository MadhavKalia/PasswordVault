import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial

with sqlite3.connect("password_manager.db") as db:
    cur = db.cursor()

#Hash Passwords


#Database
cur.execute("""
CREATE TABLE IF NOT EXISTS login_password(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS login_username(
id INTEGER PRIMARY KEY,
username TEXT NOT NULL);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
site TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

#prompting for information to store
def AskForInfo(text):
    ans =  simpledialog.askstring("input", text)
    return ans

#Creating window
window = Tk()
window.title("Password Vault")
window.geometry("350x250")


def createLogin():
    lb = Label(window, text="Create Login")
    lb.config(anchor = CENTER)
    lb.pack(pady = 10)

    username = Label(window, text="Create Username:")
    username.config()
    username.pack()

    userlogin = Entry(window,width=25)
    userlogin.focus()    
    userlogin.pack()

    passw = Label(window, text="Create Password:")
    passw.config()
    passw.pack()

    userpass = Entry(window,width=25, show = "*")
    userpass.focus()    
    userpass.pack()

    passw2 = Label(window, text="Re-enter Password:")
    passw2.config()
    passw2.pack()

    userpass2 = Entry(window,width=25, show = "*")
    userpass2.focus()    
    userpass2.pack()
    
    lb = Label(window)
    lb.pack()

    def savePass():
        if userpass.get() == userpass2.get():
            encryptedPassword = encryptPass(userpass.get().encode("-utf-8"))
            login_pass = """INSERT INTO login_password(password)
            VALUES(?)"""
            login_name = """INSERT INTO login_username(username)
            VALUES(?)"""
            cur.execute(login_pass, [(encryptedPassword)])
            cur.execute(login_name, [(userlogin.get())])
            db.commit()
            passVault()
        else:
            userpass.delete(0, 'end')
            userpass2.delete(0, 'end')
            lb.config(text="Error, Passwords do not match")

    Button(text="Save", command=savePass).pack()

def encryptPass(password):
    newPassword = hashlib.md5(password)
    newPassword = newPassword.hexdigest()
    return newPassword

def mainScreen():    
    lb = Label(window, text="Enter Login")
    lb.config(anchor = CENTER)
    lb.pack(pady = 10)

    username = Label(window, text="username:")
    username.config()
    username.pack()

    userlogin = Entry(window,width=25)
    userlogin.focus()    
    userlogin.pack()

    passw = Label(window, text="password:")
    passw.config()
    passw.pack()

    userpass = Entry(window,width=25, show = "*")
    userpass.focus()    
    userpass.pack()

    lb2 = Label(window)
    lb2.pack()

    def getLoginPass():
        checkEncryptedPass = encryptPass(userpass.get().encode("-utf-8"))
        cur.execute("SELECT * FROM login_password WHERE id = 1 AND password = ?", [(checkEncryptedPass)])
        return cur.fetchall()

    def getLoginUsername():
        cur.execute("SELECT * FROM login_username WHERE id = 1 AND username = ?", [(userlogin.get())])
        return cur.fetchall()

    def checklogin():
        match = getLoginPass()
        match2 = getLoginUsername()
        if match and match2:
            passVault()
        else:
            userpass.delete(0, 'end')
            userlogin.delete(0, 'end')
            lb2.config(text="Wrong username or password")


    Button(text="Submit", command=checklogin).pack()

def passVault():
    for widget in window.winfo_children():
        widget.destroy()

    def addSite():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        site = AskForInfo(text1)
        username = AskForInfo(text2)
        password = AskForInfo(text3)

        columns = """INSERT INTO vault(site, username, password)
        VALUES(?, ?, ?)"""
        cur.execute(columns, (site,username, password))
        db.commit()

        passVault()
    
    def removeSite(input):
        cur.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passVault()

    window.geometry("800x450")

    lb = Label(window, text="Password Vault")
    lb.config(anchor = CENTER)
    lb.grid(column=1)

    addButton = Button(window, text = "Add", command = addSite)
    addButton.grid(column=1, pady=10)

    lb = Label(window, text = "Website")
    lb.grid(row=2, column=0, padx=88)
    lb = Label(window, text = "Username")
    lb.grid(row=2, column=1, padx=88)
    lb = Label(window, text = "Password")
    lb.grid(row=2, column=2, padx=88)

    #show passwords,usernames and sites
    cur.execute("SELECT * FROM vault")
    if (cur.fetchall()!= None):
        i = 0
        while True:
            cur.execute("SELECT * FROM vault")
            arr = cur.fetchall()

            lb = Label(window, text = (arr[i][1]))
            lb.grid(column=0, row=i+3)
            lb2 = Label(window, text = (arr[i][2]))
            lb2.grid(column=1, row=i+3)
            lb3 = Label(window, text = (arr[i][3]))
            lb3.grid(column=2, row=i+3)

            deleteButton = Button(window, text="Delete", command= partial(removeSite, arr[i][0]))
            deleteButton.grid(column=3, row=i+3, pady=10)

            i = i +1
            cur.execute("SELECT * FROM vault")
            if (len(cur.fetchall()) <=i):
                break

check = cur.execute("SELECT * FROM login_password")
if cur.fetchall():
    mainScreen()
else:
    createLogin()

window.mainloop()