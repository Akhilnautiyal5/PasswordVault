from tkinter import *
import tkinter as tk
from tkinter import ttk
from tkinter import font, messagebox
from ttkbootstrap.constants import *
import ttkbootstrap as tb
from ttkbootstrap import style
import sqlite3, hashlib
import uuid, base64
from PIL import ImageTk, Image
import random, string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
encryptionkey=0


backend=default_backend()
salt=b'2444'
kdf=PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

def encrypt(message:bytes,token:bytes)-> bytes:
    return Fernet(token).encrypt(message)

def decrypt(message:bytes,token:bytes)-> bytes:
    return Fernet(token).decrypt(message)

def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash

# DataBase Management
with sqlite3.connect("password_vault.db") as db:
    c = db.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS masterpassword(
        id INTEGER PRIMARY KEY,
        password TEXT NOT NULL
        )
    """)
c.execute("""CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY,
        website TEXT NOT NULL,
        username TEXT NOT Null,
        hashed_password TEXT NOT NULL
        )
    """)
def myVault():
    # Create Popup
    def popup(*prompts):
        result = []

        def on_okay():
            result.extend(entry.get() for entry in entries)
            for value in result:
                if value is None or value.strip() == "":
                    break
            else:
                popup_window.destroy()


        popup_window = Toplevel(main)
        popup_window.iconbitmap(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\icon.ico")
        popup_window.geometry("330x311")
        popup_window.resizable(width=False, height=False)

        popup_window.title("Enter Information")

        entries = []

        for prompt in prompts:
            Label(popup_window, text=prompt).pack(fill="both", padx=60 ,pady=5, expand=True)
            entry = Entry(popup_window, show='*' if prompt.lower() == 'password' else None)
            entry.pack(padx=60, pady=5, fill="both", expand=True)
            if entry==None:
                pass
            else:
                entries.append(entry)

        Button(popup_window, text="Okay", height=2, width=10, command=on_okay).pack(padx=100, pady=30, fill="both", expand=True)

        popup_window.grab_set()  # Make the popup modal
        popup_window.wait_window()  # Wait for the popup to be closed

        return result



    # creating login window
    main = Toplevel()#themename="superhero")
    # main = Tk()
    main.title("MyPassVault")
    main.iconbitmap(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\icon.ico")
    main.geometry("950x450")
    main.resizable(width=True, height=True)
    main.minsize(width=950, height=450)

    global my_img
    my_img = ImageTk.PhotoImage(Image.open(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\my_png.png"))
    mylable = Label(main, image=my_img)
    mylable.grid(row=0, column=0, rowspan=3)
    # main.grid_columnconfigure(0, weight=1)
    # main.grid_rowconfigure(0, weight=1)
    global frame2
    frame2 =Frame(main, padx=100, pady=1, width=350)#, height=500)
    frame2.grid(column=1, row=0, padx=0)
    main.grid_columnconfigure(1, weight=1)
    main.grid_rowconfigure(0, weight=1)


    def firstScreen():
        global entry_font
        entry_font = font.Font(family="Helvetica", size=13, underline=True)
        lbl1 = Label(frame2, text="   Create Master Password   ", font=entry_font, anchor="s")
        lbl1.config(padx=10, pady=50)
        lbl1.pack(fill="both", expand=True)

        input_pass = StringVar()




    # Entry for password

        txt1 = Entry(frame2, textvariable=input_pass, width=30, show="*")
        txt1.pack(padx=10, anchor="n", fill="both", expand=True)
        txt1.focus()

        lbl2 = Label(frame2, text="Re-enter Passoword")
        lbl2.pack(pady=10, fill="both", expand=True)

        txt2 = Entry(frame2, width=30, show="*")
        txt2.pack(padx=10, anchor="n", fill="both", expand=True)

        lbl3 = Label(frame2)
        lbl3.pack(pady=10, fill="both", expand=True)




        """
        -----------------------------------------------------------------------------------------------------------------------------
        """
        def check_password_strength(password):
            length_score = len(password)
            numbers_score = 1 if any(c.isdigit() for c in password) else 0
            special_char_score = 1 if any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/" for c in password) else 0                              
            single_case_score = 1 if any(c.isupper() for c in password) or any(c.islower() for c in password) else 0
            mixed_case_score = 1 if any(c.isupper() for c in password) and any(c.islower() for c in password) else 0
        

            # total_score = (numbers_score + special_char_score + single_case_score + mixed_case_score) * length_score

            if numbers_score != 0 and single_case_score != 0 and mixed_case_score != 0 and special_char_score != 0:
                total_score = 5 * length_score
                if total_score < 45 :
                    return 1
                elif total_score == 45:
                    return 2
                elif total_score > 45:
                    return 3
            elif numbers_score != 0 and single_case_score != 0 and special_char_score != 0:
                total_score = 4 * length_score
                if total_score < 36 :
                    return 1
                elif total_score > 36 and total_score < 40:
                    return 2
                elif total_score > 40:
                    return 3
            elif  mixed_case_score != 0:
                total_score = 3 * length_score
                if total_score < 27 :
                    return 1
                elif total_score > 27 and total_score < 45:
                    return 2
                elif total_score > 45:
                    return 3
            elif single_case_score != 0:
                total_score = 2 * length_score
                if total_score < 20 :
                    return 1
                elif total_score > 20 and total_score < 34:
                    return 2
                elif total_score > 34:
                    return 3
            elif numbers_score != 0 or special_char_score != 0:
                total_score = 1 * length_score
                if total_score < 15:
                    return 1
                elif total_score > 15:
                    return 2


        def update_strength_gauge(password):
            global strength
            strength = check_password_strength(password)
            if strength == 1:
                gauge.configure(value=(10), style="danger.Horizontal.TProgressbar")  # Red
            elif strength == 2:
                gauge.configure(value=(30), style="warning.Horizontal.TProgressbar")  # Yellow
            elif strength == 3:
                gauge.configure(value=(200), style="success.Horizontal.TProgressbar")  # green


        def on_password_change(*args):
            password = input_pass.get()
            update_strength_gauge(password)

        # Password strength gauge
        gauge = tb.Progressbar(frame2, orient=HORIZONTAL, length=200, mode="determinate")
        # gauge.configure(barw)
        gauge.pack(pady=10, fill="both", expand=True)

        # Trace changes in the password entry
        input_pass.trace_add("write", on_password_change)
        
        # Initial update when the program starts
        on_password_change()
        """
        ------------------------------------------------------------------------------------------------------------------------------
        """

        def mesagebox():
            global response
            response = messagebox.askquestion("warning", "Your entered password is weak\ndo you want to continue?")


        def savePassword():
            global master_pass
            if txt2.get() == "" or  txt1.get() == "" or txt2.get() == " " or  txt1.get() == " ":
                lbl3.config(text="❌ Invalid Passsword", fg= "red")

            elif txt2.get() == txt1.get():
                hashedPassword = hashPassword(txt1.get().encode('utf-8'))
                # key=str(uuid.uuid4().hex)
                
                # recoverykey=hashPassword(key.encode('utf-8'))
                global encryptionkey 
                encryptionkey= base64.urlsafe_b64encode(kdf.derive("PremWagh2210".encode('utf-8')))
                if strength == 1 or strength == 2:
                    mesagebox()
                    if response == "yes":
                        insert_password = """INSERT INTO masterpassword(password)
                        VALUES(?) """
                        c.execute(insert_password, [(hashedPassword)])
                        db.commit()
                        passwordVault()
                    elif response == "no":
                        txt1.delete(0, END)
                        txt2.delete(0, END)
                else:
                    insert_password = """INSERT INTO masterpassword(password)
                    VALUES(?) """
                    c.execute(insert_password, [(hashedPassword)])
                    db.commit()
                    passwordVault()
            else:
                txt1.delete(0, END)
                txt2.delete(0, END)
                lbl3.config(text="❌Passsword do not match", fg= "red")


        def on_enter_entry1(event):
            txt2.focus()

        def on_enter_entry2(event):
            if not txt1.get():
                txt1.focus()
            else:
                savePassword()

        txt1.bind('<Return>', on_enter_entry1)
        txt2.bind('<Return>', on_enter_entry2)

        btn1 = Button(frame2, text="  Save  ", width=20, command=savePassword)
        btn1.pack(pady=10, fill="both", expand=True)









    def loginScreen():
        
        global entry_font
        entry_font = font.Font(family="Helvetica", size=13, underline=True)
        lbl1 = Label(frame2, text="   Enter Master Password   ", font=entry_font, anchor="s")
        lbl1.config(padx=10, pady=50)
        lbl1.pack(fill="both", expand=True)
        
        txt1 = Entry(frame2, width=30, show="*")
        txt1.pack(padx=10, anchor="n", fill="both", expand=True)
        txt1.focus()

        lbl2 = Label(frame2)
        lbl2.pack(pady=10, fill="both", expand=True)


        def getMasterPasword():
            checkHashedPassword = hashPassword(txt1.get().encode('utf-8'))
            c.execute("SELECT * FROM masterpassword WHERE id = 1 AND  password = ?", [(checkHashedPassword)])
            return c.fetchall()


        def checkPassword():
            match = getMasterPasword()
            if match:
                global encryptionkey 
                encryptionkey= base64.urlsafe_b64encode(kdf.derive("PremWagh2210".encode('utf-8')))
                passwordVault()
            else:
                txt1.delete(0, END)
                lbl2.config(text=" ❌ Incorrect Passsword", foreground="red")


        txt1.bind('<Return>', lambda event: checkPassword())

        btn1 = Button(frame2, text="  Submit  ",width=20, command=checkPassword)
        btn1.pack(pady=10, fill="both", expand=True)




    def passwordVault():
        for widget in main.winfo_children():
            widget.destroy()
        
        main.geometry("1000x500")

        def addEntry():
            prompts = ["Website", "Username", "Password"]
            return_data = popup(*prompts)
            website, username, password = return_data
                    

            # Hash the password before storing it
            encrypted_pass = encrypt(password.encode('utf-8'), encryptionkey)
            encrypted_usrn = encrypt(username.encode('utf-8'), encryptionkey)

            insert_fields = """INSERT INTO vault(website, username, hashed_password)
                                VALUES(?, ?, ?)"""

            c.execute(insert_fields, (website, encrypted_usrn, encrypted_pass))
            db.commit()

            passwordVault()


        def search(website):
            # Clear the treeview
            treeview.delete(*treeview.get_children())

            # Use the LIKE clause to search for records with a partial match
            c.execute("SELECT * FROM vault WHERE website LIKE ?", ('%' + website + '%',))
            data_from_db = c.fetchall()

            # Check if there is data in the result
            if data_from_db:
                # Iterate over the fetched data and insert it into the treeview
                for item in data_from_db:
                    treeview.insert('', 'end', values=(item[0], item[1], item[2], item[3]))
            else:
                # Handle the case when there is no data in the result
                print("No matching records in the vault table.")
            return



    # Create a frame
        frame = Frame(main, highlightbackground="black", highlightthickness=1, padx=100, pady=40)
        frame.pack( pady=40, expand=True, fill="both")

        lbl = Label(frame, text="  Password Vault  ", font=entry_font)
        lbl.grid(row=0, column=0, columnspan=3, pady=(0, 5))
        lbl.configure(justify=CENTER)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        btn = Button(frame, text=" New Entry ", width=15, command=addEntry)
        btn.grid(row=1,column=0, padx=40)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        srch = Entry(frame, text=" Search ", width=40)
        srch.grid(row=1,column=3)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(3, weight=1)

        btn = Button(frame, text=" Search ", width=15, command=lambda: search(srch.get()))
        btn.grid(row=1,column=2)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=1)

        # Create a treeview with two columns
        treeview = tb.Treeview(main, columns=('ID', 'Website', 'Username'), show='headings', height=30)

        # Set column headings
        treeview.heading('ID', text='ID')
        treeview.heading('Website', text='Website')
        treeview.heading('Username', text='Username')
        treeview.column('ID', width=100, stretch=True)
        treeview.column('Website', width=500, stretch=True)
        treeview.column('Username', width=500, stretch=True)



        def on_select(event):

            def copyPass(password):
                win = Tk()
                win.withdraw()

                cpass=decrypt(password, encryptionkey).decode('utf-8')
                win.clipboard_clear()
                win.clipboard_append(cpass)
                win.update()



            def copy_usrname(username):
                win = Tk()
                win.withdraw()

                usrname=decrypt(username, encryptionkey).decode('utf-8')
                win.clipboard_clear()
                win.clipboard_append(usrname)
                win.update()



            def update(id, account, user_name, password):

                decrypt(user_name, encryptionkey).decode('utf-8')
                decrypt(password, encryptionkey).decode('utf-8')

                txt1.config(state=ACTIVE)
                txt2.config(state=ACTIVE, show="")

                id = record[0]
                username=encrypt(txt1.get().encode('utf-8'), encryptionkey)
                password=encrypt(txt1.get().encode('utf-8'), encryptionkey)
            

            
                c.execute("UPDATE vault SET username=?, password=? WHERE id=?", (username,password,id))
                db.commit()

                passwordVault()

            def deleteEntry(input):
                c.execute("DELETE FROM VAULT WHERE  id = ?", (input,))
                db.commit()

                passwordVault()



        
            for selected_item in treeview.selection():
                global items
                item = treeview.item(selected_item)
                record = item["values"]

                # window = tb.Window(themename="superhero")
                window = Tk()
                # window.geometry("330x350")

                label = Label(window, text=f"  {record[1]}  ", font=("helvetica", 12))
                label.grid(row=0, column=0, columnspan=2, padx=20, pady=20)
                # label.pack()
                
                lbl1 = Label(window, text="Username", font=("helvetica", 11))
                lbl1.grid(row=1, column=0, padx=(20, 0))
                # lbl1.pack()

                # usrName = decrypt(record[2], encryptionkey)#.decode('utf-8')
                txt1 = Entry(window, foreground="black")
                # txt1.insert(0, usrName)
                txt1.grid(row=2, column=0, padx=20, pady=20)
                txt1.config(state="readonly",foreground="black")
                # txt1.pack()

                lbl3 = Label(window, text="Password", font=("helvetica", 11))
                lbl3.grid(row=3, column=0, padx=(20, 0))
                # lbl3.pack()
                
                txt2 = Entry(window, show="*",state='readonly',fg='black', foreground="black")
                txt2.insert(0, record[3])
                txt2.grid(row=4, column=0, padx=(21, 0), pady=20)
                # txt2.pack()

                btn1 = tb.Button(window, text="📄", command=lambda: copy_usrname(record[2]))
                btn1.grid(row=2, column=1, padx=(0, 20), pady=20)
                # btn1.pack()

                btn2 = tb.Button(window, text="📄", command=lambda: copyPass(record[3]))
                btn2.grid(row=4, column=1, padx=(0, 20), pady=20)
                # btn2.pack()

                btn3 = tb.Button(window, text="Update", width=7, command=lambda: update(*record))
                btn3.grid(row=5, column=0, padx=20, pady=20)
                # btn3.pack()

                btn4 = tb.Button(window, text="Delete", width=7, command=lambda: deleteEntry(record[0]))
                btn4.grid(row=5, column=1, padx=20, pady=20)
                # btn4.pack()



        # Bind the on_select function to the treeview selection
        treeview.bind('<ButtonRelease-1>', on_select)
        treeview.pack(expand=True, fill="both")


        # Fetch data from the vault table
        c.execute("SELECT * FROM vault")
        data_from_db = c.fetchall()

        # Check if there is data in the result
        if data_from_db:
            # Iterate over the fetched data and insert it into the treeview
            for item in data_from_db:
                treeview.insert('', 'end', values=(item[0], item[1], item[2], item[3]))
        else:
            # Handle the case when there is no data in the result
            print("No data in the vault table.")


    c.execute("SELECT * FROM masterpassword")
    if c.fetchall():
        loginScreen()
    else:
        firstScreen()

    # opnvault_btn["state"]=ACTIVE



def passgenerator():
    main = tb.Window(themename="superhero")
    main.geometry("900x450")
    main.iconbitmap(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\icon.ico")
    main.resizable(width=False, height=False)
    main.title("Password Generator")

    frame = Frame(main)
    # Character Options


    def update_vars(var):
        var.set(1 if var.get() == 0 else 0)

    val, special, num= IntVar(), IntVar(), IntVar()
    optionsFrame = LabelFrame(frame, text="Options", width=70, relief='solid')
    letter = Checkbutton(optionsFrame, text="Letters", onvalue=1, offvalue=0, variable=val, width=50, command=lambda: update_vars(val))
    specialChar = Checkbutton(optionsFrame, text="Special Characters", onvalue=1, offvalue=0, variable=special, width=50, command=lambda: update_vars(special))
    number = Checkbutton(optionsFrame, text="Number", onvalue=1, offvalue=0, variable=num, width=50, command=lambda: update_vars(num))
    letter.select()
    val.set(1)

    # Length Options
    global length
    length = IntVar()
    length.set(10)
    scale_frame = LabelFrame(frame, text="Pwd Length", bg="#2B3E50", highlightthickness=0, relief='flat')


    my_label = tb.Label(scale_frame, text="10", font=("Helvetica", 12), background="#bccddb")


    def scaler(e):
        my_label.config(text=f'{int(my_scale.get())}')
        length.set(int(my_scale.get()))
 


    my_scale = tb.Scale(scale_frame, bootstyle="success",
        length=300,
        orient="horizontal",
        from_=3,
        to=64,
        value=3,
        command=scaler,
        state="normal")
    my_scale.set(10)


    def generatePassword():
        copyPassword["state"] = ACTIVE

        randomletters = random.choices(string.ascii_letters, k=36) if val.get() == 1 else []
        randomSpecial = random.choices(string.punctuation, k=20) if special.get() == 1 else []
        randomNum = random.choices(string.digits, k=8) if num.get() == 1 else []

    
        # Combine the character sets
        all_characters = randomletters + randomSpecial + randomNum
        random.shuffle(all_characters)
        # Select characters based on the desired length
        length_of_pass = (length.get())
        randomGen = all_characters[:length_of_pass]
        textBox.delete(0, END)  # Clear the existing content
        textBox.insert(0, ''.join(randomGen))  # Join the characters into a string without spaces





    def Copy_password():
            win = Tk()
            win.withdraw()
            win.clipboard_clear()
            win.clipboard_append(textBox.get())
            win.update()


    # Copy password button
    copyPassword=tb.Button(main, text = 'COPY', style='raised.TButton', width=15, command = Copy_password,state=ACTIVE)
    # Buttons && Textbox
    genPwd = tb.Button(main, text="Generate Password", width=25, command=generatePassword)
    # viewHistory = Button(main, text="View History", width=25, command=getHistory)
    textBox = Entry(main)
    textBox.configure(fg="white", bg="#2B3E50")
    # textBox.bind('<Return>', Copy_password)
    # Packing && Grid of Widgets
    widgetsInFrame = [ letter, specialChar, number ]
    for item in widgetsInFrame: item.pack(pady=5, anchor="w")


    my_scale.grid(row=0, column=0, padx=5, pady=10)
    my_label.grid(row=0, column=1,padx=5, pady=10)

    optionsFrame.grid(row=0, column=0) # Options and Length beside each other
    scale_frame.grid(row=1, column=0, pady=10)  # Options and Length beside each other


    mainWidgets = [ frame, genPwd, textBox, copyPassword ]

    for widget in mainWidgets: widget.pack(pady=10)




    main.mainloop()



def homeScreen():
    home = tb.Window(themename="superhero")
    home.iconbitmap(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\icon.ico")
    home.geometry("950x500")
    home.resizable(width=False, height=False)
    home.configure(bg="#2B3E50")

    # homeicon = ImageTk.PhotoImage(Image.open(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\homepage.png").resize((50, 50), Image.BICUBIC))
    settings = ImageTk.PhotoImage(Image.open(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\keys.png").resize((50, 50), Image.BICUBIC))
    ring = ImageTk.PhotoImage(Image.open(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\password.png").resize((50,50), Image.BICUBIC))
    main_img = ImageTk.PhotoImage(Image.open(r"C:\Users\AKHIL\Desktop\cs\python\PasswordVault\main.png").resize((150, 150)))

    frame1 = Frame(home)
    frame1.grid(row=0, column=1, sticky=N, padx=200)
 
    frame1.rowconfigure(0, weight=1)
    frame1.columnconfigure(1, weight=1)

    lbl = Label(frame1, image = main_img, justify='center')
    lbl.pack(padx=150)
    home.update()

    frame2 = Frame(home, borderwidth=5, width=70, height=500)
    frame2.grid(row=0, column=0, sticky=S)
    frame2.configure(background='#bccddb')

    # home_b = Button(frame2, image=homeicon, bg='#bccddb', relief='flat', command=homeScreen)
    gen_b = Button(frame2, image=settings, bg='#bccddb', relief='flat', command=passgenerator)
    vault_b = Button(frame2, image=ring, bg='#bccddb', relief='flat', command=myVault)
    # home_b.pack(padx=10)
    gen_b.pack(pady=50)
    vault_b.pack(pady=(10, 250))

    frame2.grid_propagate(False)




    # c.execute("SELECT * FROM vault")
    # data_from_db = c.fetchall()


    home.mainloop()

homeScreen()
