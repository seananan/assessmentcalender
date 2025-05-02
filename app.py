from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
from datetime import date

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "secret_key"
DATABASE = 'DB_FILE'
today=date.today()


def connect_database(db_file):
    """
    Creates a connection to the database.
    :param db_file:
    :return: conn
    """
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(f"The error '{e}' occurred")
    return


@app.route('/')
def render_homepage():
    """
    :return: Renders home page of website
    """
    username = None
    if 'user_id' in session:
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "SELECT first_name FROM user WHERE user_id = ?"
        cur.execute(query, (session['user_id'],))
        name = cur.fetchone()
        con.close()
        if name:
            username = name[0]
    return render_template('home.html', user_name=username)


@app.route('/signup',methods=['POST', 'GET'])
def render_signup_page():
    """
    :return: Ren
    """
    if request.method =='POST':
        fname = request.form.get('user_fname').title().strip()
        lname = request.form.get('user_lname').title().strip()
        email = request.form.get('user_email').lower().strip()
        password1 = request.form.get('user_password1')
        password2 = request.form.get('user_password2')
        user_role = request.form.get('user_role')
        if password1 != password2:
            return redirect("\signup?error=passwords+do+not+match")
        if len(password1) < 8:
            return redirect("\signup?error=password+must+be+over+8+characters")
        else:
            session['logged_in = True']=True
            redirect('/')
        hashed_password = bcrypt.generate_password_hash(password1)
        con = connect_database(DATABASE)
        querysean = "SELECT email FROM user"
        cur = con.cursor()
        cur.execute(querysean)
        all_emails = cur.fetchall()
        if (email,) in all_emails:
            return redirect("\signup?error=email+already+in+use")
        is_teacher = 1 if user_role == "Teacher" else 0
        query_insert = "INSERT INTO user (first_name, last_name, email, password, is_teacher) VALUES (?, ?, ?, ?, ?)"
        cur.execute(query_insert, (fname, lname, email, hashed_password, is_teacher))
        user_id = cur.lastrowid
        con.commit()
        con.close()
        session["user_id"] = user_id
        session["logged_in"] = True
        session['is_teacher'] = is_teacher
        return redirect("/")
    return render_template('signup.html')

@app.route('/login',methods=['POST', 'GET'])
def render_login_page():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('user_password1')
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "SELECT password, user_id, email, is_teacher FROM user WHERE email = ?"
        cur.execute(query,(email,))
        user_info = cur.fetchone()
        con.close()
        session["logged_in"] = True

        if user_info:
            stored_password = user_info[0]
            print(stored_password)
            print(user_info[0])
            print(password)
            if not bcrypt.check_password_hash(stored_password, password):
                return redirect("/login?error=email+or+password+invalid")
            else:
                session['user_id'] = user_info[1]
                session['email'] = user_info[2]
                session['is_teacher'] = bool(user_info[3])
                return redirect("/")
        else:
            return redirect("/login?error=Account+not+found")
    return render_template('login.html')

@app.route('/logout')
def render_logout_page():
    session.clear()
    return redirect("/")

@app.route('/creategroup',methods=['POST', 'GET'])
def render_creategroup_page():
    if request.method == 'POST':
        subject = request.form.get('subject')
        level = request.form.get('level')
        password = request.form.get('password')
        date = request.form.get('date')
        time = request.form.get('time')
        con = connect_database(DATABASE)
        cur=con.cursor()
        query_insert = "INSERT INTO group_class (group_subject, group_year, group_password) VALUES (?, ?, ?)"
        cur.execute(query_insert, (subject, level, password))
        con.commit()
        con.close()
        redirect("/")
    return render_template("creategroup.html")

@app.route('/yourgroups',methods=['POST', 'GET'])
def render_yourgroups_page():
    con=connect_database(DATABASE)
    cur=con.cursor
    query="SELECT group_class.group_subject, group_class.group_year, group_class."
    return render_template("yourgroups.html")


@app.route('/groupsignup', methods=['POST','GET'])
def render_groupsignup_page():
    if request.method == 'POST':
        password = request.form.get('code')
        print(password)
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "SELECT group_password FROM group_class WHERE group_password = ?"
        cur.execute(query, (password,))
        group_id = cur.lastrowid()
        user_info = cur.fetchall()
        if user_info:
            user_id = session['user_id']
            con = connect_database(DATABASE)
            cur = con.cursor()
            query_insert = "INSERT INTO group_user (user_id, group_id) VALUES (?, ?)"
            cur.execute(query_insert, (user_id, group_id))
            con.commit()
            con.close()
        con.close()
        print("sean")
    return render_template("groupsignup.html")


@app.route('/createassessment',methods=['POST','GET'])
def render_createassessment_page():
    return render_template("createassessment.html")

if __name__ == '__main__':
    app.run()
