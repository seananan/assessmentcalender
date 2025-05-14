import sqlite3
from datetime import date
from sqlite3 import Error

from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "secret_key"
DATABASE = 'DB_FILE'
today = date.today()
wrong_password = False


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

@app.context_processor
def inject_user():
    """
    Injects user info into all templates
    :return:
        logged in, true if user is logged in
        is_teacher: true if user is teacher
    """
    return{
        'logged_in': session.get('user_id') is not None,
        'is_teacher': session.get('is_teacher')
    }


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


@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():
    """
    :return: Renders signup page
    """
    if request.method == 'POST':
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
            session['logged_in = True'] = True
            redirect('/')
        hashed_password = bcrypt.generate_password_hash(password1)
        con = connect_database(DATABASE)
        cur = con.cursor()
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


@app.route('/login', methods=['POST', 'GET'])
def render_login_page():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('user_password1')
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "SELECT password, user_id, email, is_teacher FROM user WHERE email = ?"
        cur.execute(query, (email,))
        user_info = cur.fetchone()
        con.close()
        session["logged_in"] = True

        if user_info:
            stored_password = user_info[0]

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


@app.route('/creategroup', methods=['POST', 'GET'])
def render_creategroup_page():
    subjects = ["Art", "Biology", "Chemistry", "Drama", "English", "Geography", "History", "Mathematics", "Music",
                "Physics"]
    if request.method == 'POST':
        subject = request.form.get('subject')
        level = request.form.get('level')
        password = request.form.get('password')
        user_id = session['user_id']

        con = connect_database(DATABASE)
        cur = con.cursor()

        query_insert = "INSERT INTO group_class (group_subject, group_year, group_password, fk_user_id) VALUES (?, ?, ?, ?)"
        cur.execute(query_insert, (subject, level, password, user_id))

        con.commit()
        con.close()

        redirect("/")
    return render_template("creategroup.html", subjects=subjects)


@app.route('/yourgroups', methods=['POST', 'GET'])
def render_yourgroups_page():
    user_id = session.get('user_id')
    if not user_id:
        return redirect("/")

    con = connect_database(DATABASE)
    cur = con.cursor()

    query = "SELECT group_class.group_id,group_class.group_subject, group_class.group_year, user.first_name, user.last_name, user.email FROM group_user JOIN user ON group_user.fk_user_id=user.user_id JOIN group_class ON group_user.fk_group_id=group_class.group_id WHERE group_user.fk_user_id=?;"
    cur.execute(query, (user_id,))
    john = cur.fetchall()

    con.commit()
    con.close()


    return render_template("yourgroups.html", classes=john)


@app.route('/groupsignup', methods=['POST', 'GET'])
def render_groupsignup_page():
    wrong_password = False

    if request.method == 'POST':
        password = request.form.get('code')


        con = connect_database(DATABASE)
        cur = con.cursor()

        query = "SELECT group_id FROM group_class WHERE group_password = ?"
        cur.execute(query, (password,))
        result = cur.fetchall()

        con.commit()
        con.close()

        if result:
            user_id = session['user_id']
            group_id = result[0][0]


            con = connect_database(DATABASE)
            cur = con.cursor()

            query_insert = "INSERT INTO group_user (fk_group_id, fk_user_id) VALUES (?, ?)"
            cur.execute(query_insert, (group_id, user_id))

            con.commit()
            con.close()
        else:
            wrong_password = True
        con.close()

        redirect('/')
    return render_template("groupsignup.html", wrong_password=wrong_password)


@app.route('/groups/<int:group_id>', methods=['POST', 'GET'])
def render_groups_page(group_id):
    user_id = session['user_id']
    if not user_id:
        return redirect("/login")

    con = connect_database(DATABASE)
    cur = con.cursor()
    query = "SELECT fk_user_id FROM group_user WHERE fk_group_id = ?"
    cur.execute(query, (group_id,))
    result2 = cur.fetchone()
    query2 = "SELECT assessments.as_num, assessments.as_name, assessments.credits, assessments.d_date, assessments.d_time FROM as_group JOIN assessments ON fk_as_id=as_id"
    cur.execute(query2,)
    assessment_info=cur.fetchall()
    print(assessment_info)
    if result2:
        group_owner_id = result2[0]
        is_owner = (user_id == group_owner_id)


        return render_template('groups.html', is_owner=is_owner, group_id=group_id, assessment_info=assessment_info)
    else:
        return "group not found", 404


@app.route('/createassessment', methods=['POST', 'GET'])
def render_createassessment_page():

    if request.method == 'POST':
        as_num = request.form.get('as_n')
        as_name = request.form.get('as_name')
        credits = request.form.get('credits')
        d_date = request.form.get('d_date')
        d_time = request.form.get('d_time')
        s_date = request.form.get('date_start')
        as_type = request.form.get('as_type')

        con = connect_database(DATABASE)
        cur = con.cursor()
        query_insert = "INSERT INTO assessments(as_num, as_name, credits, d_date, d_time, s_date, type) VALUES (?,?,?,?,?,?,?)"
        cur.execute(query_insert, (as_num, as_name, credits, d_date, d_time, s_date, as_type))
        con.commit()
        con.close()
        redirect('/')
    return render_template("createassessment.html")


@app.route('/addassessment/<int:group_id>', methods=['POST', 'GET'])
def render_addassessment_page(group_id):
    print(group_id)
    con = connect_database(DATABASE)
    cur = con.cursor()
    query2 = "SELECT as_num, as_name, as_id FROM assessments"
    cur.execute(query2)
    amount_as = cur.fetchall()
    if request.method == 'POST':
        as_id=request.form.get('assessment')
        print(as_id)
        query_insert = "INSERT INTO as_group(fk_group_id, fk_as_id) VALUES (?, ?)"
        cur.execute(query_insert, (group_id, as_id[0]))
        con.commit()
        con.close()

    return render_template("addassessment.html", amount_as=amount_as)


if __name__ == '__main__':
    app.run()
