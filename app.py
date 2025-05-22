import sqlite3
from sqlite3 import Error

from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "secret_key"

DATABASE = "DB_FILE"


def connect_database(db_file):
    """
    Establish a connection to the SQLite database
    :param db_file: Path to the SQLite database file
    :return: SQLite connection object or None on failure
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
    Inject user login status and role across all templates.
    :return: dictionary containing 'logged_in' (bool) and 'is_teacher' (bool) for templates
    """
    return {
        'logged_in': session.get('user_id') is not None,
        'is_teacher': session.get('is_teacher')
    }


@app.route("/")
def render_homepage():
    """
    Render the home page.
    :return: Rendered 'home.html' template with user_name variable (unless not logged in)
    """
    username = None

    if "user_id" in session:
        con = connect_database(DATABASE)
        cur = con.cursor()
        query = "SELECT first_name FROM user WHERE user_id = ?"
        cur.execute(query, (session["user_id"],))
        name = cur.fetchone()
        con.close()
        if name:
            username = name[0]
    return render_template("home.html", user_name=username)


@app.route("/signup", methods=["POST", "GET"])
def render_signup_page():
    """
    Display signup form or process new user registration.
    On GET, presents signup form.
    On POST, validates inputs, checks if email is unique, hashes password, inserts user information into session.
    :return: Redirect to home on success, or render "signup.html" if an error occurred.
    """

    if request.method == "POST":
        fname = request.form.get("user_fname").title().strip()
        lname = request.form.get("user_lname").title().strip()
        email = request.form.get("user_email").lower().strip()
        password1 = request.form.get("user_password1")
        password2 = request.form.get("user_password2")
        user_role = request.form.get("user_role")

        # Validate password match
        if password1 != password2:
            return redirect("/signup?error=passwords+do+not+match")

        # Ensure password length
        if len(password1) < 8:
            return redirect("/signup?error=password+must+be+over+8+characters")

        hashed_password = bcrypt.generate_password_hash(password1)  # Hash the password
        con = connect_database(DATABASE)
        cur = con.cursor()
        is_teacher = 1 if user_role == "Teacher" else 0

        # Check for existing email
        query = "SELECT email FROM user WHERE email = ?"
        cur.execute(query, (email,))

        if cur.fetchall():
            con.close()
            return redirect("/signup?error=email+already+in+use")

        # Insert new user
        query_insert = (
            "INSERT INTO user (first_name, last_name, email, password, is_teacher) "
            "VALUES (?, ?, ?, ?, ?)"
        )
        cur.execute(query_insert, (fname, lname, email, hashed_password, is_teacher))
        user_id = cur.lastrowid
        con.commit()
        con.close()

        # Initialize session
        session["user_id"] = user_id
        session["logged_in"] = True
        session["is_teacher"] = bool(is_teacher)
        return redirect("/")
    return render_template("signup.html")


@app.route("/login", methods=["POST", "GET"])
def render_login_page():
    """
    Display login form.
    On GET, shows login form.
    On POST, verifies password and sets user info into session .
    :return: Redirect to home on success or back to login page if there is an error
    """

    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        password = request.form.get("user_password1")
        con = connect_database(DATABASE)
        cur = con.cursor()

        # Retrieve stored hash and user info
        query = "SELECT password, user_id, email, is_teacher FROM user WHERE email = ?"
        cur.execute(query, (email,))
        user_info = cur.fetchone()
        con.close()

        if user_info and bcrypt.check_password_hash(user_info[0], password):
            session["user_id"] = user_info[1]
            session["email"] = user_info[2]
            session["is_teacher"] = bool(user_info[3])
            session["logged_in"] = True
            return redirect("/")
        return redirect("/login?error=email+or+password+invalid")
    return render_template("login.html")


@app.route("/logout")
def render_logout_page():
    """
    Log the user out by clearing the session.
    :return: Redirect to home page
    """
    session.clear()  # Remove all session data
    return redirect("/")


@app.route("/userprofile")
def render_profile_page():
    """
    Show the current user's profile information.
    Retrieves first name, last name, and email from the user table.
    :return: Render 'userprofile.html' with user_info
    """
    user_id = session.get("user_id")

    con = connect_database(DATABASE)
    cur = con.cursor()

    query = "SELECT first_name, last_name, email FROM user WHERE user_id = ?"
    cur.execute(query, (user_id,))
    user_info = cur.fetchone()

    con.commit()
    con.close()

    return render_template("userprofile.html", user_info=user_info)


@app.route("/editinfo", methods=["POST", "GET"])
def render_edit_info_page():
    """
    Allow logged-in users to update their personal information.
    On POST, updates fields provided.
    :return: Render "editinfo.html" on GET, redirect to "/userprofile" on POST
    """
    user_id = session.get("user_id")

    if not user_id:
        return redirect("/login")

    con = connect_database(DATABASE)
    cur = con.cursor()

    query = "SELECT first_name, last_name, email, password FROM user WHERE user_id = ?"
    cur.execute(query, (user_id,))
    user_info = cur.fetchone()
    con.close()

    if request.method == "POST":
        update_fname = request.form.get("user_fname").title().strip()
        update_lname = request.form.get("user_lname").title().strip()
        update_email = request.form.get("user_email").lower().strip()
        update_password = request.form.get("user_password1")

        fname = update_fname if update_fname else user_info[0]
        lname = update_lname if update_lname else user_info[1]
        email = update_email if update_email else user_info[2]
        password = update_password if update_password else user_info[3]

        con = connect_database(DATABASE)
        cur = con.cursor()

        query_update = "UPDATE user SET first_name = ?, last_name = ?, email = ?, password = ? WHERE user_id = ?"
        cur.execute(query_update, (fname, lname, email, password, user_id))

        con.commit()
        con.close()
        return redirect("/userprofile")

    return render_template("editinfo.html")


@app.route("/creategroup", methods=["POST", "GET"])
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

        # Redirect back to homepage after successful create
        redirect("/")

    return render_template("creategroup.html", subjects=subjects)


@app.route("/yourgroups", methods=["POST", "GET"])
def render_yourgroups_page():
    """
    List all groups the user has joined.
    Retrieves user_info and teacher info.
    :return: Render "yourgroups.html" with all class information.
    """
    user_id = session.get("user_id")

    if not user_id:
        return redirect("/")

    con = connect_database(DATABASE)
    cur = con.cursor()

    query = (
         "SELECT group_class.group_id,group_class.group_subject, group_class.group_year, group_class.fk_user_id "
         "FROM group_user "
         "INNER JOIN user ON group_user.fk_user_id=user.user_id "
         "INNER JOIN group_class ON group_user.fk_group_id=group_class.group_id "
         "WHERE group_user.fk_user_id=?;"
    )
    cur.execute(query, (user_id,))
    classes = cur.fetchall()

    if not classes:
        con.close()
        return render_template("yourgroups.html", classes=[], teacher_info=None)
    teacher_id = classes[0][3]

    query = "SELECT first_name, last_name, email FROM user WHERE user_id = ?"
    cur.execute(query, (teacher_id,))
    teacher_info = cur.fetchall()

    con.commit()
    con.close()

    return render_template("yourgroups.html", classes=classes, teacher_info=teacher_info)


@app.route("/groupsignup", methods=["POST", "GET"])
def render_groupsignup_page():
    """
    Join a group using a join code.
    On POST, verifies code and adds user to that group.
    :return: Render "groupsignup.html" with wrong_password message or a redirect to "/yourgroups"
    """
    wrong_password = False

    if request.method == "POST":
        password = request.form.get("code")

        con = connect_database(DATABASE)
        cur = con.cursor()

        query = "SELECT group_id FROM group_class WHERE group_password = ?"
        cur.execute(query, (password,))
        result = cur.fetchall()

        con.commit()
        con.close()

        if result:
            user_id = session["user_id"]
            group_id = result[0][0]

            con = connect_database(DATABASE)
            cur = con.cursor()

            query_insert = "INSERT INTO group_user (fk_group_id, fk_user_id) VALUES (?, ?)"
            cur.execute(query_insert, (group_id, user_id))

            con.commit()
            con.close()
            return redirect("/yourgroups")
        else:
            wrong_password = True
        con.close()

        redirect('/')
    return render_template("groupsignup.html", wrong_password=wrong_password)


@app.route("/groups/<int:group_id>", methods=["POST", "GET"])
def render_groups_page(group_id):
    """
    Display table of assessments within a specific group.
    :param group_id: ID of the group to view
    :return: Render "groups.html" with is_owner, group_id, assessment_info, and group_name
    """
    user_id = session["user_id"]
    if not user_id:
        return redirect("/login")

    con = connect_database(DATABASE)
    cur = con.cursor()

    query = "SELECT fk_user_id FROM group_user WHERE fk_group_id = ?"
    cur.execute(query, (group_id,))
    owner_id = cur.fetchone()

    query2 = (
        "SELECT assessments.as_num, assessments.as_name, assessments.credits, assessments.d_date, assessments.d_time, assessments.as_id "
        "FROM as_group "
        "JOIN assessments ON fk_as_id=as_id "
        "WHERE fk_group_id=?")
    cur.execute(query2, (group_id,))
    assessment_info = cur.fetchall()

    query3 = "SELECT group_subject, group_year FROM group_class WHERE group_id=?"
    cur.execute(query3, (group_id,))
    group_name = cur.fetchall()

    if owner_id:
        group_owner_id = owner_id[0]
        is_owner = (user_id == group_owner_id)

        return render_template("groups.htm", is_owner=is_owner, group_id=group_id, assessment_info=assessment_info,
                               group_name=group_name)

    else:
        return "group not found", 404


@app.route("/createassessment", methods=["POST", "GET"])
def render_createassessment_page():
    """
    Create an assessment entry in the database.
    On POST, inserts assessment details into assessments table.
    :return: Render "createassessment.html" or redirect to "/" on success
    """
    if request.method == "POST":
        as_num = request.form.get("as_n")  # Assessment number/code
        as_name = request.form.get("as_name")  # Assessment name
        credits = request.form.get("credits")  # Credit value
        d_date = request.form.get("d_date")  # Due date
        d_time = request.form.get("d_time")  # Time due
        s_date = request.form.get("date_start")  # Start date
        as_type = request.form.get("as_type")  # Assessment type

        con = connect_database(DATABASE)
        cur = con.cursor()

        # Insert new assessment into table
        query_insert = "INSERT INTO assessments(as_num, as_name, credits, d_date, d_time, s_date, type) VALUES (?,?,?,?,?,?,?)"
        cur.execute(query_insert, (as_num, as_name, credits, d_date, d_time, s_date, as_type))

        con.commit()  # Save changes
        con.close()

        # Go back to homepage
        redirect("/")

    return render_template("createassessment.html")


@app.route("/addassessment/<int:group_id>", methods=["POST", "GET"])
def render_addassessment_page(group_id):
    """
    Link an existing assessment to a specific group.
    On GET, lists available assessments.
    On POST, inserts link record.
    :param group_id: ID of the group
    :return: Render "addassessment.html" with amount_as and group_id, or redirect to group page
    """
    con = connect_database(DATABASE)
    cur = con.cursor()

    # Fetch all assessments for selection
    query2 = "SELECT as_num, as_name, as_id FROM assessments"
    cur.execute(query2)
    amount_as = cur.fetchall()

    if request.method == "POST":
        as_id = request.form.get("assessment")  # Selected assessment id
        query_insert = "INSERT INTO as_group(fk_group_id, fk_as_id) VALUES (?, ?)"
        cur.execute(query_insert, (group_id, as_id[0]))
        con.commit()
        con.close()
        return redirect(f"/groups/{group_id}")

    con.close()
    return render_template("addassessment.html", amount_as=amount_as, group_id=group_id)


@app.route("/remove_assessment", methods=["POST", "GET"])
def render_remove_assessment_page():
    """
    Remove an assessment link from within group.
    On POST, deletes link record.
    :return: Redirect back to referring page
    """

    if request.method == "POST":
        as_info = request.form.get("as_id")
        # Get the assessment id to remove
        as_id = as_info.strip()

        con = connect_database(DATABASE)
        cur = con.cursor()

        # Delete the record linking group and assessment
        query = "DELETE FROM as_group WHERE fk_as_id=?"
        cur.execute(query, (as_id,))

        con.commit()
        con.close()
    # Return to the previous page after removal
    return redirect(request.referrer)


if __name__ == "__main__":
    app.run()
