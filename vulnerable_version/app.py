from datetime import timedelta
from functools import wraps
from pathlib import Path
import re
import secrets
import sqlite3

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


base_dir = Path(__file__).resolve().parent
database_path = base_dir / "education_portal.db"
secret_path = base_dir / ".secret_key"

if not secret_path.exists():
    try:
        with secret_path.open("x", encoding="utf-8") as secret_file:
            secret_file.write(secrets.token_hex(32))
    except FileExistsError:
        pass

app = Flask(__name__)
app.secret_key = secret_path.read_text(encoding="utf-8").strip()

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=64 * 1024,
)


def get_db():
    if "database" not in g:
        g.database = sqlite3.connect(database_path)
        g.database.row_factory = sqlite3.Row
        g.database.execute("pragma foreign_keys = on")

    return g.database


@app.teardown_appcontext
def close_db(error=None):
    database = g.pop("database", None)

    if database is not None:
        database.close()


def init_db():
    database = get_db()

    database.executescript(
        """
        create table if not exists users (
            id integer primary key autoincrement,
            full_name text not null,
            email text not null unique collate nocase,
            password_hash text not null
        );

        create table if not exists courses (
            id integer primary key,
            title text not null,
            category text not null,
            description text not null,
            lesson text not null
        );

        create table if not exists enrollments (
            user_id integer not null references users(id),
            course_id integer not null references courses(id),
            primary key (user_id, course_id)
        );

        create table if not exists comments (
            id integer primary key autoincrement,
            user_id integer not null references users(id),
            course_id integer not null references courses(id),
            body text not null,
            created_at text not null default current_timestamp
        );
        """
    )

    course_rows = [
        (
            1,
            "Web Development Basics",
            "Development",
            "Explore how web pages, browsers and servers work together.",
            "HTML defines the structure of a web page. CSS controls its "
            "appearance. JavaScript adds interactions in the browser.\n\n"
            "A backend receives requests, validates input and communicates "
            "with a database. The browser displays the server response.\n\n"
            "Practice: draw a login form and list the checks that its "
            "backend must perform.",
        ),
        (
            2,
            "Information Security",
            "Security",
            "Understand the foundations of protecting information.",
            "Confidentiality limits who can read information. Integrity "
            "protects information from unauthorized changes. Availability "
            "keeps information accessible when needed.\n\n"
            "Authentication checks identity. Authorization determines "
            "what an authenticated user is allowed to do.\n\n"
            "Practice: explain why a logged-in student should not be able "
            "to update another student's profile.",
        ),
        (
            3,
            "Database Fundamentals",
            "Databases",
            "Learn how tables and relationships organize application data.",
            "A relational database stores records in tables. A primary "
            "key identifies a record. Foreign keys connect related tables.\n\n"
            "Parameterized queries keep user data separate from SQL "
            "instructions. Constraints protect data consistency.\n\n"
            "Practice: explain why the same student should not have "
            "duplicate enrollment records for one course.",
        ),
        (
            4,
            "Python Essentials",
            "Programming",
            "Start writing readable programs with variables and functions.",
            "Variables hold values. Functions group reusable operations. "
            "Conditions and loops control program execution.\n\n"
            "Use meaningful snake_case names such as user_name and "
            "get_courses. Keep indentation consistent.\n\n"
            "Practice: write a function that returns course names "
            "containing a search term.",
        ),
    ]

    database.executemany(
        """
        insert or ignore into courses
            (id, title, category, description, lesson)
        values (?, ?, ?, ?, ?)
        """,
        course_rows,
    )

    database.commit()


@app.before_request
def prepare_request():
    g.current_user = get_db().execute(
        "select id, full_name, email from users where id = ?",
        (session.get("user_id"),),
    ).fetchone()

    if request.method == "POST" and request.endpoint != "profile":
        expected_token = session.get("csrf_token", "")
        supplied_token = request.form.get("csrf_token", "")

        if not expected_token or not secrets.compare_digest(
            expected_token.encode("utf-8"),
            supplied_token.encode("utf-8"),
        ):
            abort(400, description="Form expired. Reload the page and try again.")

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


@app.context_processor
def template_context():
    return {
        "current_user": g.current_user,
        "csrf_token": session.get("csrf_token", ""),
    }


@app.after_request
def add_response_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"

    return response


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if g.current_user is None:
            return redirect("/login")

        return view_function(*args, **kwargs)

    return wrapped_view


def valid_email(email):
    return len(email) <= 254 and re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email,
    ) is not None


def start_session(user_id):
    session.clear()
    session["user_id"] = user_id
    session["csrf_token"] = secrets.token_hex(32)
    session.permanent = True


@app.route("/login", methods=["GET", "POST"])
@app.route("/signup", methods=["GET", "POST"])
def account():
    if g.current_user is not None:
        return redirect(url_for("dashboard"))

    is_signup = request.path == "/signup"

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        database = get_db()

        if is_signup:
            full_name = request.form.get("full_name", "").strip()

            if not 2 <= len(full_name) <= 80:
                flash("Enter a name between 2 and 80 characters.", "error")
            elif not valid_email(email):
                flash("Enter a valid email address.", "error")
            elif not 8 <= len(password) <= 128:
                flash("Use a password between 8 and 128 characters.", "error")
            else:
                try:
                    new_user = database.execute(
                        """
                        insert into users
                            (full_name, email, password_hash)
                        values (?, ?, ?)
                        """,
                        (
                            full_name,
                            email,
                            generate_password_hash(password),
                        ),
                    )
                    database.commit()
                except sqlite3.IntegrityError:
                    database.rollback()
                    flash("This email already has an account.", "error")
                else:
                    start_session(new_user.lastrowid)
                    flash("Account created. Welcome to Learnspace!", "success")

                    return redirect(url_for("dashboard"))

        else:
            user = database.execute(
                "select * from users where email = ?",
                (email,),
            ).fetchone()

            if (
                user is not None
                and len(password) <= 128
                and check_password_hash(user["password_hash"], password)
            ):
                start_session(user["id"])

                return redirect(url_for("dashboard"))

            flash("Email or password is incorrect.", "error")

    return render_template(
        "index.html",
        page="account",
        is_signup=is_signup,
    )


@app.post("/logout")
@login_required
def logout():
    session.clear()

    return redirect("/login")


@app.get("/")
@login_required
def dashboard():
    database = get_db()
    user_id = g.current_user["id"]
    search_query = request.args.get("q", "").strip()[:100]
    courses = database.execute(
        f"""
        select courses.*,
               exists (
                   select 1 from enrollments
                   where enrollments.course_id = courses.id
                   and enrollments.user_id = ?
               ) as enrolled
        from courses
        where title like '%{search_query}%' or category like '%{search_query}%'
        order by id
        """,
        (user_id,),
    ).fetchall()

    total_courses = database.execute(
        "select count(*) from courses"
    ).fetchone()[0]

    enrolled_count = database.execute(
        "select count(*) from enrollments where user_id = ?",
        (user_id,),
    ).fetchone()[0]

    comment_count = database.execute(
        "select count(*) from comments where user_id = ?",
        (user_id,),
    ).fetchone()[0]

    return render_template(
        "index.html",
        page="dashboard",
        courses=courses,
        search_query=search_query,
        total_courses=total_courses,
        enrolled_count=enrolled_count,
        comment_count=comment_count,
    )


def find_course(course_id):
    course = get_db().execute(
        "select * from courses where id = ?",
        (course_id,),
    ).fetchone()

    if course is None:
        abort(404, description="Course not found.")

    return course


@app.get("/courses/<int:course_id>")
@login_required
def course_detail(course_id):
    course = find_course(course_id)
    database = get_db()

    enrolled = database.execute(
        """
        select 1 from enrollments
        where user_id = ? and course_id = ?
        """,
        (g.current_user["id"], course_id),
    ).fetchone() is not None

    comments = database.execute(
        """
        select comments.body, comments.created_at, users.full_name
        from comments
        join users on users.id = comments.user_id
        where comments.course_id = ?
        order by comments.id desc
        """,
        (course_id,),
    ).fetchall()

    return render_template(
        "index.html",
        page="course",
        course=course,
        enrolled=enrolled,
        comments=comments,
    )


@app.post("/courses/<int:course_id>/enroll")
@login_required
def enroll_course(course_id):
    find_course(course_id)
    database = get_db()

    database.execute(
        """
        insert or ignore into enrollments (user_id, course_id)
        values (?, ?)
        """,
        (g.current_user["id"], course_id),
    )
    database.commit()

    flash("You have joined this course.", "success")

    return redirect(url_for("course_detail", course_id=course_id))


@app.post("/courses/<int:course_id>/comments")
@login_required
def add_comment(course_id):
    find_course(course_id)
    comment_body = request.form.get("comment_body", "").strip()

    if not 1 <= len(comment_body) <= 1000:
        flash("Write a comment between 1 and 1000 characters.", "error")
    else:
        database = get_db()

        database.execute(
            """
            insert into comments (user_id, course_id, body)
            values (?, ?, ?)
            """,
            (g.current_user["id"], course_id, comment_body),
        )
        database.commit()

        flash("Your comment has been posted.", "success")

    return redirect(url_for("course_detail", course_id=course_id))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        full_name = request.form.get(
            "full_name",
            g.current_user["full_name"],
        ).strip()

        email = request.form.get("email", "").strip().lower()

        if not 2 <= len(full_name) <= 80 or not valid_email(email):
            flash("Enter a valid name and email address.", "error")
        else:
            database = get_db()

            try:
                database.execute(
                    """
                    update users
                    set full_name = ?, email = ?
                    where id = ?
                    """,
                    (full_name, email, g.current_user["id"]),
                )
                database.commit()
            except sqlite3.IntegrityError:
                database.rollback()
                flash("That email belongs to another account.", "error")
            else:
                flash("Your profile has been updated.", "success")

                return redirect(url_for("profile"))

    return render_template("index.html", page="profile")


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)