from __future__ import annotations

from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from typing import List


class Base(DeclarativeBase):
    pass


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)


# TODO: Configure Flask-Login


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Gravator
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False, unique=True, )
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    # id: Mapped[int] = mapped_column(primary_key=True)
    # SQL to Blog Posts
    children: Mapped[List["BlogPost"]] = relationship(back_populates="parent")
    # SQL to Comments
    comment_list: Mapped[List["Comment"]] = relationship(back_populates="user_parent")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    # SQL
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    parent: Mapped["User"] = relationship(back_populates="children")
    # Comments Link
    comments_list: Mapped[List["Comment"]] = relationship(back_populates="blog_parent")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # One to many: User to Comments
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user_parent: Mapped["User"] = relationship(back_populates="comment_list")
    # One to Many : Blogpost to Comments
    blog_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    blog_parent: Mapped["BlogPost"] = relationship(back_populates="comments_list")


with app.app_context():
    db.create_all()

# Create Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    user_selected = db.session.execute(db.select(User).where(User.id == user_id)).scalar()
    return user_selected


# Create Admin decorator
def admin_only(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# DONE: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    form_name = request.form.get('name')
    form_email = request.form.get('email')
    form_password = request.form.get('password')
    if form_name is not None and form_password is not None and form_email is not None:
        output = generate_password_hash(password=form_password, method="pbkdf2", salt_length=8)
        new_user = User(
            name=form_name,
            email=form_email,
            password=output
        )
        user_selected = db.session.execute(db.select(User).where(User.email == form_email)).scalar()
        if user_selected is not None:
            flash('User already registered')
            return redirect(url_for("login", reg="True"))
        with app.app_context():
            db.session.add(new_user)
            db.session.expire_on_commit = False
            db.session.commit()
            login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=register_form)


# DONE: Retrieve a user from the database based on their email.
@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    email = request.form.get('email')
    password = request.form.get('password')
    if request.args.get('reg') is not None:
        flash("This email is already registered")
        return redirect(url_for("login"))
    if email is not None and password is not None:
        user_selected = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user_selected is None:
            flash('Email not registered')
            return redirect(url_for("register"))
        else:
            print("Password check")
            password_check = check_password_hash(user_selected.password, password)
            print(password_check)
            if password_check:
                # Login user
                login_user(user_selected)

                return redirect(url_for("get_all_posts"))
            else:
                flash('Incorrect password')
                return redirect(url_for("login"))

    return render_template("login.html", form=login_form)


@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@login_required
@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()

    if form.validate_on_submit():
        new_comment = Comment(
            body=form.body.data,
            user_id=current_user.id,
            blog_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    result = db.session.execute(db.select(Comment))
    comments = result.scalars().all()

    return render_template("post.html", post=requested_post, form=form, comments=comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    print(current_user.name)
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            user_id=current_user.id,
            author=current_user.name
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
@login_required
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5003)
