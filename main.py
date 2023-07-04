from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Text, ForeignKey
from sqlalchemy.orm import mapped_column, relationship
from flask_login import UserMixin, AnonymousUserMixin, login_user, LoginManager, \
    login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from flask_bcrypt import Bcrypt
from functools import wraps
from dotenv import load_dotenv
import os


load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY")
ckeditor = CKEditor(app)
bootstrap = Bootstrap(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
gravatar = Gravatar(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = mapped_column(Integer, primary_key=True)
    title = mapped_column(String(250), unique=True, nullable=False)
    subtitle = mapped_column(String(250), nullable=False)
    date = mapped_column(String(250), nullable=False)
    body = mapped_column(Text, nullable=False)
    img_url = mapped_column(String(250), nullable=False)
    author_id = mapped_column(ForeignKey("users.id"))
    author = relationship("User", back_populates="blog_posts")
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = mapped_column(Integer, primary_key=True)
    body = mapped_column(Text, nullable=False)
    user_id = mapped_column(ForeignKey("users.id"))
    user = relationship("User")
    post_id = mapped_column(ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = mapped_column(Integer, primary_key=True)
    email = mapped_column(String(250), nullable=False, unique=True)
    password = mapped_column(String(250), nullable=False)
    name = mapped_column(String(250), nullable=False)
    blog_posts = relationship("BlogPost", back_populates="author")

    def get_id(self):
        return self.id


with app.app_context():
    db.create_all()


# admin_only decorator function
def admin_only(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if current_user.get_id() == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)
    return inner


@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(User).filter_by(id=user_id)).scalar_one_or_none()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect("/")
    else:
        form = RegisterForm()
        if form.validate_on_submit():
            # if found user with provided email address
            if db.session().execute(db.select(User).filter_by(email=form.email.data)).scalar_one_or_none():
                flash("You have already signed up with that email address, log in instead!")
                return redirect(url_for("login"))
            else:
                user = User()
                user.name = form.name.data
                user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user.email = form.email.data

                db.session.add(user)
                db.session.commit()

                login_user(user)
                return redirect('/')

        return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect("/")
    else:
        form = LoginForm()
        if form.validate_on_submit():
            user: User = db.session.execute(db.select(User).filter_by(email=form.email.data)).scalar_one_or_none()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect("/")
                else:
                    flash("Password is incorrect.")
            else:
                flash("User with this email does not exist.")

        return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)

    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comment()
            comment.body = form.body.data
            comment.post_id = post_id
            comment.user_id = current_user.get_id()
            db.session.add(comment)
            db.session.commit()
            # form.body.data = ""
            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You have to login to make comments.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        # --------------VVVV
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
