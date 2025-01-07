from flask import Flask, render_template, url_for, redirect, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from forms import RegistrationForm, LoginForm, ProfileForm, DocumentForm
from models import User, Document, UserOperation, db
from sqlalchemy import text
import os
import subprocess
from markupsafe import Markup


app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 设置密钥
app.config['SECRET_KEY'] = 'your_secret_key'
# SQLite数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db.init_app(app)
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@login_required
def home():
    documents = Document.query.filter_by(user_id=current_user.id).all()
    return render_template('home.html', documents=documents)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        operation = UserOperation(user_id=user.id, action='Registered')
        db.session.add(operation)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
    
'''@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            operation = UserOperation(user_id=user.id, action='Logged in')
            db.session.add(operation)
            db.session.commit()
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)'''
    
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # 构造 SQL 注入漏洞：不要这样做！
        email = form.email.data
        password = form.password.data
        
        # 直接拼接用户输入到查询中（仅限实验环境）
        query = f"SELECT * FROM user WHERE email='{email}' AND password='{password}'"
        result = db.session.execute(text(query)).fetchone()

        if result:
            user = User.query.get(result[0])  # 假设id是第一列
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')

    return render_template('login.html', title='Login', form=form)
  
@app.route("/logout")
@login_required
def logout():
    operation = UserOperation(user_id=current_user.id, action='Logged out')
    db.session.add(operation)
    db.session.commit()
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        operation = UserOperation(user_id=current_user.id, action='Updated profile')
        db.session.add(operation)
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', title='Profile', form=form)

@app.route("/users")
@login_required
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)

@app.route("/delete_user/<int:user_id>", methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:  # 假设存在管理员权限检查
        abort(403)
    user = User.query.get_or_404(user_id)
    operation = UserOperation(user_id=user.id, action=f'Deleted user {user.username}')
    db.session.add(operation)
    db.session.delete(user)
    db.session.commit()
    flash('The user has been deleted!', 'success')
    return redirect(url_for('users'))

@app.route("/operations")
@login_required
def operations():
    all_operations = UserOperation.query.order_by(UserOperation.timestamp.desc()).all()
    return render_template('operations.html', operations=all_operations)

@app.route("/new_document", methods=['GET', 'POST'])
@login_required
def new_document():
    form = DocumentForm()
    if form.validate_on_submit():
        document = Document(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(document)
        db.session.commit()
        operation = UserOperation(user_id=current_user.id, action=f'Created document "{form.title.data}"')
        db.session.add(operation)
        db.session.commit()
        flash('Your document has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_document.html', title='New Document', form=form, legend='New Document')

@app.route("/document/<int:doc_id>")
@login_required
def document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.author != current_user:
        abort(403)
    return render_template('document.html', title=document.title, document=document, content=document.content) #zuihouyige

@app.route("/document/<int:doc_id>/update", methods=['GET', 'POST'])
@login_required
def update_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.author != current_user:
        abort(403)
    form = DocumentForm()
    if form.validate_on_submit():
        document.title = form.title.data
        document.content = form.content.data
        db.session.commit()
        operation = UserOperation(user_id=current_user.id, action=f'Updated document "{form.title.data}"')
        db.session.add(operation)
        db.session.commit()
        flash('Your document has been updated!', 'success')
        return redirect(url_for('document', doc_id=document.id))
    elif request.method == 'GET':
        form.title.data = document.title
        form.content.data = document.content
    return render_template('create_document.html', title='Update Document', form=form, legend='Update Document')

@app.route("/document/<int:doc_id>/delete", methods=['POST'])
@login_required
def delete_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.author != current_user:
        abort(403)
    db.session.delete(document)
    db.session.commit()
    operation = UserOperation(user_id=current_user.id, action=f'Deleted document "{document.title}"')
    db.session.add(operation)
    db.session.commit()
    flash('Your document has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route("/document/<int:doc_id>")
@login_required
def view_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.author != current_user:
        abort(403)  # 禁止访问不属于当前用户的文档
    return render_template('view_document.html', title=document.title, document=document)
    
@app.route("/document/<int:doc_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.author != current_user:
        abort(403)  # 禁止访问不属于当前用户的文档

    form = DocumentForm(obj=document)  # 使用现有文档数据填充表单
    if form.validate_on_submit():
        document.title = form.title.data
        document.content = form.content.data
        db.session.commit()
        flash('Your document has been updated!', 'success')
        return redirect(url_for('view_document', doc_id=document.id))
    elif request.method == 'GET':
        form.title.data = document.title
        form.content.data = document.content
    return render_template('create_document.html', title='Edit Document', form=form, legend='Edit Document')

comments = []

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        user_comment = request.form.get('comment')
        # 构造 XSS 漏洞：不要这样做！
        comments.append(Markup(user_comment))  # 使用 Markup 防止自动转义

    return render_template('comments.html', comments=comments)

@app.route('/cmd', methods=['GET', 'POST'])
def cmd():
    if request.method == 'POST':
        user_input = request.form.get('cmd_input')
        # 构造命令注入漏洞：不要这样做！
        try:
            result = subprocess.check_output(f"echo {user_input}", shell=True, stderr=subprocess.STDOUT)
            return f"<pre>{result.decode()}</pre>"
        except subprocess.CalledProcessError as e:
            return f"An error occurred: {e.output.decode()}"
    
    return '''
        <form method="post">
            Command: <input type="text" name="cmd_input">
            <input type="submit" value="Execute">
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)
