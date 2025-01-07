# bank_app.py - Flask示例代码

from flask import Flask, request, redirect, url_for, session, render_template_string
import uuid

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# 模拟用户账户信息
user_data = {'user_id': 12345, 'balance': 1000}

# 转账操作（CSRF攻击的目标）
@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 检查CSRF Token是否正确
    csrf_token = request.form.get('csrf_token')
    if csrf_token != session.get('csrf_token'):
        return "CSRF validation failed", 403

    amount = float(request.form.get('amount'))
    if amount <= user_data['balance']:
        user_data['balance'] -= amount
        return f"Transfer successful! New balance: {user_data['balance']}"
    return "Insufficient funds."

# 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['user_id'] = user_data['user_id']
        # 为每个用户生成一个CSRF Token
        session['csrf_token'] = str(uuid.uuid4())
        return redirect(url_for('home'))
    return render_template_string('''
        <form method="POST">
            <input type="submit" value="Login">
        </form>
    ''')

# 用户首页，提供转账界面
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template_string('''
        <h1>Welcome, User!</h1>
        <p>Balance: ${{ balance }}</p>
        <form action="/transfer" method="POST">
            <input type="text" name="amount" placeholder="Amount to transfer">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="submit" value="Transfer">
        </form>
    ''', balance=user_data['balance'], csrf_token=session['csrf_token'])

if __name__ == '__main__':
    app.run(debug=True)
