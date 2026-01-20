"""
MoneyFlow Python - Main Flask Application
Combines: Flask app, configuration, all routes, session management
"""
import os
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SelectField, TextAreaField, DateField, SubmitField  # Add SubmitField to imports  
from wtforms.validators import DataRequired, Email, Length, NumberRange
from dotenv import load_dotenv 
# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-key-change-me-in-production')
app.config['ENCRYPTION_KEY'] = os.getenv('ENCRYPTION_KEY')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['DATA_DIR'] = 'data/users'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create necessary directories
os.makedirs(app.config['DATA_DIR'], exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)
os.makedirs('static/img', exist_ok=True)

# Import other modules
from core import Security, AuthService, ExpenseService, BudgetService, InsightService, NotificationService, ReportService
from storage import UserRepository, ExpenseRepository, BudgetRepository, NotificationRepository, SecureStorage

# ================= SIMPLE FIX =================
from cryptography.fernet import Fernet
import base64
import secrets

# Generate or validate encryption key
encryption_key = app.config.get('ENCRYPTION_KEY')

if not encryption_key:
    # Generate a new key
    encryption_key = Fernet.generate_key().decode()
    app.config['ENCRYPTION_KEY'] = encryption_key
    print(f"🔑 Generated new ENCRYPTION_KEY: {encryption_key}")
    print("⚠️  Save this key in your .env file!")
else:
    # Validate the key
    try:
        # Check if it's base64 encoded
        if isinstance(encryption_key, str):
            key_bytes = encryption_key.encode()
        else:
            key_bytes = encryption_key

        # Try to decode it
        decoded = base64.urlsafe_b64decode(key_bytes)
        if len(decoded) != 32:
            raise ValueError("Key must be 32 bytes when decoded")

        # Test it works
        Fernet(key_bytes)
        print(f"✅ Using provided ENCRYPTION_KEY")

    except Exception as e:
        print(f"❌ Invalid ENCRYPTION_KEY: {str(e)}")
        print(f"❌ Generating a new one...")
        encryption_key = Fernet.generate_key().decode()
        app.config['ENCRYPTION_KEY'] = encryption_key
        print(f"🔑 New ENCRYPTION_KEY: {encryption_key}")

# Initialize storage and services
storage = SecureStorage(app.config['ENCRYPTION_KEY'])
user_repo = UserRepository(storage)
expense_repo = ExpenseRepository(storage)
budget_repo = BudgetRepository(storage)
notification_repo = NotificationRepository(storage)

auth_service = AuthService(user_repo)
expense_service = ExpenseService(expense_repo, user_repo)
budget_service = BudgetService(budget_repo, expense_repo, user_repo)
insight_service = InsightService(expense_repo, budget_repo, user_repo)
notification_service = NotificationService(notification_repo, budget_service, user_repo)
report_service = ReportService(expense_repo, budget_repo, user_repo)

# ================= FORMS =================

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')  # Add this line

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')  # Add this line


class ExpenseForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    category = SelectField('Category', choices=[
        ('food', 'Food & Dining'),
        ('transport', 'Transportation'),
        ('shopping', 'Shopping'),
        ('entertainment', 'Entertainment'),
        ('bills', 'Bills & Utilities'),
        ('health', 'Health & Medical'),
        ('education', 'Education'),
        ('travel', 'Travel'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    date = DateField('Date', default=datetime.today, validators=[DataRequired()])
    description = TextAreaField('Description')

class BudgetForm(FlaskForm):
    category = SelectField('Category', choices=[
        ('food', 'Food & Dining'),
        ('transport', 'Transportation'),
        ('shopping', 'Shopping'),
        ('entertainment', 'Entertainment'),
        ('bills', 'Bills & Utilities'),
        ('health', 'Health & Medical'),
        ('education', 'Education'),
        ('travel', 'Travel'),
        ('other', 'Other'),
        ('overall', 'Overall Budget')
    ], validators=[DataRequired()])
    amount = FloatField('Budget Amount', validators=[DataRequired(), NumberRange(min=1)])
    period = SelectField('Period', choices=[
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly')
    ], default='monthly', validators=[DataRequired()])

# ================= DECORATORS =================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ================= ROUTES =================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = auth_service.login(form.email.data, form.password.data)
            if user:
                session['user_id'] = user.id
                session['user_email'] = user.email
                session['user_name'] = user.full_name
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'danger')
        except Exception as e:
            flash(f'Login error: {str(e)}', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])  
def register():  
    if 'user_id' in session:  
        return redirect(url_for('dashboard'))  
      
    form = RegisterForm()  
    if form.validate_on_submit():  
        try:  
            user = auth_service.register(  
                email=form.email.data,  
                password=form.password.data,  
                full_name=form.full_name.data  
            )  
            if user:  
                # FIXED: User object accessed with direct attributes  
                # User is a dataclass with .id, .email, .full_name attributes  
                # NOT a dictionary, so no .get() method available  
                flash('Registration successful! Please log in.', 'success')  
                return redirect(url_for('login'))  
            else:  
                flash('Registration failed. User may already exist.', 'danger')  
        except Exception as e:  
            flash(f'Registration error: {str(e)}', 'danger')  
      
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    
    # Get recent expenses
    expenses = expense_service.get_user_expenses(user_id, limit=10)
    total_expenses = sum(e.amount for e in expenses)
    
    # Get budgets
    budgets = budget_service.get_user_budgets(user_id)
    
    # Get insights for dashboard
    category_totals = insight_service.get_category_totals(user_id)
    monthly_trend = insight_service.get_monthly_trend(user_id, months=6)
    
    # Get notifications
    notifications = notification_service.get_user_notifications(user_id, limit=5)
    
    return render_template('dashboard.html',
                         expenses=expenses,
                         total_expenses=total_expenses,
                         budgets=budgets,
                         category_totals=category_totals,
                         monthly_trend=monthly_trend,
                         notifications=notifications)

@app.route('/expenses')
@login_required
def expenses():
    user_id = session['user_id']
    
    # Get filter parameters
    category = request.args.get('category', 'all')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Get expenses with filters
    expenses_list = expense_service.get_user_expenses(
        user_id, 
        category=None if category == 'all' else category,
        start_date=datetime.fromisoformat(start_date) if start_date else None,
        end_date=datetime.fromisoformat(end_date) if end_date else None
    )
    
    # Get totals
    total_amount = sum(e.amount for e in expenses_list)
    category_totals = insight_service.get_category_totals(user_id)
    
    form = ExpenseForm()
    
    return render_template('expenses.html',
                         expenses=expenses_list,
                         total_amount=total_amount,
                         category_totals=category_totals,
                         form=form,
                         selected_category=category)

@app.route('/expenses/add', methods=['POST'])
@login_required
def add_expense():
    user_id = session['user_id']
    form = ExpenseForm()
    
    if form.validate_on_submit():
        try:
            expense = expense_service.add_expense(
                user_id=user_id,
                amount=form.amount.data,
                category=form.category.data,
                description=form.description.data,
                date=form.date.data
            )
            
            # Check if budget exceeded
            budget_check = budget_service.check_budget_exceeded(user_id, expense.category)
            if budget_check['exceeded']:
                notification_service.create_budget_alert(
                    user_id=user_id,
                    category=expense.category,
                    spent=budget_check['spent'],
                    budget=budget_check['budget']
                )
            
            flash('Expense added successfully!', 'success')
            return jsonify({
                'success': True,
                'expense': {
                    'id': expense.id,
                    'amount': expense.amount,
                    'category': expense.category,
                    'date': expense.date.isoformat(),
                    'description': expense.description
                }
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    return jsonify({'success': False, 'errors': form.errors}), 400

@app.route('/expenses/<expense_id>/delete', methods=['DELETE'])
@login_required
def delete_expense(expense_id):
    user_id = session['user_id']
    
    try:
        success = expense_service.delete_expense(user_id, expense_id)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Expense not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/budgets')
@login_required
def budgets():
    user_id = session['user_id']
    
    budgets_list = budget_service.get_user_budgets(user_id)
    budgets_with_progress = []
    
    for budget in budgets_list:
        progress = budget_service.get_budget_progress(user_id, budget.category)
        budgets_with_progress.append({
            'budget': budget,
            'progress': progress
        })
    
    form = BudgetForm()
    
    return render_template('budgets.html',
                         budgets=budgets_with_progress,
                         form=form)

@app.route('/budgets/add', methods=['POST'])
@login_required
def add_budget():
    user_id = session['user_id']
    form = BudgetForm()
    
    if form.validate_on_submit():
        try:
            budget = budget_service.create_budget(
                user_id=user_id,
                category=form.category.data,
                amount=form.amount.data,
                period=form.period.data
            )
            flash('Budget created successfully!', 'success')
            return jsonify({'success': True, 'budget_id': budget.id})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    return jsonify({'success': False, 'errors': form.errors}), 400

@app.route('/budgets/<budget_id>/delete', methods=['DELETE'])
@login_required
def delete_budget(budget_id):
    user_id = session['user_id']
    
    try:
        success = budget_service.delete_budget(user_id, budget_id)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Budget not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/insights')
@login_required
def insights():
    user_id = session['user_id']
    
    # Get data for charts
    category_totals = insight_service.get_category_totals(user_id)
    monthly_trend = insight_service.get_monthly_trend(user_id, months=12)
    budget_vs_actual = insight_service.get_budget_vs_actual(user_id)
    spending_by_day = insight_service.get_spending_by_day(user_id, days=30)
    
    return render_template('insights.html',
                         category_totals=category_totals,
                         monthly_trend=monthly_trend,
                         budget_vs_actual=budget_vs_actual,
                         spending_by_day=spending_by_day)

@app.route('/insights/data')
@login_required
def insights_data():
    user_id = session['user_id']
    chart_type = request.args.get('type', 'categories')
    
    if chart_type == 'categories':
        data = insight_service.get_category_totals(user_id)
    elif chart_type == 'monthly':
        data = insight_service.get_monthly_trend(user_id, months=12)
    elif chart_type == 'budget':
        data = insight_service.get_budget_vs_actual(user_id)
    elif chart_type == 'daily':
        data = insight_service.get_spending_by_day(user_id, days=30)
    else:
        return jsonify({'error': 'Invalid chart type'}), 400
    
    return jsonify(data)

@app.route('/notifications')
@login_required
def notifications():
    user_id = session['user_id']
    
    notifications_list = notification_service.get_user_notifications(user_id)
    unread_count = len([n for n in notifications_list if not n.read])
    
    return render_template('notifications.html',
                         notifications=notifications_list,
                         unread_count=unread_count)

@app.route('/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    user_id = session['user_id']
    
    try:
        success = notification_service.mark_as_read(user_id, notification_id)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Notification not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/notifications/clear-all', methods=['POST'])
@login_required
def clear_all_notifications():
    user_id = session['user_id']
    
    try:
        notification_service.clear_all_notifications(user_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/reports')
@login_required
def reports():
    user_id = session['user_id']
    
    return render_template('reports.html')

@app.route('/reports/generate', methods=['POST'])
@login_required
def generate_report():
    user_id = session['user_id']
    report_type = request.form.get('type', 'expenses')
    period = request.form.get('period', 'month')
    format_type = request.form.get('format', 'html')
    
    try:
        report_data = report_service.generate_report(
            user_id=user_id,
            report_type=report_type,
            period=period,
            format_type=format_type
        )
        
        if format_type == 'pdf':
            # Return PDF file
            return send_file(
                report_data['file_path'],
                as_attachment=True,
                download_name=report_data['filename']
            )
        else:
            # Return HTML report
            return render_template('report_view.html', **report_data)
            
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'danger')
        return redirect(url_for('reports'))

@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    
    try:
        user = user_repo.get_user(user_id)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('dashboard'))
        
        # Get user stats
        total_expenses = expense_service.get_total_expenses(user_id)
        active_budgets = budget_service.get_active_budgets_count(user_id)
        
        return render_template('profile.html',
                             user=user,
                             total_expenses=total_expenses,
                             active_budgets=active_budgets)
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    user_id = session['user_id']
    full_name = request.form.get('full_name', '').strip()
    
    if not full_name or len(full_name) < 2:
        flash('Full name must be at least 2 characters', 'danger')
        return redirect(url_for('profile'))
    
    try:
        success = auth_service.update_profile(user_id, full_name)
        if success:
            session['user_name'] = full_name
            flash('Profile updated successfully!', 'success')
        else:
            flash('Failed to update profile', 'danger')
    except Exception as e:
        flash(f'Error updating profile: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    user_id = session['user_id']
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password:
        flash('All password fields are required', 'danger')
        return redirect(url_for('profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('profile'))
    
    if len(new_password) < 6:
        flash('New password must be at least 6 characters', 'danger')
        return redirect(url_for('profile'))
    
    try:
        success = auth_service.change_password(user_id, current_password, new_password)
        if success:
            flash('Password changed successfully!', 'success')
        else:
            flash('Current password is incorrect', 'danger')
    except Exception as e:
        flash(f'Error changing password: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))

# ================= ERROR HANDLERS =================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(e):
    return "File too large", 413

# ================= API ENDPOINTS (for AJAX) =================

@app.route('/api/expenses')
@login_required
def api_expenses():
    user_id = session['user_id']
    
    expenses = expense_service.get_user_expenses(user_id)
    expenses_data = []
    
    for expense in expenses:
        expenses_data.append({
            'id': expense.id,
            'amount': expense.amount,
            'category': expense.category,
            'date': expense.date.isoformat(),
            'description': expense.description
        })
    
    return jsonify({'expenses': expenses_data})

@app.route('/api/budgets/progress')
@login_required
def api_budgets_progress():
    user_id = session['user_id']
    
    budgets = budget_service.get_user_budgets(user_id)
    progress_data = []
    
    for budget in budgets:
        progress = budget_service.get_budget_progress(user_id, budget.category)
        progress_data.append({
            'category': budget.category,
            'budget': budget.amount,
            'spent': progress['spent'],
            'percentage': progress['percentage'],
            'exceeded': progress['exceeded']
        })
    
    return jsonify({'budgets': progress_data})

@app.route('/api/notifications/count')
@login_required
def api_notifications_count():
    user_id = session['user_id']
    
    notifications = notification_service.get_user_notifications(user_id)
    unread_count = len([n for n in notifications if not n.read])
    
    return jsonify({'count': unread_count})



@app.route('/api/auth/check')  
@login_required  
def api_auth_check():  
    user_id = session['user_id']  
    user = user_repo.get_user(user_id)  
    if user:  
        return jsonify({  
            'authenticated': True,   
            'user': {  
                'id': user.id,  
                'email': user.email,  
                'full_name': user.full_name  
            }  
        })  
    return jsonify({'authenticated': False})  
  
@app.route('/api/notifications')  
@login_required  
def api_notifications():  
    user_id = session['user_id']  
    notifications = notification_service.get_user_notifications(user_id)  
    return jsonify({  
        'notifications': [  
            {  
                'id': n.id,  
                'message': n.message,  
                'type': n.type,  
                'date': n.created_at.strftime('%Y-%m-%d'),  
                'read': n.read  
            } for n in notifications[:5]  
        ]  
    })
# ================= MAIN ENTRY POINT =================

if __name__ == '__main__':
    # Generate encryption key if not exists
    if not app.config['ENCRYPTION_KEY']:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        print(f"Generated ENCRYPTION_KEY: {key}")
        print("Add this to your .env file as ENCRYPTION_KEY=")
        app.config['ENCRYPTION_KEY'] = key
    
    app.run(debug=True, host='0.0.0.0', port=5000)