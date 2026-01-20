"""
MoneyFlow Python - Core Business Logic, Models & Services
Combines: Models, Services, Security, Exceptions
"""
import uuid
import hashlib
from datetime import datetime, date, timedelta
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum
from abc import ABC, abstractmethod
from decimal import Decimal, ROUND_HALF_UP

# ================= EXCEPTIONS =================

class MoneyFlowException(Exception):
    """Base exception for MoneyFlow application"""
    pass

class AuthenticationError(MoneyFlowException):
    """Authentication related errors"""
    pass

class ValidationError(MoneyFlowException):
    """Data validation errors"""
    pass

class StorageError(MoneyFlowException):
    """File storage errors"""
    pass

class EncryptionError(MoneyFlowException):
    """Encryption/decryption errors"""
    pass

class NotFoundError(MoneyFlowException):
    """Resource not found errors"""
    pass

# ================= MODELS =================

@dataclass
class User:
    """User model"""
    id: str
    email: str
    full_name: str
    hashed_password: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'User':
        """Create from dictionary"""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        return cls(**data)

@dataclass
class Expense:
    """Expense model"""
    id: str
    user_id: str
    amount: float
    category: str
    date: datetime
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['date'] = self.date.isoformat()
        data['created_at'] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Expense':
        """Create from dictionary"""
        data['date'] = datetime.fromisoformat(data['date'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)

@dataclass
class Budget:
    """Budget model"""
    id: str
    user_id: str
    category: str
    amount: float
    period: str  # 'monthly' or 'yearly'
    start_date: datetime = field(default_factory=datetime.now)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['start_date'] = self.start_date.isoformat()
        data['created_at'] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Budget':
        """Create from dictionary"""
        data['start_date'] = datetime.fromisoformat(data['start_date'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)

@dataclass
class Notification:
    """Notification model"""
    id: str
    user_id: str
    message: str
    type: str  # 'info', 'warning', 'alert', 'success'
    read: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Notification':
        """Create from dictionary"""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)

# ================= SECURITY =================

class Security:
    """Security utilities for encryption and hashing"""
    
    def __init__(self, encryption_key: str):
        """
        Initialize security with encryption key
        
        Args:
            encryption_key: Fernet encryption key as string
        """
        from cryptography.fernet import Fernet, InvalidToken
        from passlib.hash import bcrypt
        
        self.fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        self.bcrypt = bcrypt
    
    def encrypt(self, data: str) -> bytes:
        """
        Encrypt a string
        
        Args:
            data: String to encrypt
            
        Returns:
            Encrypted bytes
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            return self.fernet.encrypt(data.encode('utf-8'))
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """
        Decrypt bytes to string
        
        Args:
            encrypted_data: Bytes to decrypt
            
        Returns:
            Decrypted string
            
        Raises:
            EncryptionError: If decryption fails
        """
        try:
            return self.fernet.decrypt(encrypted_data).decode('utf-8')
        except InvalidToken:
            raise EncryptionError("Invalid encryption token - data may be corrupted")
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {str(e)}")
    
    def encrypt_dict(self, data: Dict) -> bytes:
        """
        Encrypt a dictionary to JSON string
        
        Args:
            data: Dictionary to encrypt
            
        Returns:
            Encrypted bytes
        """
        import json
        json_str = json.dumps(data, default=str)
        return self.encrypt(json_str)
    
    def decrypt_dict(self, encrypted_data: bytes) -> Dict:
        """
        Decrypt bytes to dictionary
        
        Args:
            encrypted_data: Encrypted bytes
            
        Returns:
            Decrypted dictionary
        """
        import json
        json_str = self.decrypt(encrypted_data)
        return json.loads(json_str)
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        return self.bcrypt.hash(password)
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            password: Plain text password
            hashed_password: Hashed password
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return self.bcrypt.verify(password, hashed_password)
        except Exception:
            return False
    
    def generate_user_id(self, email: str) -> str:
        """
        Generate a unique user ID from email
        
        Args:
            email: User's email
            
        Returns:
            Unique user ID
        """
        # Use SHA256 hash of email + timestamp for uniqueness
        timestamp = str(datetime.now().timestamp())
        hash_input = f"{email}_{timestamp}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:32]

# ================= SERVICES =================

class BaseService(ABC):
    """Base service class"""
    
    def __init__(self):
        pass
    
    def _validate_amount(self, amount: float) -> bool:
        """Validate amount is positive"""
        return amount > 0
    
    def _generate_id(self) -> str:
        """Generate a unique ID"""
        return str(uuid.uuid4())

class AuthService(BaseService):
    """Authentication service"""
    
    def __init__(self, user_repository):
        super().__init__()
        self.user_repo = user_repository
        self.security = Security(user_repository.storage.encryption_key)
    
    def register(self, email: str, password: str, full_name: str) -> Optional[User]:
        """
        Register a new user
        
        Args:
            email: User email
            password: Plain text password
            full_name: User's full name
            
        Returns:
            User object if successful, None otherwise
            
        Raises:
            ValidationError: If input validation fails
            StorageError: If storage operation fails
        """
        # Validate inputs
        if not email or '@' not in email:
            raise ValidationError("Invalid email address")
        
        if not password or len(password) < 6:
            raise ValidationError("Password must be at least 6 characters")
        
        if not full_name or len(full_name) < 2:
            raise ValidationError("Full name must be at least 2 characters")
        
        # Check if user already exists
        existing_user = self.user_repo.find_by_email(email)
        if existing_user:
            raise ValidationError("User with this email already exists")
        
        # Hash password
        hashed_password = self.security.hash_password(password)
        
        # Generate user ID
        user_id = self.security.generate_user_id(email)
        
        # Create user object
        user = User(
            id=user_id,
            email=email.lower().strip(),
            full_name=full_name.strip(),
            hashed_password=hashed_password
        )
        
        # Save user
        if self.user_repo.create_user(user):
            return user
        
        return None
    
    def login(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate a user
        
        Args:
            email: User email
            password: Plain text password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        # Find user by email
        user = self.user_repo.find_by_email(email.lower().strip())
        
        if not user:
            return None
        
        # Verify password
        if self.security.verify_password(password, user.hashed_password):
            return user
        
        return None
    
    def update_profile(self, user_id: str, full_name: str) -> bool:
        """
        Update user profile
        
        Args:
            user_id: User ID
            full_name: New full name
            
        Returns:
            True if successful, False otherwise
        """
        user = self.user_repo.get_user(user_id)
        if not user:
            return False
        
        user.full_name = full_name.strip()
        user.updated_at = datetime.now()
        
        return self.user_repo.update_user(user)
    
    def change_password(self, user_id: str, current_password: str, new_password: str) -> bool:
        """
        Change user password
        
        Args:
            user_id: User ID
            current_password: Current plain text password
            new_password: New plain text password
            
        Returns:
            True if successful, False otherwise
        """
        user = self.user_repo.get_user(user_id)
        if not user:
            return False
        
        # Verify current password
        if not self.security.verify_password(current_password, user.hashed_password):
            return False
        
        # Validate new password
        if len(new_password) < 6:
            raise ValidationError("New password must be at least 6 characters")
        
        # Hash new password
        user.hashed_password = self.security.hash_password(new_password)
        user.updated_at = datetime.now()
        
        return self.user_repo.update_user(user)

class ExpenseService(BaseService):
    """Expense management service"""
    
    def __init__(self, expense_repository, user_repository):
        super().__init__()
        self.expense_repo = expense_repository
        self.user_repo = user_repository
    
    def add_expense(self, user_id: str, amount: float, category: str, 
                   description: str = "", date: datetime = None) -> Optional[Expense]:
        """
        Add a new expense
        
        Args:
            user_id: User ID
            amount: Expense amount
            category: Expense category
            description: Expense description
            date: Expense date (defaults to now)
            
        Returns:
            Expense object if successful, None otherwise
            
        Raises:
            ValidationError: If validation fails
        """
        # Validate inputs
        if not self._validate_amount(amount):
            raise ValidationError("Amount must be positive")
        
        if not category or category.strip() == "":
            raise ValidationError("Category is required")
        
        # Verify user exists
        user = self.user_repo.get_user(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Set default date if not provided
        if date is None:
            date = datetime.now()
        
        # Create expense
        expense = Expense(
            id=self._generate_id(),
            user_id=user_id,
            amount=float(Decimal(str(amount)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)),
            category=category.strip(),
            description=description.strip(),
            date=date
        )
        
        # Save expense
        if self.expense_repo.add_expense(user_id, expense):
            return expense
        
        return None
    
    def get_user_expenses(self, user_id: str, category: str = None, 
                         start_date: datetime = None, end_date: datetime = None,
                         limit: int = None) -> List[Expense]:
        """
        Get expenses for a user with optional filters
        
        Args:
            user_id: User ID
            category: Filter by category (optional)
            start_date: Filter by start date (optional)
            end_date: Filter by end date (optional)
            limit: Maximum number of expenses to return (optional)
            
        Returns:
            List of Expense objects
        """
        expenses = self.expense_repo.get_user_expenses(user_id)
        
        # Apply filters
        filtered_expenses = []
        
        for expense in expenses:
            # Category filter
            if category and expense.category != category:
                continue
            
            # Date range filter
            if start_date and expense.date < start_date:
                continue
            
            if end_date and expense.date > end_date:
                continue
            
            filtered_expenses.append(expense)
        
        # Sort by date (newest first)
        filtered_expenses.sort(key=lambda x: x.date, reverse=True)
        
        # Apply limit
        if limit and len(filtered_expenses) > limit:
            return filtered_expenses[:limit]
        
        return filtered_expenses
    
    def get_total_expenses(self, user_id: str, category: str = None,
                          start_date: datetime = None, end_date: datetime = None) -> float:
        """
        Get total expenses for a user
        
        Args:
            user_id: User ID
            category: Filter by category (optional)
            start_date: Filter by start date (optional)
            end_date: Filter by end date (optional)
            
        Returns:
            Total expenses amount
        """
        expenses = self.get_user_expenses(user_id, category, start_date, end_date)
        return sum(expense.amount for expense in expenses)
    
    def delete_expense(self, user_id: str, expense_id: str) -> bool:
        """
        Delete an expense
        
        Args:
            user_id: User ID
            expense_id: Expense ID
            
        Returns:
            True if successful, False otherwise
        """
        return self.expense_repo.delete_expense(user_id, expense_id)
    
    def get_expense_by_id(self, user_id: str, expense_id: str) -> Optional[Expense]:
        """
        Get a specific expense by ID
        
        Args:
            user_id: User ID
            expense_id: Expense ID
            
        Returns:
            Expense object if found, None otherwise
        """
        expenses = self.expense_repo.get_user_expenses(user_id)
        for expense in expenses:
            if expense.id == expense_id:
                return expense
        return None

class BudgetService(BaseService):
    """Budget management service"""
    
    def __init__(self, budget_repository, expense_repository, user_repository):
        super().__init__()
        self.budget_repo = budget_repository
        self.expense_repo = expense_repository
        self.user_repo = user_repository
    
    def create_budget(self, user_id: str, category: str, amount: float, 
                     period: str = 'monthly') -> Optional[Budget]:
        """
        Create a new budget
        
        Args:
            user_id: User ID
            category: Budget category
            amount: Budget amount
            period: Budget period ('monthly' or 'yearly')
            
        Returns:
            Budget object if successful, None otherwise
            
        Raises:
            ValidationError: If validation fails
        """
        # Validate inputs
        if not self._validate_amount(amount):
            raise ValidationError("Budget amount must be positive")
        
        if not category or category.strip() == "":
            raise ValidationError("Category is required")
        
        if period not in ['monthly', 'yearly']:
            raise ValidationError("Period must be 'monthly' or 'yearly'")
        
        # Verify user exists
        user = self.user_repo.get_user(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Check if budget already exists for this category and period
        existing_budgets = self.budget_repo.get_user_budgets(user_id)
        for budget in existing_budgets:
            if budget.category == category and budget.period == period:
                # Update existing budget
                budget.amount = amount
                budget.start_date = datetime.now()
                if self.budget_repo.update_budget(user_id, budget):
                    return budget
                return None
        
        # Create new budget
        budget = Budget(
            id=self._generate_id(),
            user_id=user_id,
            category=category.strip(),
            amount=float(Decimal(str(amount)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)),
            period=period,
            start_date=datetime.now()
        )
        
        # Save budget
        if self.budget_repo.add_budget(user_id, budget):
            return budget
        
        return None
    
    def get_user_budgets(self, user_id: str) -> List[Budget]:
        """
        Get all budgets for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of Budget objects
        """
        return self.budget_repo.get_user_budgets(user_id)
    
    def get_budget_progress(self, user_id: str, category: str) -> Dict[str, Any]:
        """
        Get budget progress for a category
        
        Args:
            user_id: User ID
            category: Budget category
            
        Returns:
            Dictionary with progress information
        """
        # Get budget for category
        budgets = self.get_user_budgets(user_id)
        budget = None
        
        for b in budgets:
            if b.category == category:
                budget = b
                break
        
        if not budget:
            return {
                'budget': 0,
                'spent': 0,
                'percentage': 0,
                'exceeded': False,
                'remaining': 0
            }
        
        # Calculate expenses for the current period
        now = datetime.now()
        start_date = budget.start_date
        
        if budget.period == 'monthly':
            # Get expenses for current month
            end_date = start_date.replace(
                year=start_date.year + (start_date.month // 12),
                month=(start_date.month % 12) + 1,
                day=1
            ) - timedelta(days=1)
        else:  # yearly
            # Get expenses for current year
            end_date = start_date.replace(year=start_date.year + 1) - timedelta(days=1)
        
        # Get expenses for the period
        expenses = self.expense_repo.get_user_expenses(user_id)
        spent = 0
        
        for expense in expenses:
            if expense.category == category and start_date <= expense.date <= end_date:
                spent += expense.amount
        
        # Calculate progress
        percentage = (spent / budget.amount * 100) if budget.amount > 0 else 0
        exceeded = spent > budget.amount
        remaining = max(0, budget.amount - spent)
        
        return {
            'budget': budget.amount,
            'spent': spent,
            'percentage': round(percentage, 2),
            'exceeded': exceeded,
            'remaining': round(remaining, 2),
            'period': budget.period,
            'start_date': start_date,
            'end_date': end_date
        }
    
    def check_budget_exceeded(self, user_id: str, category: str) -> Dict[str, Any]:
        """
        Check if budget is exceeded for a category
        
        Args:
            user_id: User ID
            category: Expense category
            
        Returns:
            Dictionary with exceeded status and details
        """
        progress = self.get_budget_progress(user_id, category)
        return {
            'exceeded': progress['exceeded'],
            'spent': progress['spent'],
            'budget': progress['budget'],
            'percentage': progress['percentage']
        }
    
    def delete_budget(self, user_id: str, budget_id: str) -> bool:
        """
        Delete a budget
        
        Args:
            user_id: User ID
            budget_id: Budget ID
            
        Returns:
            True if successful, False otherwise
        """
        return self.budget_repo.delete_budget(user_id, budget_id)
    
    def get_active_budgets_count(self, user_id: str) -> int:
        """
        Get count of active budgets
        
        Args:
            user_id: User ID
            
        Returns:
            Number of active budgets
        """
        budgets = self.get_user_budgets(user_id)
        return len(budgets)

class InsightService(BaseService):
    """Financial insights and analytics service"""
    
    def __init__(self, expense_repository, budget_repository, user_repository):
        super().__init__()
        self.expense_repo = expense_repository
        self.budget_repo = budget_repository
        self.user_repo = user_repository
    
    def get_category_totals(self, user_id: str) -> Dict[str, Any]:
        """
        Get total expenses by category
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary with category totals
        """
        expenses = self.expense_repo.get_user_expenses(user_id)
        category_totals = {}
        
        for expense in expenses:
            category = expense.category
            if category not in category_totals:
                category_totals[category] = 0
            category_totals[category] += expense.amount
        
        # Convert to list for Chart.js
        categories = []
        amounts = []
        colors = []
        
        # Predefined colors for common categories
        color_map = {
            'food': '#FF6384',
            'transport': '#36A2EB',
            'shopping': '#FFCE56',
            'entertainment': '#4BC0C0',
            'bills': '#9966FF',
            'health': '#FF9F40',
            'education': '#C9CBCF',
            'travel': '#FF6384',
            'other': '#E7E9ED'
        }
        
        for category, amount in sorted(category_totals.items(), key=lambda x: x[1], reverse=True):
            categories.append(category.capitalize())
            amounts.append(round(amount, 2))
            colors.append(color_map.get(category, '#E7E9ED'))
        
        return {
            'categories': categories,
            'amounts': amounts,
            'colors': colors,
            'total': round(sum(amounts), 2)
        }
    
    def get_monthly_trend(self, user_id: str, months: int = 12) -> Dict[str, Any]:
        """
        Get monthly expense trend
        
        Args:
            user_id: User ID
            months: Number of months to include
            
        Returns:
            Dictionary with monthly trend data
        """
        expenses = self.expense_repo.get_user_expenses(user_id)
        
        # Group by month
        monthly_totals = {}
        
        for expense in expenses:
            month_key = expense.date.strftime('%Y-%m')
            if month_key not in monthly_totals:
                monthly_totals[month_key] = 0
            monthly_totals[month_key] += expense.amount
        
        # Generate last N months
        now = datetime.now()
        months_list = []
        amounts_list = []
        
        for i in range(months - 1, -1, -1):
            month_date = now - timedelta(days=30 * i)
            month_key = month_date.strftime('%Y-%m')
            month_label = month_date.strftime('%b %Y')
            
            months_list.append(month_label)
            amounts_list.append(round(monthly_totals.get(month_key, 0), 2))
        
        return {
            'months': months_list,
            'amounts': amounts_list,
            'average': round(sum(amounts_list) / len(amounts_list) if amounts_list else 0, 2)
        }
    
    def get_budget_vs_actual(self, user_id: str) -> Dict[str, Any]:
        """
        Get budget vs actual spending
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary with budget vs actual data
        """
        budgets = self.budget_repo.get_user_budgets(user_id)
        
        categories = []
        budget_amounts = []
        actual_amounts = []
        
        for budget in budgets:
            progress = BudgetService(self.budget_repo, self.expense_repo, self.user_repo).get_budget_progress(user_id, budget.category)
            
            categories.append(budget.category.capitalize())
            budget_amounts.append(round(budget.amount, 2))
            actual_amounts.append(round(progress['spent'], 2))
        
        return {
            'categories': categories,
            'budget': budget_amounts,
            'actual': actual_amounts
        }
    
    def get_spending_by_day(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """
        Get spending by day for the last N days
        
        Args:
            user_id: User ID
            days: Number of days to include
            
        Returns:
            Dictionary with daily spending data
        """
        expenses = self.expense_repo.get_user_expenses(user_id)
        
        # Get date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Initialize daily totals
        daily_totals = {}
        current_date = start_date
        
        while current_date <= end_date:
            daily_totals[current_date.strftime('%Y-%m-%d')] = 0
            current_date += timedelta(days=1)
        
        # Sum expenses by day
        for expense in expenses:
            if start_date <= expense.date <= end_date:
                day_key = expense.date.strftime('%Y-%m-%d')
                if day_key in daily_totals:
                    daily_totals[day_key] += expense.amount
        
        # Convert to lists
        dates = []
        amounts = []
        
        for day_key, amount in sorted(daily_totals.items()):
            date_obj = datetime.strptime(day_key, '%Y-%m-%d')
            dates.append(date_obj.strftime('%b %d'))
            amounts.append(round(amount, 2))
        
        return {
            'dates': dates,
            'amounts': amounts,
            'average': round(sum(amounts) / len(amounts) if amounts else 0, 2),
            'max': round(max(amounts) if amounts else 0, 2),
            'min': round(min(amounts) if amounts else 0, 2)
        }
    
    def get_top_expenses(self, user_id: str, limit: int = 10) -> List[Expense]:
        """
        Get top expenses by amount
        
        Args:
            user_id: User ID
            limit: Maximum number of expenses to return
            
        Returns:
            List of top expenses
        """
        expenses = self.expense_repo.get_user_expenses(user_id)
        expenses.sort(key=lambda x: x.amount, reverse=True)
        return expenses[:limit]

class NotificationService(BaseService):
    """Notification service"""
    
    def __init__(self, notification_repository, budget_service, user_repository):
        super().__init__()
        self.notification_repo = notification_repository
        self.budget_service = budget_service
        self.user_repo = user_repository
    
    def create_budget_alert(self, user_id: str, category: str, spent: float, budget: float) -> Optional[Notification]:
        """
        Create a budget exceeded alert
        
        Args:
            user_id: User ID
            category: Budget category
            spent: Amount spent
            budget: Budget amount
            
        Returns:
            Notification object if created, None otherwise
        """
        percentage = (spent / budget * 100) if budget > 0 else 0
        
        message = f"Budget exceeded for {category.capitalize()}: ${spent:.2f} spent (${budget:.2f} budget, {percentage:.1f}%)"
        
        notification = Notification(
            id=self._generate_id(),
            user_id=user_id,
            message=message,
            type='alert',
            read=False
        )
        
        return self.notification_repo.add_notification(user_id, notification)
    
    def create_info_notification(self, user_id: str, message: str) -> Optional[Notification]:
        """
        Create an informational notification
        
        Args:
            user_id: User ID
            message: Notification message
            
        Returns:
            Notification object if created, None otherwise
        """
        notification = Notification(
            id=self._generate_id(),
            user_id=user_id,
            message=message,
            type='info',
            read=False
        )
        
        return self.notification_repo.add_notification(user_id, notification)
    
    def get_user_notifications(self, user_id: str, limit: int = None) -> List[Notification]:
        """
        Get notifications for a user
        
        Args:
            user_id: User ID
            limit: Maximum number of notifications to return
            
        Returns:
            List of Notification objects
        """
        notifications = self.notification_repo.get_user_notifications(user_id)
        
        # Sort by creation date (newest first)
        notifications.sort(key=lambda x: x.created_at, reverse=True)
        
        if limit and len(notifications) > limit:
            return notifications[:limit]
        
        return notifications
    
    def mark_as_read(self, user_id: str, notification_id: str) -> bool:
        """
        Mark a notification as read
        
        Args:
            user_id: User ID
            notification_id: Notification ID
            
        Returns:
            True if successful, False otherwise
        """
        notifications = self.get_user_notifications(user_id)
        
        for notification in notifications:
            if notification.id == notification_id:
                notification.read = True
                return self.notification_repo.update_notification(user_id, notification)
        
        return False
    
    def clear_all_notifications(self, user_id: str) -> bool:
        """
        Clear all notifications for a user
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        return self.notification_repo.clear_user_notifications(user_id)

class ReportService(BaseService):
    """Report generation service"""
    
    def __init__(self, expense_repository, budget_repository, user_repository):
        super().__init__()
        self.expense_repo = expense_repository
        self.budget_repo = budget_repository
        self.user_repo = user_repository
        self.insight_service = InsightService(expense_repository, budget_repository, user_repository)
    
    def generate_report(self, user_id: str, report_type: str = 'expenses', 
                       period: str = 'month', format_type: str = 'html') -> Dict[str, Any]:
        """
        Generate a financial report
        
        Args:
            user_id: User ID
            report_type: Type of report ('expenses', 'budgets', 'full')
            period: Time period ('week', 'month', 'year', 'all')
            format_type: Output format ('html', 'pdf')
            
        Returns:
            Dictionary with report data
        """
        user = self.user_repo.get_user(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Calculate date range based on period
        end_date = datetime.now()
        
        if period == 'week':
            start_date = end_date - timedelta(days=7)
        elif period == 'month':
            start_date = end_date - timedelta(days=30)
        elif period == 'year':
            start_date = end_date - timedelta(days=365)
        else:  # 'all'
            start_date = datetime.min
        
        # Get data for report
        expenses = self.expense_repo.get_user_expenses(user_id)
        filtered_expenses = []
        
        for expense in expenses:
            if start_date <= expense.date <= end_date:
                filtered_expenses.append(expense)
        
        budgets = self.budget_repo.get_user_budgets(user_id)
        
        # Calculate totals
        total_expenses = sum(expense.amount for expense in filtered_expenses)
        total_budgets = sum(budget.amount for budget in budgets)
        
        # Get insights
        category_totals = self.insight_service.get_category_totals(user_id)
        monthly_trend = self.insight_service.get_monthly_trend(user_id, 6)
        
        # Prepare report data
        report_data = {
            'user': user,
            'period': period,
            'start_date': start_date,
            'end_date': end_date,
            'expenses': filtered_expenses,
            'budgets': budgets,
            'total_expenses': round(total_expenses, 2),
            'total_budgets': round(total_budgets, 2),
            'category_totals': category_totals,
            'monthly_trend': monthly_trend,
            'generated_at': datetime.now()
        }
        
        # Generate report in requested format
        if format_type == 'pdf':
            # This would use ReportLab to generate PDF
            # For now, we'll return the data and let the route handle PDF generation
            report_data['format'] = 'pdf'
            report_data['filename'] = f"moneyflow_report_{user_id}_{period}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            report_data['file_path'] = f"tmp/{report_data['filename']}"
        else:
            report_data['format'] = 'html'
        
        return report_data

# ================= HELPER FUNCTIONS =================

def format_currency(amount: float) -> str:
    """Format amount as currency string"""
    return f"${amount:,.2f}"

def format_date(date_obj: datetime) -> str:
    """Format date as string"""
    return date_obj.strftime('%Y-%m-%d %H:%M:%S')

def format_date_short(date_obj: datetime) -> str:
    """Format date as short string"""
    return date_obj.strftime('%b %d, %Y')

def get_category_color(category: str) -> str:
    """Get color for a category"""
    color_map = {
        'food': '#FF6384',
        'transport': '#36A2EB',
        'shopping': '#FFCE56',
        'entertainment': '#4BC0C0',
        'bills': '#9966FF',
        'health': '#FF9F40',
        'education': '#C9CBCF',
        'travel': '#FF6384',
        'other': '#E7E9ED'
    }
    return color_map.get(category, '#E7E9ED')

def get_category_icon(category: str) -> str:
    """Get FontAwesome icon for a category"""
    icon_map = {
        'food': 'fas fa-utensils',
        'transport': 'fas fa-car',
        'shopping': 'fas fa-shopping-cart',
        'entertainment': 'fas fa-film',
        'bills': 'fas fa-file-invoice-dollar',
        'health': 'fas fa-heartbeat',
        'education': 'fas fa-graduation-cap',
        'travel': 'fas fa-plane',
        'other': 'fas fa-circle'
    }
    return icon_map.get(category, 'fas fa-circle')