"""
MoneyFlow Python - File Storage, Encryption & Repositories
Combines: File handling, encryption, and all repository classes
"""
import os
import json
import shutil
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any, Union
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib

# ================= SECURE STORAGE =================

class SecureStorage:
    """Secure file storage with encryption"""
    
    def __init__(self, encryption_key: str):
        """
        Initialize secure storage
        
        Args:
            encryption_key: Fernet encryption key (base64 encoded)
        """
        if not encryption_key:
            raise ValueError("Encryption key is required")
        
        try:
            # Ensure key is properly formatted
            key_bytes = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
            self.fernet = Fernet(key_bytes)
            self.encryption_key = encryption_key
        except Exception as e:
            raise ValueError(f"Invalid encryption key: {str(e)}")
        
        # Thread lock for file operations
        self.lock = threading.RLock()
    
    def encrypt_data(self, data: Dict) -> bytes:
        """
        Encrypt dictionary data
        
        Args:
            data: Dictionary to encrypt
            
        Returns:
            Encrypted bytes
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            json_str = json.dumps(data, default=str, indent=2)
            return self.fernet.encrypt(json_str.encode('utf-8'))
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")
    
    def decrypt_data(self, encrypted_data: bytes) -> Dict:
        """
        Decrypt bytes to dictionary
        
        Args:
            encrypted_data: Encrypted bytes
            
        Returns:
            Decrypted dictionary
            
        Raises:
            EncryptionError: If decryption fails or data is corrupted
        """
        try:
            json_str = self.fernet.decrypt(encrypted_data).decode('utf-8')
            return json.loads(json_str)
        except InvalidToken:
            raise EncryptionError("Invalid encryption token - data may be corrupted or tampered with")
        except json.JSONDecodeError:
            raise EncryptionError("Decrypted data is not valid JSON")
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {str(e)}")
    
    def save_to_file(self, filepath: str, data: Dict) -> bool:
        """
        Save encrypted data to file
        
        Args:
            filepath: Path to save file
            data: Dictionary data to save
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                
                # Encrypt data
                encrypted_data = self.encrypt_data(data)
                
                # Write to temporary file first (atomic operation)
                temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(filepath))
                try:
                    with os.fdopen(temp_fd, 'wb') as temp_file:
                        temp_file.write(encrypted_data)
                    
                    # Replace original file
                    shutil.move(temp_path, filepath)
                    return True
                    
                except Exception:
                    # Clean up temp file on error
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                    raise
                    
            except Exception as e:
                raise StorageError(f"Failed to save file {filepath}: {str(e)}")
    
    def load_from_file(self, filepath: str) -> Optional[Dict]:
        """
        Load and decrypt data from file
        
        Args:
            filepath: Path to load file from
            
        Returns:
            Decrypted dictionary or None if file doesn't exist
        """
        with self.lock:
            try:
                if not os.path.exists(filepath):
                    return None
                
                with open(filepath, 'rb') as f:
                    encrypted_data = f.read()
                
                if not encrypted_data:
                    return {}
                
                return self.decrypt_data(encrypted_data)
                
            except Exception as e:
                raise StorageError(f"Failed to load file {filepath}: {str(e)}")
    
    def delete_file(self, filepath: str) -> bool:
        """
        Delete a file
        
        Args:
            filepath: Path to delete
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            try:
                if os.path.exists(filepath):
                    os.unlink(filepath)
                    return True
                return False
            except Exception as e:
                raise StorageError(f"Failed to delete file {filepath}: {str(e)}")
    
    def file_exists(self, filepath: str) -> bool:
        """
        Check if a file exists
        
        Args:
            filepath: Path to check
            
        Returns:
            True if file exists, False otherwise
        """
        return os.path.exists(filepath)

# ================= FILE HANDLER =================

class FileHandler:
    """File path and directory utilities"""
    
    def __init__(self, base_dir: str = "data/users"):
        """
        Initialize file handler
        
        Args:
            base_dir: Base directory for user data
        """
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
    
    def get_user_filename(self, user_id: str, data_type: str, extension: str) -> str:
        """
        Get filename for user data
        
        Args:
            user_id: User ID
            data_type: Type of data (expenses, budgets, etc.)
            extension: File extension (.mfe, .mfb, etc.)
            
        Returns:
            Full file path
        """
        # Clean filename components
        clean_user_id = self._sanitize_filename(user_id)
        clean_type = self._sanitize_filename(data_type)
        
        filename = f"{clean_user_id}_{clean_type}{extension}"
        return os.path.join(self.base_dir, filename)
    
    def get_user_directory(self, user_id: str) -> str:
        """
        Get user-specific directory
        
        Args:
            user_id: User ID
            
        Returns:
            Directory path for user
        """
        clean_user_id = self._sanitize_filename(user_id)
        user_dir = os.path.join(self.base_dir, clean_user_id)
        os.makedirs(user_dir, exist_ok=True)
        return user_dir
    
    def list_user_files(self, user_id: str, extension: str = None) -> List[str]:
        """
        List user files
        
        Args:
            user_id: User ID
            extension: Filter by extension (optional)
            
        Returns:
            List of file paths
        """
        user_dir = self.get_user_directory(user_id)
        
        if not os.path.exists(user_dir):
            return []
        
        files = []
        for filename in os.listdir(user_dir):
            if extension and not filename.endswith(extension):
                continue
            
            filepath = os.path.join(user_dir, filename)
            if os.path.isfile(filepath):
                files.append(filepath)
        
        return files
    
    def get_user_file(self, user_id: str, data_type: str, extension: str) -> str:
        """
        Get specific user file path
        
        Args:
            user_id: User ID
            data_type: Type of data
            extension: File extension
            
        Returns:
            Full file path
        """
        user_dir = self.get_user_directory(user_id)
        clean_type = self._sanitize_filename(data_type)
        filename = f"{clean_type}{extension}"
        return os.path.join(user_dir, filename)
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent directory traversal
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        # Remove dangerous characters
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
        
        return filename
    
    def backup_file(self, filepath: str) -> str:
        """
        Create a backup of a file
        
        Args:
            filepath: Path to file
            
        Returns:
            Path to backup file
        """
        if not os.path.exists(filepath):
            return None
        
        backup_path = f"{filepath}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            shutil.copy2(filepath, backup_path)
            return backup_path
        except Exception:
            return None

# ================= BASE REPOSITORY =================

class BaseRepository:
    """Base repository for CRUD operations"""
    
    def __init__(self, storage: SecureStorage, file_handler: FileHandler = None):
        """
        Initialize base repository
        
        Args:
            storage: SecureStorage instance
            file_handler: FileHandler instance (optional)
        """
        self.storage = storage
        self.file_handler = file_handler or FileHandler()
        self.lock = threading.RLock()
    
    def _get_filepath(self, user_id: str, data_type: str, extension: str) -> str:
        """
        Get filepath for user data
        
        Args:
            user_id: User ID
            data_type: Type of data
            extension: File extension
            
        Returns:
            Full file path
        """
        return self.file_handler.get_user_file(user_id, data_type, extension)
    
    def _load_all(self, user_id: str, data_type: str, extension: str) -> List[Dict]:
        """
        Load all data from file
        
        Args:
            user_id: User ID
            data_type: Type of data
            extension: File extension
            
        Returns:
            List of data dictionaries
        """
        filepath = self._get_filepath(user_id, data_type, extension)
        data = self.storage.load_from_file(filepath)
        
        if data is None:
            return []
        
        # Handle both list format and dict format
        if isinstance(data, dict):
            # Convert dict to list of items
            items = []
            for item_id, item_data in data.items():
                if isinstance(item_data, dict):
                    item_data['id'] = item_id
                    items.append(item_data)
            return items
        elif isinstance(data, list):
            return data
        else:
            return []
    
    def _save_all(self, user_id: str, data_type: str, extension: str, items: List[Dict]) -> bool:
        """
        Save all data to file
        
        Args:
            user_id: User ID
            data_type: Type of data
            extension: File extension
            items: List of data dictionaries
            
        Returns:
            True if successful, False otherwise
        """
        filepath = self._get_filepath(user_id, data_type, extension)
        
        # Convert to dict with IDs as keys for easier lookup
        data_dict = {}
        for item in items:
            if 'id' in item:
                data_dict[item['id']] = item
        
        return self.storage.save_to_file(filepath, data_dict)
    
    def _find_by_id(self, user_id: str, data_type: str, extension: str, item_id: str) -> Optional[Dict]:
        """
        Find item by ID
        
        Args:
            user_id: User ID
            data_type: Type of data
            extension: File extension
            item_id: Item ID
            
        Returns:
            Item dictionary or None if not found
        """
        items = self._load_all(user_id, data_type, extension)
        
        for item in items:
            if item.get('id') == item_id:
                return item
        
        return None

# ================= USER REPOSITORY =================

class UserRepository(BaseRepository):
    """User data repository"""
    
    def __init__(self, storage: SecureStorage):
        """
        Initialize user repository
        
        Args:
            storage: SecureStorage instance
        """
        super().__init__(storage)
        self.user_index = {}  # email -> user_id mapping cache
    
    def create_user(self, user_data: Dict) -> bool:
        """
        Create a new user
        
        Args:
            user_data: User data dictionary
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            user_id = user_data.get('id')
            email = user_data.get('email', '').lower()
            
            if not user_id or not email:
                return False
            
            # Check if user already exists
            if self.find_by_email(email):
                return False
            
            # Save user data
            filepath = self._get_filepath(user_id, 'user', '.mfc')
            success = self.storage.save_to_file(filepath, user_data)
            
            if success:
                # Update cache
                self.user_index[email] = user_id
            
            return success
    
    def find_by_email(self, email: str) -> Optional[Dict]:
        """
        Find user by email
        
        Args:
            email: User email
            
        Returns:
            User dictionary or None if not found
        """
        with self.lock:
            email = email.lower()
            
            # Check cache first
            if email in self.user_index:
                user_id = self.user_index[email]
                return self.get_user(user_id)
            
            # Scan user files (this is inefficient for many users, but works for small scale)
            # In production, you'd want a separate index file
            user_files = self.file_handler.list_user_files('*', '.mfc')
            
            for filepath in user_files:
                try:
                    user_data = self.storage.load_from_file(filepath)
                    if user_data and user_data.get('email', '').lower() == email:
                        user_id = user_data.get('id')
                        if user_id:
                            # Update cache
                            self.user_index[email] = user_id
                        return user_data
                except Exception:
                    continue
            
            return None
    
    def get_user(self, user_id: str) -> Optional[Dict]:
        """
        Get user by ID
        
        Args:
            user_id: User ID
            
        Returns:
            User dictionary or None if not found
        """
        filepath = self._get_filepath(user_id, 'user', '.mfc')
        user_data = self.storage.load_from_file(filepath)
        
        if user_data and 'email' in user_data:
            # Update cache
            self.user_index[user_data['email'].lower()] = user_id
        
        return user_data
    
    def update_user(self, user_data: Dict) -> bool:
        """
        Update user data
        
        Args:
            user_data: Updated user data
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            user_id = user_data.get('id')
            if not user_id:
                return False
            
            # Get existing user to preserve email for cache
            existing_user = self.get_user(user_id)
            if not existing_user:
                return False
            
            old_email = existing_user.get('email', '').lower()
            new_email = user_data.get('email', '').lower()
            
            # Save updated user data
            filepath = self._get_filepath(user_id, 'user', '.mfc')
            success = self.storage.save_to_file(filepath, user_data)
            
            if success and old_email != new_email:
                # Update cache
                if old_email in self.user_index:
                    del self.user_index[old_email]
                if new_email:
                    self.user_index[new_email] = user_id
            
            return success
    
    def delete_user(self, user_id: str) -> bool:
        """
        Delete user and all associated data
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            # Get user to get email for cache cleanup
            user_data = self.get_user(user_id)
            if user_data:
                email = user_data.get('email', '').lower()
                if email in self.user_index:
                    del self.user_index[email]
            
            # Delete user file
            filepath = self._get_filepath(user_id, 'user', '.mfc')
            user_deleted = self.storage.delete_file(filepath)
            
            # Try to delete all user data files
            user_dir = self.file_handler.get_user_directory(user_id)
            if os.path.exists(user_dir):
                try:
                    # Delete all files in user directory
                    for filename in os.listdir(user_dir):
                        os.unlink(os.path.join(user_dir, filename))
                    # Remove directory
                    os.rmdir(user_dir)
                except Exception:
                    pass  # Continue even if cleanup fails
            
            return user_deleted
    
    def user_exists(self, user_id: str) -> bool:
        """
        Check if user exists
        
        Args:
            user_id: User ID
            
        Returns:
            True if user exists, False otherwise
        """
        filepath = self._get_filepath(user_id, 'user', '.mfc')
        return self.storage.file_exists(filepath)

# ================= EXPENSE REPOSITORY =================

class ExpenseRepository(BaseRepository):
    """Expense data repository"""
    
    def __init__(self, storage: SecureStorage):
        """
        Initialize expense repository
        
        Args:
            storage: SecureStorage instance
        """
        super().__init__(storage)
    
    def add_expense(self, user_id: str, expense_data: Dict) -> bool:
        """
        Add an expense
        
        Args:
            user_id: User ID
            expense_data: Expense data dictionary
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            expense_id = expense_data.get('id')
            if not expense_id:
                return False
            
            # Load existing expenses
            expenses = self._load_all(user_id, 'expenses', '.mfe')
            
            # Check if expense already exists
            for i, exp in enumerate(expenses):
                if exp.get('id') == expense_id:
                    # Update existing expense
                    expenses[i] = expense_data
                    return self._save_all(user_id, 'expenses', '.mfe', expenses)
            
            # Add new expense
            expenses.append(expense_data)
            return self._save_all(user_id, 'expenses', '.mfe', expenses)
    
    def get_user_expenses(self, user_id: str) -> List[Dict]:
        """
        Get all expenses for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of expense dictionaries
        """
        return self._load_all(user_id, 'expenses', '.mfe')
    
    def get_expense(self, user_id: str, expense_id: str) -> Optional[Dict]:
        """
        Get a specific expense
        
        Args:
            user_id: User ID
            expense_id: Expense ID
            
        Returns:
            Expense dictionary or None if not found
        """
        return self._find_by_id(user_id, 'expenses', '.mfe', expense_id)
    
    def update_expense(self, user_id: str, expense_data: Dict) -> bool:
        """
        Update an expense
        
        Args:
            user_id: User ID
            expense_data: Updated expense data
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            expense_id = expense_data.get('id')
            if not expense_id:
                return False
            
            expenses = self._load_all(user_id, 'expenses', '.mfe')
            
            # Find and update expense
            for i, exp in enumerate(expenses):
                if exp.get('id') == expense_id:
                    expenses[i] = expense_data
                    return self._save_all(user_id, 'expenses', '.mfe', expenses)
            
            return False
    
    def delete_expense(self, user_id: str, expense_id: str) -> bool:
        """
        Delete an expense
        
        Args:
            user_id: User ID
            expense_id: Expense ID
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            expenses = self._load_all(user_id, 'expenses', '.mfe')
            
            # Filter out the expense to delete
            new_expenses = [exp for exp in expenses if exp.get('id') != expense_id]
            
            if len(new_expenses) != len(expenses):
                # Expense was found and removed
                return self._save_all(user_id, 'expenses', '.mfe', new_expenses)
            
            return False
    
    def get_expenses_by_category(self, user_id: str, category: str) -> List[Dict]:
        """
        Get expenses by category
        
        Args:
            user_id: User ID
            category: Expense category
            
        Returns:
            List of expense dictionaries
        """
        expenses = self._load_all(user_id, 'expenses', '.mfe')
        return [exp for exp in expenses if exp.get('category') == category]
    
    def get_expenses_by_date_range(self, user_id: str, start_date: datetime, 
                                  end_date: datetime) -> List[Dict]:
        """
        Get expenses within a date range
        
        Args:
            user_id: User ID
            start_date: Start date
            end_date: End date
            
        Returns:
            List of expense dictionaries
        """
        expenses = self._load_all(user_id, 'expenses', '.mfe')
        
        result = []
        for exp in expenses:
            exp_date_str = exp.get('date')
            if not exp_date_str:
                continue
            
            try:
                if isinstance(exp_date_str, str):
                    exp_date = datetime.fromisoformat(exp_date_str.replace('Z', '+00:00'))
                else:
                    # Assume it's already a datetime object
                    exp_date = exp_date_str
                
                if start_date <= exp_date <= end_date:
                    result.append(exp)
            except Exception:
                continue
        
        return result

# ================= BUDGET REPOSITORY =================

class BudgetRepository(BaseRepository):
    """Budget data repository"""
    
    def __init__(self, storage: SecureStorage):
        """
        Initialize budget repository
        
        Args:
            storage: SecureStorage instance
        """
        super().__init__(storage)
    
    def add_budget(self, user_id: str, budget_data: Dict) -> bool:
        """
        Add a budget
        
        Args:
            user_id: User ID
            budget_data: Budget data dictionary
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            budget_id = budget_data.get('id')
            if not budget_id:
                return False
            
            # Load existing budgets
            budgets = self._load_all(user_id, 'budgets', '.mfb')
            
            # Check if budget already exists for same category and period
            category = budget_data.get('category')
            period = budget_data.get('period')
            
            for i, budget in enumerate(budgets):
                if (budget.get('category') == category and 
                    budget.get('period') == period):
                    # Update existing budget
                    budgets[i] = budget_data
                    return self._save_all(user_id, 'budgets', '.mfb', budgets)
            
            # Add new budget
            budgets.append(budget_data)
            return self._save_all(user_id, 'budgets', '.mfb', budgets)
    
    def get_user_budgets(self, user_id: str) -> List[Dict]:
        """
        Get all budgets for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of budget dictionaries
        """
        return self._load_all(user_id, 'budgets', '.mfb')
    
    def get_budget(self, user_id: str, budget_id: str) -> Optional[Dict]:
        """
        Get a specific budget
        
        Args:
            user_id: User ID
            budget_id: Budget ID
            
        Returns:
            Budget dictionary or None if not found
        """
        return self._find_by_id(user_id, 'budgets', '.mfb', budget_id)
    
    def update_budget(self, user_id: str, budget_data: Dict) -> bool:
        """
        Update a budget
        
        Args:
            user_id: User ID
            budget_data: Updated budget data
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            budget_id = budget_data.get('id')
            if not budget_id:
                return False
            
            budgets = self._load_all(user_id, 'budgets', '.mfb')
            
            # Find and update budget
            for i, budget in enumerate(budgets):
                if budget.get('id') == budget_id:
                    budgets[i] = budget_data
                    return self._save_all(user_id, 'budgets', '.mfb', budgets)
            
            return False
    
    def delete_budget(self, user_id: str, budget_id: str) -> bool:
        """
        Delete a budget
        
        Args:
            user_id: User ID
            budget_id: Budget ID
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            budgets = self._load_all(user_id, 'budgets', '.mfb')
            
            # Filter out the budget to delete
            new_budgets = [budget for budget in budgets if budget.get('id') != budget_id]
            
            if len(new_budgets) != len(budgets):
                # Budget was found and removed
                return self._save_all(user_id, 'budgets', '.mfb', new_budgets)
            
            return False
    
    def get_budget_by_category(self, user_id: str, category: str, 
                              period: str = None) -> Optional[Dict]:
        """
        Get budget by category
        
        Args:
            user_id: User ID
            category: Budget category
            period: Budget period (optional)
            
        Returns:
            Budget dictionary or None if not found
        """
        budgets = self._load_all(user_id, 'budgets', '.mfb')
        
        for budget in budgets:
            if budget.get('category') == category:
                if period is None or budget.get('period') == period:
                    return budget
        
        return None

# ================= NOTIFICATION REPOSITORY =================

class NotificationRepository(BaseRepository):
    """Notification data repository"""
    
    def __init__(self, storage: SecureStorage):
        """
        Initialize notification repository
        
        Args:
            storage: SecureStorage instance
        """
        super().__init__(storage)
    
    def add_notification(self, user_id: str, notification_data: Dict) -> bool:
        """
        Add a notification
        
        Args:
            user_id: User ID
            notification_data: Notification data dictionary
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            notification_id = notification_data.get('id')
            if not notification_id:
                return False
            
            # Load existing notifications
            notifications = self._load_all(user_id, 'notifications', '.mfn')
            
            # Add new notification
            notifications.append(notification_data)
            
            # Keep only last 100 notifications to prevent file from growing too large
            if len(notifications) > 100:
                notifications = notifications[-100:]
            
            return self._save_all(user_id, 'notifications', '.mfn', notifications)
    
    def get_user_notifications(self, user_id: str) -> List[Dict]:
        """
        Get all notifications for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of notification dictionaries
        """
        return self._load_all(user_id, 'notifications', '.mfn')
    
    def get_notification(self, user_id: str, notification_id: str) -> Optional[Dict]:
        """
        Get a specific notification
        
        Args:
            user_id: User ID
            notification_id: Notification ID
            
        Returns:
            Notification dictionary or None if not found
        """
        return self._find_by_id(user_id, 'notifications', '.mfn', notification_id)
    
    def update_notification(self, user_id: str, notification_data: Dict) -> bool:
        """
        Update a notification
        
        Args:
            user_id: User ID
            notification_data: Updated notification data
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            notification_id = notification_data.get('id')
            if not notification_id:
                return False
            
            notifications = self._load_all(user_id, 'notifications', '.mfn')
            
            # Find and update notification
            for i, notification in enumerate(notifications):
                if notification.get('id') == notification_id:
                    notifications[i] = notification_data
                    return self._save_all(user_id, 'notifications', '.mfn', notifications)
            
            return False
    
    def delete_notification(self, user_id: str, notification_id: str) -> bool:
        """
        Delete a notification
        
        Args:
            user_id: User ID
            notification_id: Notification ID
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            notifications = self._load_all(user_id, 'notifications', '.mfn')
            
            # Filter out the notification to delete
            new_notifications = [n for n in notifications if n.get('id') != notification_id]
            
            if len(new_notifications) != len(notifications):
                # Notification was found and removed
                return self._save_all(user_id, 'notifications', '.mfn', new_notifications)
            
            return False
    
    def clear_user_notifications(self, user_id: str) -> bool:
        """
        Clear all notifications for a user
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        return self._save_all(user_id, 'notifications', '.mfn', [])

# ================= HELPER FUNCTIONS =================

def generate_encryption_key() -> str:
    """
    Generate a new Fernet encryption key
    
    Returns:
        Base64 encoded encryption key
    """
    return Fernet.generate_key().decode()

def derive_key_from_password(password: str, salt: bytes = None) -> str:
    """
    Derive an encryption key from a password
    
    Args:
        password: Password string
        salt: Salt bytes (optional, generated if not provided)
        
    Returns:
        Base64 encoded encryption key
    """
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key.decode()

def hash_user_id(email: str) -> str:
    """
    Generate a user ID hash from email
    
    Args:
        email: User email
        
    Returns:
        Hashed user ID
    """
    # Use SHA-256 for secure hashing
    return hashlib.sha256(email.lower().encode()).hexdigest()[:32]

def create_backup(backup_dir: str = "backups") -> str:
    """
    Create a backup of all data
    
    Args:
        backup_dir: Backup directory
        
    Returns:
        Path to backup file
    """
    import zipfile
    from datetime import datetime
    
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(backup_dir, f"moneyflow_backup_{timestamp}.zip")
    
    try:
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add all data files
            for root, dirs, files in os.walk('data'):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, 'data')
                    zipf.write(file_path, arcname)
        
        return backup_path
    except Exception as e:
        raise StorageError(f"Backup failed: {str(e)}")

def restore_backup(backup_path: str) -> bool:
    """
    Restore data from backup
    
    Args:
        backup_path: Path to backup file
        
    Returns:
        True if successful, False otherwise
    """
    import zipfile
    import tempfile
    
    if not os.path.exists(backup_path):
        return False
    
    try:
        # Extract to temporary directory first
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                zipf.extractall(temp_dir)
            
            # Replace data directory
            data_dir = 'data'
            if os.path.exists(data_dir):
                shutil.rmtree(data_dir)
            
            shutil.move(os.path.join(temp_dir, os.listdir(temp_dir)[0]), data_dir)
        
        return True
    except Exception as e:
        raise StorageError(f"Restore failed: {str(e)}")

# ================= ERROR CLASSES =================

class StorageError(Exception):
    """File storage related errors"""
    pass

class EncryptionError(Exception):
    """Encryption/decryption errors"""
    pass

class RepositoryError(Exception):
    """Repository operation errors"""
    pass

# ================= INITIALIZATION =================

def initialize_storage(encryption_key: str = None) -> SecureStorage:
    """
    Initialize secure storage
    
    Args:
        encryption_key: Encryption key (generated if not provided)
        
    Returns:
        SecureStorage instance
    """
    if encryption_key is None:
        encryption_key = generate_encryption_key()
        print(f"Generated new encryption key: {encryption_key}")
        print("Save this key to your .env file as ENCRYPTION_KEY=")
    
    return SecureStorage(encryption_key)

def initialize_repositories(storage: SecureStorage) -> Dict[str, BaseRepository]:
    """
    Initialize all repositories
    
    Args:
        storage: SecureStorage instance
        
    Returns:
        Dictionary of repositories
    """
    return {
        'user': UserRepository(storage),
        'expense': ExpenseRepository(storage),
        'budget': BudgetRepository(storage),
        'notification': NotificationRepository(storage)
    }