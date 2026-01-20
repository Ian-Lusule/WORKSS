# run.py
import os
import sys
from cryptography.fernet import Fernet
import base64

def setup_environment():
    """Setup environment and generate keys if needed"""
    
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        print("📝 Creating .env file...")
        
        # Generate keys
        secret_key = secrets.token_hex(32)
        encryption_key = Fernet.generate_key().decode()
        
        with open('.env', 'w') as f:
            f.write(f"SECRET_KEY={secret_key}\n")
            f.write(f"ENCRYPTION_KEY={encryption_key}\n")
            f.write("FLASK_ENV=development\n")
        
        print(f"✅ Generated SECRET_KEY: {secret_key[:20]}...")
        print(f"✅ Generated ENCRYPTION_KEY: {encryption_key[:20]}...")
        print("📁 Saved to .env file")
    
    # Check if encryption key is valid
    from dotenv import load_dotenv
    load_dotenv()
    
    encryption_key = os.getenv('ENCRYPTION_KEY')
    if encryption_key:
        try:
            # Validate the key
            Fernet(encryption_key.encode())
            print("✅ ENCRYPTION_KEY is valid")
        except Exception as e:
            print(f"❌ Invalid ENCRYPTION_KEY: {str(e)}")
            print("🔑 Generating new key...")
            
            # Generate new key
            new_key = Fernet.generate_key().decode()
            
            # Update .env file
            with open('.env', 'r') as f:
                lines = f.readlines()
            
            with open('.env', 'w') as f:
                for line in lines:
                    if line.startswith('ENCRYPTION_KEY='):
                        f.write(f'ENCRYPTION_KEY={new_key}\n')
                    else:
                        f.write(line)
            
            print(f"✅ New ENCRYPTION_KEY: {new_key[:20]}...")
    
    # Create necessary directories
    os.makedirs('data/users', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/img', exist_ok=True)
    
    print("📁 Created necessary directories")
    
    return True

if __name__ == '__main__':
    print("🚀 Setting up MoneyFlow...")
    
    if setup_environment():
        print("\n✅ Setup complete! Starting MoneyFlow...")
        print("🌐 Open http://localhost:5000 in your browser\n")
        
        # Run the app
        os.system('python app.py')
    else:
        print("❌ Setup failed")
        sys.exit(1)