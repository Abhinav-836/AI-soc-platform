import os
import re

def fix_imports():
    """Fix all import statements from 'core' to 'src.core'"""
    
    folders_to_fix = ['src']
    extensions = ['.py']
    
    fixed_count = 0
    
    for folder in folders_to_fix:
        for root, dirs, files in os.walk(folder):
            for file in files:
                if file.endswith(tuple(extensions)):
                    filepath = os.path.join(root, file)
                    
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    original = content
                    
                    # Fix imports
                    content = re.sub(r'from core\.', 'from src.core.', content)
                    content = re.sub(r'import core\.', 'import src.core.', content)
                    content = re.sub(r'from core import', 'from src.core import', content)
                    
                    if content != original:
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(content)
                        print(f"Fixed: {filepath}")
                        fixed_count += 1
    
    print(f"\nFixed {fixed_count} files")

if __name__ == "__main__":
    fix_imports()
    print("\nDone! Now run: python run.py")