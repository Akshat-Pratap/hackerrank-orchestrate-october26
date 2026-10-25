"""Package code.zip per Challenge Specification §6.8 and §6.9."""
import zipfile
import os

def package():
    zip_path = 'code.zip'
    if os.path.exists(zip_path):
        os.remove(zip_path)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        # Add root README.md
        if os.path.exists('README.md'):
            z.write('README.md', 'README.md')

        # Add evaluation/ directory at root
        if os.path.exists('evaluation'):
            for root, dirs, files in os.walk('evaluation'):
                if '__pycache__' in root:
                    continue
                for f in files:
                    p = os.path.join(root, f)
                    z.write(p, p.replace('\\', '/'))

        # Add code/ directory
        for root, dirs, files in os.walk('code'):
            if any(skip in root for skip in ['__pycache__', '.venv', '.git']):
                continue
            for f in files:
                p = os.path.join(root, f)
                z.write(p, p.replace('\\', '/'))

    size_kb = os.path.getsize(zip_path) / 1024
    print(f"Packaged {zip_path} successfully ({size_kb:.1f} KB)")

if __name__ == '__main__':
    package()
