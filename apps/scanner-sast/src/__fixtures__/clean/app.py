import os
import subprocess

def search(request):
    q = request.args.get('q')
    cursor.execute("SELECT * FROM items WHERE name = %s", (q,))

def run(request):
    path = request.args.get('path')
    subprocess.run(['ls', path])

password = os.environ.get('DB_PASSWORD')
