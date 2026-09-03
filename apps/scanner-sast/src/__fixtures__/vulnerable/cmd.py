import os

def run(request):
    cmd = request.args.get('cmd')
    os.system(cmd)
