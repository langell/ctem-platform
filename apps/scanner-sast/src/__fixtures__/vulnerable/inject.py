def search(request):
    q = request.args.get('q')
    cursor.execute("SELECT * FROM items WHERE name = '" + q + "'")
