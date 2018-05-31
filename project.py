from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from functools import wraps
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

# Read Google client_secrets.json and assign client_id to
# a variable for later use.
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Catalog"

# Create session and connect to DB ##
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Check for user login status
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('showLogin', next=request.url))
    return decorated_function


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Connect user using Facebook account.
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.12/me"
    '''
        Due to the formatting for the result from the server token exchange we
        have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace
        the remaining quotes with nothing so that it can be used directly
        in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.12/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.12/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# Disconnect Facebook user
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']

    """Ensure to only disconnect a connected user"""
    if access_token is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]

    """Reset the user's session"""
    del login_session['provider']
    del login_session['username']
    del login_session['email']
    del login_session['facebook_id']

    flash("You've successfully logged out")
    return redirect(url_for('showHome'))


# Connect user using Google Plus account.
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ Handles the Google+ sign-in process on the server side.
    Server side function to handle the state-token and the one-time-code
    send from the client callback function following the seven steps of the
    Google+ sign-in flow. See the illustrated flow on
    https://developers.google.com/+/web/signin/server-side-flow.
    Returns:
        When the sign-in was successful, a html response is sent to the client
        signInCallback-function confirming the login. Otherwise, one of the
        following responses is returned:
        200 OK: The user is already connected.
        401 Unauthorized: There is either a mismatch between the sent and
            received state token, the received access token doesn't belong to
            the intended user or the received client id doesn't match the web
            apps client id.
        500 Internal server error: The access token inside the received
            credentials object is not a valid one.
    Raises:
        FlowExchangeError: The exchange of the one-time code for the
            credentials object failed.
    """
    # Confirm that the token the client sends to the server matches the
    # state token that the server sends to the client.
    # This roundship verification helps ensure that the user is making the
    # request and and not a maliciousscript.
    # Using the request.args.get-method, the code examines the state token
    # passed in and compares it to the state of the login session. If thesse
    # two do not match, a response message of an invalid state token is created
    # and returned to the client. No further authentication will occur on the
    # server side if there was a mismatch between these state token.
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # If the above statement is not true then I can proceed and collect the
    # one-time code from the server with the request.data-function.
    code = request.data

    # 5) The Server tries to exchange the one-time code for an access_token and
    # an id_token (credentials object).
    # 6) When successful, Google returns the credentials object. Then the
    # server is able to make its own API calls, which can be done while the
    # user is offline.
    try:
        # Create an oauth_flow object and add clients secret key information
        # to it.
        oauth_flow = flow_from_clientsecrets(
            'client_secrets.json', scope='')
        # Postmessage specifies that this is the one-time-code flow that my
        # server will be sending off.
        oauth_flow.redirect_uri = 'postmessage'
        # The exchange is initiated with the step2_exchange-function passing in
        # the one-time code as input.
        # The step2_exchange-function of the flow-class exchanges an
        # authorization (one-time) code for an credentials object.
        # If all goes well, the response from Google will be an object which
        # is stored under the name credentials.
        credentials = oauth_flow.step2_exchange(code)
    # If an error happens along the way, then this FlowExchangeError is thrown
    # and sends the response as an JSON-object.
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # After the credentials object has been received. It has to be checked if
    # there is a valid access token inside of it.
    access_token = credentials.access_token
    # If the token is appended to the following url, the Google API server can
    # verify that this is a valid token for use.
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Create a JSON get-request containing the url and access-token and store
    # the result of this request in a variable called result
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, send a 500 internal
    # server error is send to the client.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    # If the above if-statement isn't true then the access token is working.

    # Next, verify that the access token is used for the intended user.
    # Grab the id of the token in my credentials object and compare it to the
    # id returned by the google api server. If these two ids do not match, then
    # I do not have the correct token and should return an error.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Similary, if the client ids do not match, then my app is trying to use a
    # client_id that doesn't belong to it. So I shouldn't allow for this.
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if the user is already logged in
    # ! Credentials shouldn't been stored in the session
    # stored_credentials = login_session.get('credentials')
    stored_credentials = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
    # So assuming that none of these if-statements were true, I have a valid
    # access token and my user is successfully able to login to my server.
    # In this user's login_session, the credentials and the gplus_id are stored
    # to recall later (see check above).
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Use the google plus API to get some more information about the user.
    # Here, a message is send off to the google API server with the access
    # token requesting the user info allowed by the token scope and store it in
    # an object called data.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    # Data should have all of the values listed on
    # https://developers.google.com/+/api/openidconnect/getOpenIdConnect#response
    # filled in, so long as the user specified them in their account. In the
    # following, the users name, picture and e-mail address are stored in the
    # login session.
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # If user doesn't exist, make a new one.
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # 7) If the above worked, a html response is returned confirming the login
    # to the Client.
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px; border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as %s" % login_session['username'])
    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session


# Disconnect Google user
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']

    """Ensure to only disconnect a connected user"""
    if access_token is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    """Execute HTTP GET request to revoke current token"""
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        """Reset the user's session"""
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        flash("You've successfully logged out")
        return redirect(url_for('showHome'))
    else:
        """If the given token was invalid, do the following"""
        response = make_response(json.dumps(
            "Failed to revoke token for given user"), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    try:
        if login_session['provider'] == 'google':
            return redirect('/gdisconnect')
    except:
        return redirect('/fbdisconnect')


# JSON APIs
# API endpoints for all users.
@app.route('/users.json')
def userJSON():
    users = session.query(User).all()
    return jsonify(User=[u.serialize for u in users])


# API endpoints for all categories and items.
@app.route('/catalog.json')
def catalogJSON():
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return jsonify(Categories=[c.serialize for c in categories],
                   Items=[i.serialize for i in items])


# API endpoints for all items of a specific category.
@app.route('/<category_name>/items.json')
def itemsJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category=category).all()
    return jsonify(Items=[i.serialize for i in items])


# API endpoints for all categories.
@app.route('/categories.json')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


# Show cover page
@app.route('/')
def showCover():
    return render_template('cover.html')


# Show user info
@app.route('/user/<username>/<email>')
def showUser(username, email):
    user = session.query(User).filter_by(name=username, email=email).one()
    return render_template('showUser.html', user=user)


# Show home page
@app.route('/catalog')
def showHome():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).order_by(desc(Item.createdDate))
    if 'username' not in login_session:
        return render_template('publichome.html', categories=categories, items=items)
    else:
        return render_template('home.html', categories=categories, items=items)


# Create a new category
@app.route('/catalog/newcategory', methods=['GET', 'POST'])
@login_required
def newCategory():
    if request.method == 'POST':
        addingCategory = Category(name=request.form['name'],
                                  user_id=login_session['user_id'])
        session.add(addingCategory)
        session.commit()
        flash("New Category Created!")
        return redirect(url_for('showHome'))
    else:
        return render_template('newCategory.html')


# Edit a category
@app.route('/catalog/<category_name>/edit', methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    categoryToEdit = session.query(
        Category).filter_by(name=category_name).one()
# Prevent logged-in user to edit other user's category
    if categoryToEdit.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
            "to edit this category. Please create your own category" \
            "in order to edit.');}</script><body onload='myFunction()'>"

# Save edited category to the database
    if request.method == 'POST':
        categoryToEdit.name = request.form['name']
        session.add(categoryToEdit)
        session.commit()
        flash("Category has been edited!")
        return redirect(url_for('showHome'))
    else:
        return render_template('editCategory.html', category=categoryToEdit)


# Delete a category
@app.route('/catalog/<category_name>/delete', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    categoryToDelete = session.query(
        Category).filter_by(name=category_name).one()
# Prevent logged-in user to edit other user's category
    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
            "to delete this category. Please create your own category" \
            "in order to delete.');}</script><body onload='myFunction()'>"

# Delete category from the database
    if request.method == 'POST':
        session.delete(categoryToDelete)
        session.commit()
        flash("Category has been deleted!")
        return redirect(url_for('showHome'))
    else:
        return render_template('deleteCategory.html', category=categoryToDelete)


# Show all category items
@app.route('/catalog/<category_name>/items')
def showCategoryItems(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    chosenCategory = session.query(
        Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(
        category_id=chosenCategory.id).order_by(asc(Item.name))
    creator = getUserInfo(chosenCategory.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicCategoryItems.html', categories=categories, chosenCategory=chosenCategory, items=items)
    else:
        return render_template('showCategoryItems.html', categories=categories, chosenCategory=chosenCategory, items=items)


# Show information of a specific item
@app.route('/catalog/<category_name>/<item_name>')
def showItem(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(
        name=item_name, category=category).one()
    creator = getUserInfo(item.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicitems.html', item=item)
    else:
        return render_template('showItem.html', item=item, creator=creator)


# Create a new item
@app.route('/catalog/newitem', methods=['GET', 'POST'])
@login_required
def newItem():
    categories = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        itemName = request.form['name']
        itemDescription = request.form['description']
        itemPrice = request.form['price']
        itemCategory = session.query(Category).filter_by(
            name=request.form['category']).one()
        itemImage = request.form['image']
        if itemName != '':
            print "item name %s" % itemName
            addingItem = Item(name=itemName, description=itemDescription, price=itemPrice, image=itemImage, category=itemCategory,
                              user_id=itemCategory.user_id)
            session.add(addingItem)
            session.commit()
            flash("Item has been created!")
            return redirect(url_for('showHome'))
        else:
            return render_template('newItem.html', categories=categories)
    else:
        return render_template('newItem.html', categories=categories)


# Edit an item
@app.route('/catalog/<category_name>/<item_name>/edit', methods=['GET', 'POST'])
@login_required
def editItem(category_name, item_name):
    categories = session.query(Category).order_by(asc(Category.name))
    editingItemCategory = session.query(
        Category).filter_by(name=category_name).one()
    editingItem = session.query(Item).filter_by(
        name=item_name, category=editingItemCategory).one()
# Prevent logged-in user to edit other user's category
    if editingItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
            "to edit this item. Please create your own item" \
            "in order to edit.');}</script><body onload='myFunction()'>"
# Save edited item to the database
    if request.method == 'POST':
        if request.form['name']:
            editingItem.name = request.form['name']
        if request.form['description']:
            editingItem.description = request.form['description']
        if request.form['price']:
            editingItem.price = request.form['price']
        if request.form['category']:
            editingItem.category = session.query(Category).filter_by(
                name=request.form['category']).one()
        session.add(editingItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showItem', category_name=editingItemCategory.name, item_name=editingItem.name))
    else:
        return render_template(
            'edititem.html', categories=categories, editingItemCategory=editingItemCategory, item=editingItem)


# Delete an item
@app.route('/catalog/<category_name>/<item_name>/delete', methods=['GET', 'POST'])
@login_required
def deleteItem(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    deletingItem = session.query(Item).filter_by(
        name=item_name, category=category).one()
# Prevent logged in user to delete item belongs to others
    if deletingItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
            "to delete this item. Please create your own item" \
            "in order to delete.');}</script><body onload='myFunction()'>"
# Delete Item from database
    if request.method == 'POST':
        session.delete(deletingItem)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showCategoryItems', category_name=category.name))
    else:
        return render_template('deleteItem.html', item=deletingItem)


# Edit item image
@app.route('/catalog/<category_name>/<item_name>/editimage', methods=['GET', 'POST'])
@login_required
def editImage(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    editingItem = session.query(Item).filter_by(
        name=item_name, category=category).one()

# Prevent logged-in user to edit item image which belongs to other user
    if editingItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
            "to edit this item. Please create your own item" \
            "in order to edit.');}</script><body onload='myFunction()'>"
# Save edited image to the database
    if request.method == 'POST':
        if request.form['image']:
            editingItem.image = request.form['image']
            session.add(editingItem)
            session.commit()
            flash("Image has been edited!")
            return redirect(url_for('showItem', category_name=category.name, item_name=editingItem.name))
    else:
        return render_template('editImage.html', item=editingItem)


# Delete item image
@app.route('/catalog/<category_name>/<item_name>/deleteimage', methods=['GET', 'POST'])
@login_required
def deleteImage(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    editingItem = session.query(Item).filter_by(
        name=item_name, category=category).one()

# Prevent logged-in user to delete item image which belongs to other user
    if editingItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized" \
            "to delete this item. Please create your own item" \
            "in order to delete.');}</script><body onload='myFunction()'>"
# Delete item image
    if request.method == 'POST':
        editingItem.image = url_for(
            'static', filename='charles-deluvio-464973-unsplash.jpg')
        session.add(editingItem)
        session.commit()
        flash("Image has been deleted!")
        return redirect(url_for('showItem', category_name=category.name, item_name=editingItem.name))
    else:
        return render_template('deleteImage.html', item=editingItem)


# Render contact page
@app.route('/contact')
def contact():
    return render_template('contact.html')


# Render about page
@app.route('/about')
def about():
    return render_template('about.html')


# User Helper Functions
# Create a new user
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Get user info
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Get user id by email
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
