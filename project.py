from flask import Flask, render_template, request, redirect, url_for,flash, jsonify
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Topic, SubTopic, SubTopicItem, Rating


from flask import session as login_session
import random, string

# flow object from client secrets json file. stores client ID/oauth parameters. flowexchangeerror for error message
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Rate Everything"

engine = create_engine('sqlite:///rateeverything.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange (32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
	# protect against cross site forgery attacks by checking state
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	access_token = request.data
	print "access token received %s" % access_token

	# exchange client token for long-lived server-side token with GET /oauth/access_token?grant_type=fb_exchange_token&client_id={app-id}&client_secre={app-secret}&fb_exchange_token{short-lived-token}
	app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
	app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
	url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
	h = httplib2.Http()
	result = h.request(url,'GET')[1]

	#use token to get user info from API
	userinfo_url = 'https://graph.facebook.com/v2.4/me'
	#strip to explore tag from access token
	token = result.split("&")[0]


	url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,email,id' % token
	print url
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	print "url sent for API access:%s"% url
	print "API JSON result: %s" % result
	data = json.loads(result)
	print data
	login_session['provider'] = 'facebook'
	login_session['username'] = data['name']
	login_session['email'] = data['email']
	login_session['facebook_id'] = data['id']

	#token must be stored in login_session to properly log out
	stored_token = token.split("=")[1]
	login_session['access_token'] = stored_token

	#get user picture
	url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	data = json.loads(result)

	login_session['picture'] = data['data']['url']

	#see if user exists
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
	output += '" style = "width:300px;height:300px;border-radius:150px;-webkit-border-radius:150px;-moz-border-radius:150px;"> '
	flash("You are now logged in as %s"%login_session['username'])
	print "done!"
	return output

@app.route('/fbdisconnect')
def fbdisconnect():
	facebook_id = login_session['facebook_id']
	url = 'https://graph.facebook.com/%s/permissions' % facebook_id
	h = httplib2.Http()
	result = h.request(url, 'DELETE')[1]
	del login_session['username']
	del login_session['email']
	del login_session['picture']
	del login_session['user_id']
	del login_session['facebook_id']
	return "You have been logged out."

@app.route('/gconnect', methods=['POST'])
def gconnect():
	#validate state token against the login_session token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	#obtain authorization code
	code = request.data

	#upgrade auth code into credentials object
	try:
		oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	#check token validity
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])
	#if error in access token, abort
	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 500)
		response.headers['Content-Type'] = 'application/json'

	#verify access token is for intended user
	gplus_id = credentials.id_token['sub']
	if result['user_id'] != gplus_id:
		response = make_response(
			json.dumps("Token's user ID doesn't match given user"), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	#verify access token valid for app
	if result['issued_to'] != CLIENT_ID:
		response = make_response(json.dumps("Token's client id does not match app's"), 401)
		print "Token's client id does not match app's."
		response.headers['Content-Type'] = 'application/json'
		return response

	# check if user is logged in already
	stored_credentials = login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_credentials is not None and gplus_id == stored_gplus_id:
		response = make_response(json.dumps('Current user already connected'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response

	#store access token in session for later use
	login_session['provider'] = 'google'
	login_session['credentials'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

	#get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': credentials.access_token, 'alt':'json'}
	answer = requests.get(userinfo_url, params = params)
	data = answer.json()

	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']

	user_id = getUserID(login_session['email'])
	if not user_id:
		user_id = createUser(login_session)
	login_session['user_id'] = user_id

	#response with name/picture/info

	output = ''
	output += '<h1>Welcome, '
	output += login_session['username']

	output += '!</h1>'
	output += '<img src="'
	output += login_session['picture']
	output += '">'
	flash("You are now logged in as %s"%login_session['username'])
	print "done!"
	return output

@app.route("/gdisconnect")
def gdisconnect():
	credentials = login_session.get('credentials')
	if credentials is None:
		#check if user connected
		response = make_response(json.dumps('Current user not connected.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	#execute http get to revoke token
	access_token = credentials
	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
	h = httplib2.Http()
	result = h.request(url, 'GET')[0]

	if result['status'] == '200':
		#reset user session
		del login_session['credentials']
		del login_session['gplus_id']
		del login_session['username']
		del login_session['email']
		del login_session['picture']

		response = make_response(json.dumps('Successfully disconnected'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response

	else:
		#for whatever reason token is invalid
		response = make_response(json.dumps('Failed to revoke token for given user'), 400)
		response.headers['Content-Type'] = 'application/json'
		return response


@app.route('/disconnect')
def disconnect():
	if 'provider' in login_session:
		if login_session['provider'] == 'google':
			gdisconnect()
			del login_session['user_id']
		if login_session['provider'] == 'facebook':
			fbdisconnect()

		del login_session['provider']

		flash("You have successfully been logged out.")
		return redirect(url_for('showTopics'))
	else:
		flash("You're not logged in.")
		return redirect(url_for('showTopics'))



@app.route('/')
@app.route('/topics')
def showTopics():
	topics = session.query(Topic)
	if 'username' not in login_session:
		return render_template('publictopics.html', topics=topics)
	else:
		return render_template('topics.html', topics = topics)

@app.route('/topic/new', methods=['GET','POST'])
def newTopic():
	#check if user is logged in
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		newTopic = Topic(name=request.form['name'], description=request.form['description'], user_id=login_session['user_id'])
		session.add(newTopic)
		session.commit()
		flash('New topic created!')
		return redirect(url_for('showTopics'))
	else:
		return render_template('newtopic.html')

@app.route('/topic/<int:topic_id>/edit', methods=['GET', 'POST'])
def editTopic(topic_id):
	editedTopic = session.query(Topic).filter_by(id=topic_id).one()
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		if request.form['name']:
			editedTopic.name = request.form['name']
			editedTopic.description = request.form['description']
		session.add(editedTopic)
		session.commit()
		flash("Topic successfully edited!")
		return redirect(url_for('showTopics'))
	else:
		return render_template('edittopic.html', i = editedTopic)

@app.route('/topic/<int:topic_id>/delete', methods=['GET', 'POST'])
def deleteTopic(topic_id):
	if 'username' not in login_session:
		return redirect('/login')
	topicToDelete = session.query(Topic).filter_by(id=topic_id).one()
	if request.method == 'POST':
		session.delete(topicToDelete)
		session.commit()
		flash('Topic successfully deleted!')
		return redirect(url_for('showTopics'))
	else:
		return render_template('deletetopic.html', i = topicToDelete)
	
	

@app.route('/topic/<int:topic_id>')
@app.route('/topic/<int:topic_id>/subtopics')
def showSubTopics(topic_id):
	topic = session.query(Topic).filter_by(id=topic_id).one()
	creator = getUserInfo(topic.user_id)
	subtopics = session.query(SubTopic).filter_by(topic_id = topic_id).all()
	if 'username' not in login_session or creator.id != login_session['user_id']:
		return render_template('publicsubtopics.html', topic=topic, subtopics=subtopics, creator=creator)
	else:
		return render_template('subtopics.html', topic = topic, subtopics = subtopics, creator=creator)

@app.route('/topic/<int:topic_id>/subtopic/new', methods=['GET','POST'])
def newSubTopic(topic_id):
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		newSubTopic = SubTopic(name=request.form['name'], description=request.form['description'], topic_id = topic_id, user_id = login_session['user_id'])
		session.add(newSubTopic)
		session.commit()
		flash('New subtopic created!')
		return redirect(url_for('showSubTopics', topic_id = topic_id))
	else:
		return render_template('newsubtopic.html', topic_id = topic_id)

@app.route('/topic/<int:topic_id>/subtopic/<int:subtopic_id>/edit', methods=['GET', 'POST'])
def editSubTopic(topic_id, subtopic_id):
	if 'username' not in login_session:
		return redirect('/login')
	editedSubTopic = session.query(SubTopic).filter_by(id=subtopic_id).one()
	if request.method == 'POST':
		if request.form['name']:
			editedSubTopic.name = request.form['name']
			editedSubTopic.description = request.form['description']
		session.add(editedSubTopic)
		session.commit()
		flash('Subtopic successfully edited!')
		return redirect(url_for('showSubTopics', topic_id = topic_id))
	else:
		return render_template('editsubtopic.html', topic_id = topic_id, id = subtopic_id, s = editedSubTopic)

@app.route('/topic/<int:topic_id>/subtopic/<int:subtopic_id>/delete', methods=['GET', 'POST'])
def deleteSubTopic(topic_id, subtopic_id):
	if 'username' not in login_session:
		return redirect('/login')
	deletedSubTopic = session.query(SubTopic).filter_by(id=subtopic_id).one()
	if request.method =='POST':
		session.delete(deletedSubTopic)
		session.commit()
		flash('Subtopic successfully deleted!')
		return redirect(url_for('showSubTopics', topic_id = topic_id))
	else:
		return render_template('deletesubtopic.html', topic_id = topic_id, s = deletedSubTopic)

@app.route('/topic/<int:topic_id>/subtopic/<int:sub_topic_id>')
def showSubTopicItems(topic_id, sub_topic_id):
	topic = session.query(Topic).filter_by(id=topic_id).one()
	subtopics =session.query(SubTopic).filter_by(id=sub_topic_id).one()
	creator = getUserInfo(topic.user_id)
	subtopicitems = session.query(SubTopicItem).filter_by(topic_id = topic_id, sub_topic_id = sub_topic_id).all()
	if 'username' not in login_session or creator.id != login_session['user_id']:
		return render_template('publicsubtopicitems.html', topic=topic, subtopics=subtopics, items=subtopicitems, creator=creator)
	else:
		return render_template('subtopicitems.html', topic = topic, subtopics = subtopics, items=subtopicitems, creator=creator)

@app.route('/topic/<int:topic_id>/subtopic/<int:sub_topic_id>/new', methods=['GET','POST'])
def newSubTopicItems(topic_id, sub_topic_id):
	if 'username' not in login_session:
		return redirect('/login')
	if request.method == 'POST':
		newSubTopicItem = SubTopicItem(name=request.form['name'], description=request.form['description'], picture=request.form['picture'], link=request.form['link'], topic_id = topic_id, sub_topic_id = sub_topic_id, user_id = login_session['user_id'])
		session.add(newSubTopicItem)
		session.commit()
		flash('New subtopic item created!')
		return redirect(url_for('showSubTopicItems', topic_id = topic_id, sub_topic_id = sub_topic_id))
	else:
		return render_template('newsubtopicitem.html', topic_id = topic_id,sub_topic_id = sub_topic_id)

@app.route('/topic/<int:topic_id>/subtopic/<int:subtopic_id>/item/<int:subtopicitem_id>/edit', methods=['GET', 'POST'])
def editSubTopicItem(topic_id, subtopic_id, subtopicitem_id):
	if 'username' not in login_session:
		return redirect('/login')
	editedSubTopicItem = session.query(SubTopicItem).filter_by(id = subtopicitem_id).one()
	if request.method == 'POST':
		if request.form['name']:
			editedSubTopicItem.name = request.form['name']
			editedSubTopicItem.description = request.form['description']
			editedSubTopicItem.link = request.form['link']
			editedSubTopicItem.picture = request.form['picture']
		session.add(editedSubTopicItem)
		session.commit()
		flash('Subtopic item successfully edited!')
		return redirect(url_for('showSubTopicItems', topic_id = topic_id, sub_topic_id = subtopic_id))
	else:
		return render_template('editsubtopicitem.html', topic_id = topic_id, subtopic_id = subtopic_id, id = subtopicitem_id, s = editedSubTopicItem)


@app.route('/topic/<int:topic_id>/subtopic/<int:subtopic_id>/item/<int:subtopicitem_id>/delete', methods=['GET', 'POST'])
def deleteSubTopicItem(topic_id, subtopic_id, subtopicitem_id):
	if 'username' not in login_session:
		return redirect('/login')
	deletedSubTopicItem = session.query(SubTopicItem).filter_by(id=subtopicitem_id).one()
	if request.method =='POST':
		session.delete(deletedSubTopicItem)
		session.commit()
		flash('Subtopic item successfully deleted!')
		return redirect(url_for('showSubTopicItems', topic_id = topic_id, sub_topic_id = subtopic_id))
	else:
		return render_template('deletesubtopicitem.html', topic_id = topic_id, subtopic_id = subtopic_id, id=subtopicitem_id, s = deletedSubTopicItem)


@app.route('/topics/JSON', methods=['GET'])
def topicListJSON():
	topics = session.query(Topic)
	return jsonify(topics=[t.serialize for t in topics])

@app.route('/topic/<int:topic_id>/subtopics/JSON', methods=['GET'])
def subTopicListJSON(topic_id):
	topic = session.query(Topic).filter_by(id=topic_id).one()
	subtopics = session.query(SubTopic).filter_by(topic_id=topic_id).all()
	return jsonify(SubTopics=[s.serialize for s in subtopics])

@app.route('/topic/<int:topic_id>/subtopic/<int:subtopic_id>/JSON', methods=['GET'])
def subTopicJSON(topic_id, subtopic_id):
	subTopic = session.query(SubTopic).filter_by(id=subtopic_id).one()
	return jsonify(SubTopics=[subTopic.serialize])

@app.route('/topic/<int:topic_id>/subtopic/<int:subtopic_id>/subtopicitems/JSON', methods=['GET'])
def subTopicItemsJSON(topic_id, subtopic_id):
	subTopicItems = session.query(SubTopicItem)
	return jsonify(SubTopicItems=[s.serialize for s in subTopicItems])

def getUserID(email):
	try:
		user = session.query(User).filter_by(email = email).one()
		return user.id
	except:
		return None

def getUserInfo(user_id):
	user = session.query(User).filter_by(id = user_id).one()
	return user

def createUser(login_session):
	newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host = '0.0.0.0', port = 8000)