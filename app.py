import os, datetime, time, random, json, uuid, base64, hashlib
from os.path import splitext
from flask import redirect, render_template, url_for, flash, request, Flask, send_file
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from flask.ext.script import Manager, Shell
from flask.ext.bootstrap import Bootstrap
from flask.ext.login import LoginManager, login_required, login_user, UserMixin, logout_user, current_user
from werkzeug import secure_filename
import cloudinary, cloudinary.uploader, cloudinary.api
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, ProfileForm, AddUser, EditUser, TempPasswordForm
from flask.ext.migrate import Migrate, MigrateCommand

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SQLALCHEMY_DATABASE_URI = 'postgresql://localhost/donkey'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    CLOUDINARY_URL = 'cloudinary://368227621922385:c2-QBS-sjsFavGCW03mbSpeMxIY@donkey'
    SECRET_KEY = 'yCt2asdfTsLHvL#BG6'

config = Config

## app setup
app = Flask(__name__)
manager = Manager(app)
bootstrap = Bootstrap(app)
ALLOWED_EXTENSIONS = ['png', 'jpg', 'gif']
UPLOAD_FOLDER = os.path.join(basedir, 'static/photos/')

app.config.from_object(config)

cloudinary.config (
    cloud_name = "donkey", 
    api_key = "368227621922385", 
    api_secret = "c2-QBS-sjsFavGCW03mbSpeMxIY" 
    )

def format_comma(value):
    return "{:,.0f}".format(value)
app.jinja_env.filters['format_comma'] = format_comma

## db setup
db = SQLAlchemy(app)


migrate = Migrate(app, db)

## Login Manager
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    token = db.Column(db.String(64))
    role = db.Column(db.String(64)) # admin, user
    temp_password = db.Column(db.Boolean())
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>\n' % self.username

class Photo(db.Model):
    __tablename__ = 'photos'

    id = db.Column(db.String(64), primary_key=True)
    caption = db.Column(db.String(128), index=True)
    filename = db.Column(db.String(512))
    location = db.Column(db.String(128))
    region = db.Column(db.String(128))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    username = db.relationship('User')
    vote_value = db.Column(db.Integer)

    def __repr__(self):
        return '<TraceFile %r, filename: %r>\n' % (self.name, self.filename)

class Vote(db.Model):
    __tablename__ = 'votes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    photo_id = db.Column(db.String(64), db.ForeignKey('photos.id'))
    value = db.Column(db.Integer)

    def __repr__(self):
        return '<Vote for %r by %s, value: %s>\n' % (self.photo_id, self.user_id, self.value)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    level = db.Column(db.String) #info, warning, error
    description = db.Column(db.String)

    def __repr__(self):
        return '<Log: %s - %s - %s>\n' % (self.timestamp, self.level, self.description)

def allowed_file(filename):
    return '.' in filename and (filename.split('.')[-1] in ALLOWED_EXTENSIONS)

def get_uuid():
    return base64.b64encode(hashlib.sha256( str(random.getrandbits(256)) ).digest(), random.choice(['rA','aZ','gQ','hH','hG','aR','DD'])).rstrip('==')

def log(level, description):
    note = Log(timestamp=datetime.datetime.now(), level=level.upper(), description=description)
    db.session.add(note)
    db.session.commit()

@app.route('/login/', methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(request.args.get('next') or url_for('login'))
        
        if user.temp_password:
            return redirect(url_for('home'))
        else:
            return redirect(request.args.get('next') or url_for('home'))

    else:
        return render_template('login.html', form=form)

@app.route('/logout/', methods=['GET','POST'])
def logout():
    logout_user()
    flash('You have been logged out.', 'warning')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def home():

    form = TempPasswordForm()

    if form.validate_on_submit():

        user = User.query.filter_by(id=current_user.id).one()

        if user.verify_password(form.temp_password.data):
            user.password = form.new_password1.data
        else:
            flash('Current password is not correct.', 'danger')
            return redirect(url_for('home'))

        user.temp_password = False
        db.session.commit()


        flash('Password has been changed.', 'success')
        return redirect(url_for('home'))

    else:
        
        photos = Photo.query.order_by(desc(Photo.vote_value)).all()

        return render_template('home.html', form=form, photos=photos)


@app.route('/users/', methods=['GET', 'POST'])
@login_required
def users():
    form = AddUser()

    if form.validate_on_submit():
        if current_user.role != 'admin':
            flash('You are not permitted to add users.', 'warning')
            return redirect(url_for('users'))

        if form.role.data not in ['admin', 'user']:
            flash('%s is not a valid role.' % form.role.data, 'warning')
            return redirect(url_for('users'))

        user = User(username=form.username.data, 
            password=form.password.data, 
            role=form.role.data, 
            temp_password=True,
            token = get_uuid())

        db.session.add(user)
        db.session.commit()

        flash('User %s has been added.' % user.username, 'success')
        return redirect(url_for('users'))

    else:

        if current_user.role != 'admin':
            flash('You are not permitted to edit users.', 'warning')
            return redirect(url_for('home'))

        users = User.query.order_by(User.id).all()
        return render_template('users.html', form=form, users=users)

@app.route('/users/<user_id>', methods=['GET', 'POST'])
@login_required
def user(user_id):
    form = EditUser()

    if form.validate_on_submit():
        if current_user.role != 'admin':
            flash('You are not permitted to edit users.', 'warning')
            return redirect(url_for('users'))

        if form.role.data not in ['admin', 'user']:
            flash('%s is not a valid role.' % form.role.data, 'warning')
            return redirect(url_for('users'))

        user = User.query.get_or_404(user_id)
        user.role = form.role.data
        db.session.commit()
        
        flash('Changes to %s have been made.' % user.username, 'success')
        return redirect(url_for('users'))

    else:

        if current_user.role != 'admin':
            flash('You are not permitted to edit users.', 'warning')
            return redirect(url_for('dashboard'))

        user = User.query.get_or_404(user_id)

        form.role.data = user.role

        return render_template('users.html', form=form, user=user)

@app.route('/users/<user_id>/delete/')
@login_required
def delete_user(user_id):

    name = User.query.get_or_404(user_id).username
    User.query.filter_by(id=user_id).delete()

    db.session.commit()

    log('info','Deleting user: %s' % name)

    flash('User %s has been deleted' % name, 'success')
    return redirect('users')

@app.route('/profile/', methods=['GET', 'POST'])
@login_required
def profile():

    form = ProfileForm()

    if form.validate_on_submit():

        user = User.query.filter_by(username=current_user.username).one()

        user.email = form.email.data

        if form.new_password1.data:
            if user.verify_password(form.current_password.data):
                user.password = form.new_password1.data
            else:
                db.session.commit()
                flash('Current password is not correct.', 'danger')
                return redirect(url_for('profile'))

        db.session.commit()

        flash('Profile changes saved.', 'success')
        return redirect(url_for('profile'))

    else:

        user = User.query.filter_by(username=current_user.username).one()
        
        photos = Photo.query.filter_by(user_id=user.id).order_by(desc(Photo.vote_value)).all()

        votes = {}

        for photo in photos:
            temp_votes = Vote.query.filter_by(photo_id=photo.id).all()
            votes[photo.id] = {'up': 0, 'down': 0}
            for vote in temp_votes:
                if vote.value > 0:
                    votes[photo.id]['up'] += 1
                else:
                    votes[photo.id]['down'] += 1

            votes[photo.id]['total'] = votes[photo.id]['up'] - votes[photo.id]['down']

        form.email.data = user.email

        return render_template('profile.html', form=form, photos=photos, votes=votes)

@app.route('/profile/photos')
@login_required
def profile_photos():

    user = User.query.filter_by(username=current_user.username).one()

    photos = Photo.query.filter_by(user_id=user.id).all()

    votes = {}

    for photo in photos:
        temp_votes = Vote.query.filter_by(photo_id=photo.id).all()
        votes[photo.id] = {'up': 0, 'down': 0}
        for vote in temp_votes:
            if vote.value > 0:
                votes[photo.id]['up'] += 1
            else:
                votes[photo.id]['down'] += 1

        votes[photo.id]['total'] = votes[photo.id]['up'] - votes[photo.id]['down']

    
    return render_template('profile.html', photos=photos, votes=votes)

# @app.route('/photoupload', methods=['POST'])
def api_upload_photo(photoFile, token):
    
    try:
        user = User.query.filter_by(token=token).one()
    except NoResultFound:
        return json.dumps({"status":404,"exceptions":["API Token is missing or invalid"]}), 404

    # photoFile = request.files['file']

    if photoFile and allowed_file(photoFile.filename):

        # print photoFile.filename

        filetype = splitext(photoFile.filename)[1].strip('.')
        uuid_filename = '.'.join([str(uuid.uuid4()),filetype])
        # photoFile.save(os.path.join(UPLOAD_FOLDER, uuid_filename))
        c_response = cloudinary.uploader.upload(photoFile)
        
        new_file = Photo(id=c_response['public_id'],
            caption=secure_filename(splitext(photoFile.filename)[0]),
            user_id = user.id,
            filename = str(c_response['url']),
            vote_value = 1
            )

        db.session.add(new_file)
        db.session.commit()
        db.session.refresh(new_file)

        auto_vote = Vote(
            photo_id = new_file.id,
            user_id = current_user.id,
            value = 1
            )

        db.session.add(new_vote)
        db.session.commit()

        log('info','File uploaded by \'%s\': %s.' % (user.username, new_file.caption))
        return json.dumps({"filename": new_file.caption,"id":new_file.id}), 202

    else:
        return json.dumps({"status":406,"exceptions":["Not a valid file type. (pcap, pcapng, cap)"]}), 406

    # else: 
    #     return 'Upload Files to this path.'

@app.route('/photos/upload', methods=['POST'])
@login_required
def upload_photo():

    photoFile = request.files['file']

    return api_upload_photo(photoFile, current_user.token)


# @app.route('/photos/delete/<file_id>')
def api_delete_file(photo_id, token):

    try:
        photoFile = Photo.query.filter_by(id=photo_id).one()
    except NoResultFound:
        return json.dumps({"status":404,"message":"Photo not found.", "id": photo_id}), 404

    try:
        user = User.query.filter_by(id=photoFile.user_id).one()
    except NoResultFound:
        return json.dumps({"status":404,"message":"Photo not found.", "id": photo_id}), 404


    if token == user.token:
        
        Vote.query.filter_by(photo_id=photo_id).delete()
        Photo.query.filter_by(id=photo_id).delete()

        db.session.commit()

        # try:
        # os.remove(os.path.join(UPLOAD_FOLDER, photoFile.filename))
        cloudinary.api.delete_resources([photo_id])
        # except Exception as e:
        #     print e

        log('info','Photo deleted by \'%s\': %s.' % (user.username, photoFile.caption))
        return json.dumps({"status":200,"message":"Photo deleted successfully.","id":photoFile.id}), 200
    else:

        return json.dumps({"status":403,"message":"Not Authorized."}), 403

@app.route('/photos/delete/<photo_id>')
@login_required
def delete_file(photo_id):

    return api_delete_file(photo_id, current_user.token)
    
@app.route('/photos/vote/<photo_id>', methods=['POST'])
@login_required
def vote(photo_id):

    vote = request.data

    vote_value = {'down': -1, 'up': 1}

    # existing vote by user for this photo
    existing_vote = Vote.query.filter_by(photo_id=photo_id).filter_by(user_id=current_user.id).first()

    if existing_vote:
        if existing_vote.value == vote_value[vote]:
            Vote.query.filter_by(photo_id=photo_id).filter_by(user_id=current_user.id).delete()
        else:
            existing_vote.value = vote_value[vote]
            # db.session.merge(existing_vote)

        db.session.commit()
        db.session.flush()
        # db.session.refresh(existing_vote)

    # if existing vote matches current vote
    else:
        new_vote = Vote(
            photo_id = photo_id,
            user_id = current_user.id,
            value = vote_value[vote]
            )

        db.session.add(new_vote)
        db.session.commit()
        db.session.flush()
        # db.session.refresh(new_vote)

    #update vote value
    photo = Photo.query.get(photo_id)
    photo.vote_value = sum([x.value for x in Vote.query.filter_by(photo_id=photo_id)])
    
    return 'Success', 200

@app.route('/photos/checkvote/<photo_id>')
@login_required
def check_vote(photo_id):


    existing_vote = Vote.query.filter_by(photo_id=photo_id).filter_by(user_id=current_user.id).first()

    try:
        if existing_vote.value == 1:
            return 'up', 200
        else:
            return 'down', 200
    except AttributeError:
        return 'none', 204


# @app.route('/savename/<file_id>', methods=['POST'])
# @login_required
# def save_name(file_id):

#     name = request.data

#     if name:
        
#         traceFile = TraceFile.query.filter_by(id=file_id).one()

#         traceFile.name = secure_filename(name)

#         db.session.commit()
    
#     return 'Name has been updated.'

@app.route('/downloadfile/<file_id>/<attachment_name>')
@login_required
def download_file(file_id, attachment_name):

    traceFile = TraceFile.query.get_or_404(file_id)

    return send_file(os.path.join(UPLOAD_FOLDER, traceFile.filename), attachment_filename=attachment_name)

@app.route('/help/')
@login_required
def help():
    return render_template('help.html')

@app.route('/logs/')
@login_required
def logs():

    if current_user.role != 'admin':
        return redirect(url_for('home'))
    
    level = request.args.get('level')
    limit = request.args.get('limit')

    try:
        limit = int(limit)
    except (ValueError, TypeError):
        limit=50

    if level:
        logs = Log.query.filter_by(level=level.upper()).order_by(desc(Log.timestamp)).limit(limit).all()
    else:
        logs = Log.query.order_by(desc(Log.timestamp)).limit(limit).all()

    return render_template('logs.html', logs=logs, level=level, limit=limit)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    log('error', 'Exception: %s' % e)
    return render_template('500.html', e=e), 500

@app.before_first_request
def schedule_updates():
    log('info', '-------------- App has started --------------')

def make_shell_context():
    return dict(app=app, db=db, User=User, Vote=Vote, Photo=Photo, Log=Log)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    # app.run(host='0.0.0.0', debug=True, threaded=True)
    manager.run()
