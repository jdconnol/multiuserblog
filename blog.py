import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'joec'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # returns the user ID value of the cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.redirect('/blog/')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# our blog values
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    likes = db.ListProperty(int, required = True)
    ## new values
    ## creator is the hash of the user. 
    creator = db.IntegerProperty(required = True)
    # ## both likes and unlikes will be a list of user-emails (or hashes)
    # ## a new 'like' has the user-email checked against existing list
    # ## total number of likes is len(list)
    
    # unlikes = db.StringListProperty(required = False)

    @classmethod
    def by_id(cls, pid):
        """Get post by id"""
        return Post.get_by_id(pid, parent=blog_key())

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self, user=user)

class Comment(db.Model):
    post_id = db.IntegerProperty(required = True)
    creator = db.IntegerProperty(required = True)
    content = db.TextProperty(required = True)
    # likes = db.ListProperty(int, required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_id(cls, pid):
        """Get comment by id"""
        return Comment.get_by_id(pid, parent=blog_key())

    # this allows us to render comments
    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", p = self, user=user)
    ## new values
    ## creator is the hash of the user. 


class BlogFront(BlogHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:            
            curr_user_id = self.read_secure_cookie('user_id')
            # posts = Post.all().order('-created')
            posts = db.GqlQuery("select * from Post order by created desc limit 10")
            # self.render('front.html', posts = posts)
            self.render('front.html', posts = posts, user = self.user)

class PostPage(BlogHandler):
    def get(self, post_id):
        if self.user:            
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)  
            comments = Comment.all().filter(
                'post_id =', int(post_id)).order('created')

            if not post:
                self.error(404)
                return

            self.render("permalink.html", post = post, comments = comments)
    def post(self, post_id):
        # get post key from URL
        if self.user:   
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            creator = int(self.read_secure_cookie('user_id'))
            comment_content = self.request.get('comment_content')
            comments = Comment.all().filter(
                'post_id =', int(post_id)).order('created')
            # if the comment is empty
            if comment_content == "":
                msg = "an empty comment isn't a comment! try again"
                self.render("permalink.html", post=post, comments = comments, error = msg)
                self.write("your content is %s" % comment_content)
            elif self.user:
                # add comment to DB
                c = Comment(parent = blog_key(),
                            post_id = post.key().id(),
                            content = comment_content,
                            creator = creator)
                c.put()
                comments = Comment.all().filter(
                    'post_id =', int(post_id)).order('created')
                # re-direct to permalink page
                time.sleep(.25)
                self.render("permalink.html", post=post, comments = comments)

class EditComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            # get the comment from DB
            key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if post.creator != self.user.key().id():
                self.redirect('/blog?')
            self.render('editcomment.html', post = post)

    def post(self, post_id):
        # if not logged in --> send to blog
        if not self.user:
            self.redirect('/blog?')

        # get the post

        post_id = int(self.request.get('comment_id'))
        post = Comment.by_id(post_id)

        if not post:
            self.error(404)

        post_content = self.request.get('content')

        #if there's a subject and content - update DB
        if post_content:
            post.content = post_content
            post.put()
        # redirect to the /permalink page for this comment!
            time.sleep(.25)
            self.redirect('/blog/%s' % str(post.post_id))
        # if not, display error & re-render page
        else:
            error = "you need to put content! otherwise just delete the post!"
            self.render('editcomment.html', post=post, error = error)
        


## posts a new blog page
class NewPost(BlogHandler):
    def get(self):
        ## checks if you're a user, if yes, renders the new post page, otherwise login
        
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        # userID is read from cookie as a string, must conver to int
        creator = int(self.read_secure_cookie('user_id'))

        #adds new post to the database if valid.
        if subject and content:
            p = Post(parent = blog_key(),
                    subject = subject,
                    content = content,
                    creator = creator)
            # adds new post to DB
            p.put() 
            # redirects to blog/database-id-of-the-post
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
        ## if a subject and content have not been entered -- returns page with an error
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    # if user logs out, redirects to signup page
    def get(self):
        self.logout()
        self.redirect('/signup')

class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            if post.creator != self.user.key().id():
                self.redirect("/blog")

            self.render('editpost.html', post = post)
        else:
            self.redirect("/login")


    def post(self, post_id):
        # if not logged in --> send to blog
        if not self.user:
            self.redirect('/blog')

        # get the post

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)

        if post.creator != self.user.key().id():
                self.redirect("/blog")

        post_content = self.request.get('content')
        post_subject = self.request.get('subject')

        #if there's a subject and content - update DB
        if post_subject and post_content:
            post.subject = post_subject
            post.content = post_content

            post.put()
        # redirect to specific blog page
            self.redirect('/blog/%s' % str(post.key().id()))
        # if not, display error & re-render page
        else:
            msg = "you need to put a subject and a content! no half assed posts"
            self.render('editpost.html', post=post, error = msg)

class Like(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            curr_user_id = self.user.key().id()

            if not post:
                self.error(404)
                return

            if curr_user_id == post.creator: 
                #  same person can't like their own post, send back to blog. 
                # if they've already liked post send back to blog
                self.redirect('/blog')
            elif curr_user_id_long not in post.likes:
                post.likes.append(int(curr_user_id))
                post.put()
                time.sleep(.25)
                self.redirect('/blog')

            else:
                self.redirect('/blog')

class Unlike(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        curr_user_id = self.read_secure_cookie('user_id')
        curr_user_id_long = long(curr_user_id)
        likes_list = post.likes
        if curr_user_id == post.creator: 
            #  same person can't unlike their own post, send back to blog. 
            # if they've already liked post send back to blog
            self.redirect('/blog')
        elif curr_user_id_long in post.likes:
            likes_list.remove(int(curr_user_id))
            post.likes = likes_list
            post.put()
            time.sleep(.25)
            self.redirect('/blog')

        else:
            # add curr_user_id to list of likes
            self.redirect('/blog')
            # self.write('you already liked it! OR not the same post_creator: %s and post.creator: %s' % (int(curr_user_id), post.likes))  

class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            if post.creator != self.user.key().id():
                self.redirect("/blog")
            else:
                #  delete the post
                post.delete()
                time.sleep(.25)
                self.redirect('/blog')

class DeleteComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            if post.creator != self.user.key().id():
                self.redirect("/blog")
            # delete the comment
            else:
                blog_post_id = post.post_id
                post.delete()
                time.sleep(.25)
                self.redirect('/blog/%s' % str(blog_post_id))



app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)/', EditPost),
                               ('/blog/like/([0-9]+)/', Like),
                               ('/blog/unlike/([0-9]+)/', Unlike),
                               ('/blog/editcomment/([0-9]+)/', EditComment),
                               ('/blog/deletecomment/([0-9]+)/', DeleteComment),
                               ('/blog/deletepost/([0-9]+)/', DeletePost),
                               # ('/blog/deletepost', DeletePost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
