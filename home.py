import os
import webapp2
import jinja2
import re
import hmac
from google.appengine.ext import db

template_path=os.path.join(os.path.dirname(__file__),"template")
JINGA_ENVIRONMENT=jinja2.Environment(loader=jinja2.FileSystemLoader(template_path),autoescape=True)

SECRET_KEY="COOLME"

def make_hash_cookie_string(s):
    return str(s+"|"+hmac.new(SECRET_KEY,s).hexdigest())

def make_password_hash(s):
    return str(hmac.new(SECRET_KEY, s).hexdigest())

def check_hash_value(h):
    key=h.split("|")[0]
    if h==make_hash_cookie_string(key):
        return True

class Handler(webapp2.RequestHandler):
    def write(self, *a):
        self.response.out.write(*a)

    def render_string(self, template, **params):
        t=JINGA_ENVIRONMENT.get_template(template)
        return t.render(params)

    def render(self, template, **params):
        self.write(self.render_string(template, **params))

class User(db.Model):
    username=db.StringProperty(required=True)
    password=db.TextProperty(required=True)
    email=db.StringProperty()
    created_on=db.DateTimeProperty(auto_now_add=True)

class MainPage(Handler):
    def get(self):
        items=self.request.get_all("items")
        self.render("mainpage.html",items=items)


class SignUp(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        username=self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        user=valid_username(username)
        pass1=valid_password(password)
        pass2=valid_password(verify)
        ema=valid_email(email)
        if not user:
            self.render_argument(error1="Enter Username")
        elif user_exist(username):
            self.render_argument(error1="User already exist")
        elif not pass1:
            self.render_argument(error2="Enter Password",name=username)
        elif not pass2:
            self.render_argument(error3="Enter Password to verify",name=username,passw=password)
        elif password != verify:
            self.render_argument(error3="The password does not match",
                                name = username, passw = password)
        else:
            newData=User(username=username, password=make_password_hash(password), email=email)
            x=newData.put()
            if x:

                self.response.headers.add_header("Set-Cookie", "user_id="+make_hash_cookie_string(str(newData.key().id()))+
                                                 "; path=/")
                self.redirect("/unit3/welcome")
            
    def render_argument(self,error1='',error2='',error3='',error4='',name='',passw='',email=''):
        self.render("signup.html", error1=error1, error2=error2, error3=error3,
                    error4=error4,name=name,passw=passw,mail=email)


def user_exist(user_name):
    cursor=db.GqlQuery("select * from User where username = :num",num=user_name)
    for x in cursor:
        return True

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_PASS= re.compile(r"^.{3,20}$")
USER_EMAIL= re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return USER_PASS.match(password)


def valid_email(email):
    return USER_EMAIL.match(email)


class FeedBuzz(Handler):
    def get(self):
        self.render("solution_list.html")

    def post(self):
        data=self.request.get("text")
        string=""
        for x in data:
            t=ord(x)
            if t>=97 and t<=122:
                if(t+13<=122):
                    string+=chr(t+13)
                else:
                    etc=t+13-122
                    string+=chr(96+etc)
            elif t>=65 and t<=90:
                if(t+13<=90):
                    string+=chr(t+13)
                else:
                    etc=t+13-90
                    string+=chr(64+etc)
            else:
                string+=chr(t)
        self.render("solution_list.html", data=string)


class Userwelcome(Handler):
    def get(self):
        username=self.request.cookies.get("user_id")
        if username:
            ID=username.split("|")[0]
            user=User.get_by_id(int(ID))
            if user and check_hash_value(username):
                name = user.username
                self.render("welcome.html",username=name)
            else:
                self.redirect("/signup")
        else:
            self.redirect("/signup")

class LogIn(Handler):
    def render_argument(self,error1="",error2=""):
        self.render("login.html",error1=error1,error2=error2)

    def get(self):
        self.render_argument()

    def post(self):
        username=self.request.get("username")
        password=self.request.get("password")
        print(user_exist(username))
        if not username or not password:
            self.render_argument(error2="username or password is wrong.")
        elif user_exist(username):
            x=User.all().filter("username = ",username).get()
            password_in_db=x.password
            #great thing to remember. x is model instance, instance.key()-> gives key instance and than you can get your key.
            ID=x.key().id()
            if make_password_hash(password)==password_in_db:
                self.response.headers.add_header("Set-Cookie","user_id = "+make_hash_cookie_string(str(ID))+
                                                 "; path=/")
                self.redirect("/unit3/welcome")
        else:
            self.render_argument(error1="user does not exist")

class LogOut(Handler):
    def get(self):
        self.response.headers.add_header("Set-Cookie", "user_id =" + "; path=/")
        self.redirect("/signup")



app = webapp2.WSGIApplication([
    ('/', MainPage), ('/feedbuzz', FeedBuzz), ('/signup', SignUp),
    ("/unit3/welcome",Userwelcome),("/login", LogIn) , ("/logout",LogOut)
], debug=True)
