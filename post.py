from google.appengine.ext import db

from user import User
import template_render

class Post(db.Model):
	"""
        This is a Post Class, which holds blog post information.
        And helps to store/retrieve User data to/from database.
        Attributes:
            user_id (int): This is user id, who wrote the blog post.
            subject (str): This is subject line of the post.
            content (text): This is content of the post.
            created (text): This is date of the post.
    """

	user_id = db.IntegerProperty(required=True)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def getUserName(self):
		user = User.by_id(self.user_id)
		return user.name

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return template_render.jinja_render_str("post.html", p = self)
