Author: Rigoberto Gort
Date: 03/22/2017

------------- Project Info -------------

Filename: README.txt

Main Project File: blog.py

Connected Module Files: comment.py, like_dislike.py, post.py, template_reader.py, user.py, app.yaml, index.yaml

------------- Configuration Instructions -------------

- blog.py -

This is the primary file for running the multi-user blog website where a user can add a newpost, comment on existing posts, like posts, and delete posts or comments.

This file connects the other components from comment.py, like_dislike.py, post.py, template_reader.py, user.py, app.yaml, index.yaml together which builds the overall site.

------------- Operating Instructions -------------
If you want to run the script you must be using the google cloud sdk for gcloud.

Once installed and configured correctly you will do the following. 

You would need to,

1.) Open the CMD prompt.
2.) Change the directory to the project folder via cd in Windows to the project folder directory.
ex: cd Desktop/Project
3.) After changing the directory successfully you will return to the CMD prompt and type dev_appserver.py .
NOTE: Keep in mind that ending . is not a period but a part of of the code necessary to run the project files.
4.) Once the command has executed you will type localhost:8080/blog.
5.) From there you will be able to view the main blog page, login, and signup from the main page. In order to add a newpost you would simply add /newpost to the url at the top after localhost:8080/blog


The public URL for the project to see it running is as follows,

https://multi-user-blog-project-162306.appspot.com/blog

------------- end of read_me.txt -------------