# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## Index
The analysis of the implementation of this vulnerability is divided in the following sections:

1. [Explanation](#explanation)
2. [Implementation](#implementation)
    - [Posssible exploitation](#posssible-exploitation)
4. [Mitigation](#mitigation)
5. [Examples](#examples)

## Explanation

- What is [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

> *The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.*
> 
> by **Common Weakness Enumeration**

For a website to have dynamic but persistent data, this information has to be stored somewhere, otherwise it would just be a static website and that would be impossible to implement if we want the website to be, as we said before, **dynamic** and interactive.

So, the best method for a developer to store information about all kinds of intervinients in the web application is to create some sort of a **database**. This could be accomplished in a number of different ways, most commonly we have either **SQL databases** or **NoSQL databases** (like **MongoDB** wich uses a structure like JSON). This said, SQL databases are still the most used, and the used type in project.

- **SQL Databases**

Soo, how do we get data **to** and **from** this database to the **user** ?

This process has **3** major steps:
  1. User requesting information via the **client**, and **specifying** or **identifying** who he/she is, in a **request to the server**
  2. Server will **use the received information** from the user to craft a special type of **statement** that is executed to the **database**, resulting in this last one to **respond** with the requested data in the **statement**
  3. The server will now **respond** to the **client** that presents the data to the user

  - A SQL Injection can occur if the step **2** is **mishandled**, how soo ?

As said, the server crafts a **statement** to retrieve the asked information **from the database**, in this statement, in most cases, what the user has requested has to be **specified inside the statement** that is send to the database. What stops he user from misspealing or crafting a word or set of word that **will be inserted** inside the **sql statement** ? **Nothing**. Because of this, one has to **assume the worst** case scenario, and insert this user inputs very carefully in said statement.

## Implementation

- **How** it was implemented

This project being a webstore, with the possibility of a user to create his/her own account, the option of **reset the password** if one was to forget it, must be given. It is in this process that the **SQL Injection** will take place.

The code bellow is relative to the **function** in the **server side** of the operation, that handles the **requests** from the client to pass information about the **username** that is asking permission to **reset** the password. This process is a **mimic** of a common process used by a great number of website worldwide, where to **reset** the password, a user will **only** have to specify a **username**, after this, the server will send a **message** to the email address associated with the given **username**, containing a **one-time-use unique key** attached to a url that is **associated with the username**, that url once it's accessed gives permission to the user to **set a new password**, the hash of this new password will **replace** the old one.

The ensure safety in the process, this **one-time-use unique key** is composed of **64 random alpha-numeric characters** and is this key that will then be used to **identify** the **position** in the **database** were the new password hash is **to be set**.

```python
@cherrypy.expose
@cherrypy.tools.json_out()
@cherrypy.tools.json_in()
def reset_validation(self):
    input = cherrypy.request.json
    username = decode64(input["username"])

    db = sqlite3.connect("database.db")
    cur = db.cursor()

    com = "SELECT email FROM users WHERE username='%s'" % username      # <-- !!!
    match = cur.execute(com)

    email = match.fetchone()[0]

    response = None
    if email != None:
        ran = "".join(random.choices(
            string.ascii_uppercase + string.digits, k=64))

        com = " UPDATE users SET reset='%s' WHERE username= '%s'" % (ran, username)     # <-- !!!
        cur.execute(com)
        db.commit()

        repo_email = "/newpassword?id=" + ran
        
        print("\n<--- Simulação email --->\n\nSent to: " + email + "\n\nReposition url: " +
              repo_email + "\n\n<--- Simulação email --->\n")
              
        response = {
            "success": 1,
            "message": "Verifique o seu email pelo link de reposicao",
        }
    else:
        response = {"success": 0, "message": "Username inexistente"}

    db.close()
    return json.dumps(response)
```
Notice:
- *This being a project, an email service in not provided, thus the one-time-use unique key with the url is printed to the console to simulate what would be send in the email and the email it would be sent to. This url must be appended to the website hostname (ex. 127.0.0.1:8080/newpassword?id=key)*
- *This piece of code is the only one mishandled in the **unsecure** version of this website, simulating a programmers lapse in development, and the security effect it can have*

This previous code is a good exemple of how **not to** combine **user generated values** with SQL statements. They key is the **''(quotes)** that surround the variable, they define what's inside of them as a variable or a value, instead of being part of the SQL statement directives.

This said, if an attacker was able to **write outside this quotes**, his/her input would be considered as part of the directives and would have some control over what the SQL statement executes. In the previous code this is possible, since all an attacker has too do is **write** the end quote and all that is written after that will be considered as SQL statement directives

### Posssible exploitation

Exploring the flaw in this code is particularly interesting, since even after the SQL Injection attack, the attacker does not gain any power over the service or even necessarily destroys any information.

What the attacker can do is **set a trap** that, may or may not, bet **triggered by a inocent user**, without this one knowing or even noticing any difference in the website on is side, but **all the other users** will definitely notice it since the trap will result in a **denial of service** by making the **user's accounts inaccessible to their owners**.

- **How to do it**

By navigating to the **reset** page, we will be met with a form that asks us to provide a **username**. Where a normal user would provide is own username in order to receive the email message, we will **put the following code**
```sql
' OR 1=1 --
```
Notice:
- *This project uses SQLite3, if it was used other kind of SQL database the sintax could be different*

This will **result** in the end **SQL statement** being something like
```python
com = "SELECT email FROM users WHERE username='' OR 1=1 --'"
match = cur.execute(com)
email = match.fetchone()[0]

...

com = " UPDATE users SET reset='%s' WHERE username= '' OR 1=1 --'"
cur.execute(com)
db.commit()

```

What will this do ? Previously it was mentioned that the **one-time-use url key** was created and placed in the position associated with the given **username**, but what the **resulting** SQL statement does is **retrieving the first email address** of the **SQL table**, to where the reset email **will be send**, and also placing the **key** in **every position** of the table, associating it to **all the users**

Lets look now at the function that server the **new password setting** page, only serving it if the **id**(GET param) is found on the table 
```python
@cherrypy.expose
def newpassword(self, id):
    db = sqlite3.connect("database.db")
    cur = db.cursor()

    com = """ SELECT * FROM users WHERE reset=? """
    arg = (id,)
    match = cur.execute(com, arg)

    data = match.fetchone()[0]

    if data == None:
        return "Ops, this record doesn't exists"
    else:
        return open("resources/newpassword.html")

```

And the function that **sets the new password hash** in the users table, for **every position the key is found***
```python
@cherrypy.expose
@cherrypy.tools.json_out()
@cherrypy.tools.json_in()
def newpassword_validation(self):
    input = cherrypy.request.json
    resetid = decode64(input["resetid"])
    hash = decode64(input["hash"])

    db = sqlite3.connect("database.db")
    cur = db.cursor()

    com = """ UPDATE users SET hash=?, reset=NULL WHERE reset= ? """
    arg = (hash,resetid)
    cur.execute(com, arg)

    db.commit()
    db.close()

    response = {"message": "Password atualizada com sucesso"}

    return json.dumps(response)
```
This two previous functions do not present any danger in them selfs, the danger is already present in the database itself since when the **key** was **misplaced**

That trap is set now, the trigger of this **denial of service "time bomb"** will get "pushed" if, by chance, the first user, the person who receives the email, is inocent enough to follow the link and **reset his/hers** password, but in doing soo, it will also **set this new password** for **all the users** in the table *(see functions above)*. 

So effectively, after this, **every user** will have **the same password**, but the only person who knows it is the inocent victim that followed the link, resulting in **every single user**, except the victim for whom nothing appears to change, to be **locked out** of his/hers account.

## Mitigation

Preventing this vulnerability however is quite simples, if we use (like we did on the othe SQL database queries) **parameterized statements**.

By **hardcoding** SQL statements, and only leaving placeholders in the string containing que querie, we can than **pass** that **querie** and a **tuple containing the variables** with the user input, directly to the **execute()** function from the **sqlite3** lib. Just this simples step will prevent all kinds of SQL Injection

So the previous code will suffer the following changes in the **reset_validation()** function

```python
From this ⬇️

com = "SELECT email FROM users WHERE username='%s'" % username      # <-- !!!
match = cur.execute(com)
...
com = " UPDATE users SET reset='%s' WHERE username= '%s'" % (ran, username)     # <-- !!!
cur.execute(com)

To this ⬇️

com = """SELECT email FROM users WHERE username= ?"""
arg = (username,)
...
com = """ UPDATE users SET reset=? WHERE username= ?"""
arg = (ran, username)
cur.execute(com, arg)
```

Notice
- *It is also good pratice to use """(triple quotes) in python, since doing soo escapes every character inside the string*

## Examples

### Vulnerable
As we can see, after the SQL querie gets inserted in the form a loaded to the server, it operates as parte of que SQL statement, resulting in the improper modification of the SQL table, placing the unique random key in all the rows of the table

![Vulnerable](CWE-89-vulnerable.gif)

---
### Safe
In the safe version, because the input is treated as a simple string, we just get an error message since the input doesn't match any existing username, it there was a user with that as a username, the key would simple get inserted in the corresponding row of that user

![Vulnerable](CWE-89-safe.gif)
