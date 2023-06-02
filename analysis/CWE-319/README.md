# CWE-319: Cleartext Transmission of Sensitive Information


## Index
The analysis of the implementation of this vulnerability is divided in the following sections:

1. [Explanation](#explanation)
2. [Implementation](#implementation)
    - [Posssible exploitation](#posssible-exploitation)
4. [Mitigation](#mitigation)
5. [Examples](#examples)

## Explanation

- What is [CWE-319](https://cwe.mitre.org/data/definitions/319.html)

> The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.
> 
> *Many communication channels can be "sniffed" by attackers during data transmission. For example, network traffic can often be sniffed by any attacker who has access to a network interface. This significantly lowers the difficulty of exploitation by attackers.*
> 
> by **Common Weakness Enumeration**

This perhaps being the _simplest_ vulnerability of this project, is also an incredibly important one.

This vulnerability comes, not from errors or bugs in the code, but from the complete lack of a secure tactic in the design of the application, by leaving the traffic in the communication channels completly exposed to third partys that can intercept it. 

## Implementation

- **How** it was implemented  

The implementation of this vulnerability is pretty straightforward since all one has too do is **not implementing** a method of encrypting and protecting the already mentioned traffic and communication channels like **POST and GET requests**.

By not doing this, in this particular project, the **default protocol** in **Cherrypy** for information transfer is **HTTP**, wich **does not encrypt** the information that it transfers.

### Posssible exploitation

As the information tranfered is not encrypted, if an attacker were to **intercept communications** between client and server, it would see the information transmitted clearly written.

Intercepting this communications, at least in this project, is quite simple since all communications are in the host machine, soo by setting up a monitoring software like **Wireshark** we can intercept the requests and replys and read them easily. 

This is done in the [Examples](#exemples) section and we'll be able to see the differences in **HTTP vs HTTPS**

## Mitigation

As said above, the simplest and most effective solution is tho switch protocols, from HTTP to **HTTPS**.

- What is **https** ?

HTTPS stands for Hypertext Transfer Protocol Secure (also referred to as HTTP over TLS or HTTP over SSL). HTTPS uses TLS (or SSL) to encrypt HTTP requests and responses, so instead of the plaintext, an attacker would see a series of seemingly random characters.

SSL/TLS uses both asymmetric and symmetric encryption to protect the confidentiality and integrity of data-in-transit. Asymmetric encryption is used to establish a secure session between a client and a server, and symmetric encryption is used to exchange data within the secured session. 

The public key form the asymmetric method is shared with client devices via the server's SSL certificate. The certificates are cryptographically signed by a Certificate Authority (CA), and each browser has a list of CAs it implicitly trusts. Any certificate signed by a CA in the trusted list is given a green padlock lock in the browser’s address bar, because it is proven to be “trusted” and belongs to that domain. Since in this project, we created the certificate ourselves, they are not recognized by the browser and thus, although the data is encrypted securely, the browser does not recognizes de certificate and gives out a warning when accessing the site for the first time.

The SSL certificates were created following the indications in the [Cherrypy Docs](https://docs.cherrypy.dev/en/latest/deploy.html#ssl-support), using **python's built-in SSL** and **without** a password in the private key.

The alterations in the code are as following:

```python
From this ⬇️

if __name__ == "__main__":
    conf = {
        "/": {
            "tools.sessions.on": True,
            "tools.staticdir.on": True,
            "tools.staticdir.dir": os.path.abspath("./"),
            "error_page.default": notfound,
        }
    }
    cherrypy.config.update(
        {
            "tools.sessions.secure": "True",
        }
    )
    cherrypy.quickstart(serve(), "/", conf)

To this ⬇️

if __name__ == "__main__":
    conf = {
        "/": {
            "tools.sessions.on": True,
            "tools.staticdir.on": True,
            "tools.staticdir.dir": os.path.abspath("./"),
            "error_page.default": notfound,
        }
    }
    cherrypy.config.update(
        {
            
            "server.ssl_module": "builtin",
            "server.ssl_certificate": "cert.pem",
            "server.ssl_private_key": "privkey.pem",
            
            "tools.sessions.secure": "True",
            "tools.sessions.httponly": "True",
        }
    )
    cherrypy.quickstart(serve(), "/", conf)
```

Plus, two files were created, the [cert.perm](../../app_sec/cert.pem) and [privkey.pem](../../app_sec/privkey.pem)

## Examples

As we can see in this first case, the requests are clearly visible and very easily captured, and we can read the information transmitted inside
### Vulnerable

![Vulnerable](CWE-319-vulnerable.gif)

---
With the SSL/TLS one only with difficulty can differentiate the direction the packages are being trasmitted in, and it's impossible to know what is going inside 
### Safe

![Vulnerable](CWE-319-safe.gif)
