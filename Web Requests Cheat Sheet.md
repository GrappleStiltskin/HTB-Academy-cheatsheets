## cURL
```Shell
curl inlanefreight.com 	
```
Basic GET request

```Shell
curl -s -O inlanefreight.com/index.html
```
Download file

```Shell
curl -k https://inlanefreight.com
```
Skip HTTPS (SSL) certificate validation

```Shell
curl inlanefreight.com -v
```
Print full HTTP request/response details

```Shell
curl -I https://www.inlanefreight.com
```
Send HEAD request (only prints response headers)

```Shell
curl -i https://www.inlanefreight.com
```
Print response headers and response body

```Shell
curl https://www.inlanefreight.com -A 'Mozilla/5.0'
```
Set User-Agent header

```Shell
curl -u admin:admin http://<SERVER_IP>:<PORT>/
```
Set HTTP basic authorization credentials

```Shell
curl http://admin:admin@<SERVER_IP>:<PORT>/
```
Pass HTTP basic authorization credentials in the URL

```Shell
curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/
```
Set request header

```Shell
curl 'http://<SERVER_IP>:<PORT>/search.php?search=le'
```
Pass GET parameters

```Shell
curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/
```
Send POST request with POST data

```Shell
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```
Send POST request with identified value

```Shell
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```
Set request cookies

```Shell
curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php
```
Send POST request with JSON data

## APIs

 ```Shell
curl http://<SERVER_IP>:<PORT>/api.php/city/london
```
Read entry
 
```Shell
curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq
```
Read all entries
 
```Shell
curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```
Create (add) entry
 
```Shell
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```
Update (modify) entry
 
```Shell
curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City
```
Delete entry

[CTRL+SHIFT+I] or [F12] 	
Show devtools
 
[CTRL+SHIFT+E] 
Show Network tab
 
[CTRL+SHIFT+K] 	
Show Console tab