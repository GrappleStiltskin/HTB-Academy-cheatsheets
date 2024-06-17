## Deobfuscation Websites

[JS Console](https://jsconsole.com/)
[Prettier](https://prettier.io/playground/)
[Beautifier](https://beautifier.io/)
[JSNice](http://www.jsnice.org/)

## Basic Obfuscation

### Minifying JavaScript Code
[javascript-minifier](https://www.toptal.com/developers/javascript-minifier)

Copy the minified code to JSConsole, and run it, and we see that it runs as expected. Usually, minified JavaScript code is saved with the extension `.min.js`.

### Packing JavaScript code

#### Using [BeautifyTools](http://beautifytools.com/javascript-obfuscator.php) to obfuscate
![[Pasted image 20230502211644.png]]

```JavaScript
eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))
```

#### Copy this code into https://jsconsole.com, to verify that it still does its main function
![[Pasted image 20230502211755.png]]

## Advanced Obfuscation

### [Obfuscator](https://obfuscator.io)
![[Pasted image 20230502212008.png]]
Before we click `obfuscate`, we will change `String Array Encoding` to `Base64`

#### Now, we can paste our code and click obfuscate: 
![[Pasted image 20230502212046.png]]

We get the following code:
```JavaScript
var _0x1ec6=['Bg9N','sfrciePHDMfty3jPChqGrgvVyMz1C2nHDgLVBIbnB2r1Bgu='];(function(_0x13249d,_0x1ec6e5){var _0x14f83b=function(_0x3f720f){while(--_0x3f720f){_0x13249d['push'](_0x13249d['shift']());}};_0x14f83b(++_0x1ec6e5);}(_0x1ec6,0xb4));var _0x14f8=function(_0x13249d,_0x1ec6e5){_0x13249d=_0x13249d-0x0;var _0x14f83b=_0x1ec6[_0x13249d];if(_0x14f8['eOTqeL']===undefined){var _0x3f720f=function(_0x32fbfd){var _0x523045='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=',_0x4f8a49=String(_0x32fbfd)['replace'](/=+$/,'');var _0x1171d4='';for(var _0x44920a=0x0,_0x2a30c5,_0x443b2f,_0xcdf142=0x0;_0x443b2f=_0x4f8a49['charAt'](_0xcdf142++);~_0x443b2f&&(_0x2a30c5=_0x44920a%0x4?_0x2a30c5*0x40+_0x443b2f:_0x443b2f,_0x44920a++%0x4)?_0x1171d4+=String['fromCharCode'](0xff&_0x2a30c5>>(-0x2*_0x44920a&0x6)):0x0){_0x443b2f=_0x523045['indexOf'](_0x443b2f);}return _0x1171d4;};_0x14f8['oZlYBE']=function(_0x8f2071){var _0x49af5e=_0x3f720f(_0x8f2071);var _0x52e65f=[];for(var _0x1ed1cf=0x0,_0x79942e=_0x49af5e['length'];_0x1ed1cf<_0x79942e;_0x1ed1cf++){_0x52e65f+='%'+('00'+_0x49af5e['charCodeAt'](_0x1ed1cf)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x52e65f);},_0x14f8['qHtbNC']={},_0x14f8['eOTqeL']=!![];}var _0x20247c=_0x14f8['qHtbNC'][_0x13249d];return _0x20247c===undefined?(_0x14f83b=_0x14f8['oZlYBE'](_0x14f83b),_0x14f8['qHtbNC'][_0x13249d]=_0x14f83b):_0x14f83b=_0x20247c,_0x14f83b;};console[_0x14f8('0x0')](_0x14f8('0x1'));
```

### More Obfuscation

#### [JSF](http://www.jsfuck.com/)
#### [JJ Encode](https://utf-8.jp/public/jjencode.html)
#### [AA Encode](https://utf-8.jp/public/aaencode.html)

## Deobfuscation

### Beautify

Can be done with Browser Dev Tools
- Open the browser debugger with [ CTRL+SHIFT+Z ], and then click on our script secret.js
- Click on the `'{ }'` button at the bottom
![[Pasted image 20230502220752.png]]

#### Online Tools:
[Prettier](https://prettier.io/playground/)
[Beautifier](https://beautifier.io/)

### Deobfuscate

#### [JSNice](http://www.jsnice.org/)
Click the `Nicify JavaScript` button

*Tip: We should click on the options button next to the "Nicify JavaScript" button, and de-select "Infer types" to reduce cluttering the code with comments.*

*Tip: Ensure you do not leave any empty lines before the script, as it may affect the deobfuscation process and give inaccurate results.*

![[Pasted image 20230502221009.png]]
Another way of `unpacking` such code is to find the` return` value at the end and use `console.log` to print it instead of executing it.

## Code Analysis

#### Code to be examined:
```JavaScript
'use strict';
function generateSerial() {
  ...SNIP...
  var xhr = new XMLHttpRequest;
  var url = "/serial.php";
  xhr.open("POST", url, true);
  xhr.send(null);
};
```
File contains only one function, `generateSerial`

### HTTP Requests

#### Code Variables
```JavaScript
var xhr = new XMLHttpRequest;
```
The variable `xhr` creates an object of `XMLHttpRequest`. Google shows that this is a JS function that handles web requests

```JavaScript
var url = "/serial.php";
```
URL variable defines a URL `/serial.php`, which should be on the same domain, as no domain was specified.

#### Code Functions
```JavaScript
xhr.open("POST", url, true);
```
`xhr.open` is used with `"POST"` and `URL`. Google shows that it opens the HTTP request defined '`GET` or `POST`' to the `URL`, and then the next line` xhr.send` would send the request.

```JavaScript
xhr.send(null);
```
Sends the request from the `xhr.open` function

All `generateSerial` is doing is simply sending a `POST` request to `/serial.php`, without including any `POST` data or retrieving anything in return.

#### POST Request w/ cURL
```Shell
curl -s http://SERVER_IP:PORT/ -X POST
```
Tip: We add the "-s" flag to reduce cluttering the response with unnecessary data

#### Sending data with cURL using a POST Request
```Shell
curl -s http://SERVER_IP:PORT/ -X POST -d "param1=sample"
```
To send data, we can use the "`-d "param1=sample"`" flag and include our data for each parameter

## Decoding

### Base64

#### Base64 Encode
```Shell
echo https://www.hackthebox.eu/ | base64
```

#### Base64 Decode
```Shell
echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d
```

### Hex

#### Find the full ASCII table in Linux
```Shell
man ascii
```

#### Spotting Hex

Any string encoded in `hex` would be comprised of hex characters only, which are 16 characters only: 0-9 and a-f. 

#### Hex Encode
```Shell
echo https://www.hackthebox.eu/ | xxd -p
```

#### Hex Decode
```Shell
echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r
```

### Caesar/Rot13

#### Rot13 Encode
```Shell
echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
There isn't a specific command in Linux to do rot13 encoding. However, it is fairly easy to create our own command to do the character shifting

#### Rot13 Decode
```Shell
echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

