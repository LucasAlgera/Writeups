# Infostealer/phising - rabo-inloggen.com

**Domain:** rabo-inloggen.com  
**IP:** 199.91.220.65  
**Server type:** nginx/1.18.0 (Ubuntu)  
**ASN:** AS399629  
**Registered On:** 2026-06-03  
**Registrar:** OwnRegistrar, Inc.  
**SMS received at:** 6/5/2026 20:54  
**SMS sent by:** +31 6 43 90 98 11

| file/site |MD5 | SHA-256 | filesize
|---|---|---|---|
card-details.html	|73f9db7f9a8379f5cdab53e48f12d8b3	|3e88c2fba8ce9cc26c4b3c47206790d60e13e1e4b7ab56304d38dcd007d7ddcc|	9.445	|
success.html	|2e80fcf94e6a6d079bf40a34e67f26d3	|084f87e2cf923a2cbf666b542807c1bbf0a35ab89b643c7aeb9a868fbcd513d6	|6.765	|

## Phishing attempt

![phishing message](image-6.png)

This link goes to:  [rabo-inloggen.com/r/direct](rabo-inloggen.com/r/direct)

## The webpage
https://rabo-inloggen.com/r/direct redirects the victim to https://rabo-inloggen.com/r/direct/step/card-details. 

![enter credentials page](image.png)

This website functions as a phishing kit for harvesting payment card information. It uses Socket.io to have a stream-like connection between the server and the user. Socket.io communicates with the server over the https port: `199.91.220.65:443`.   
This is what me typing `PHISHING` into the `cardName` field probably looks like this to the server:  
![informing server](image-3.png)  
Like this the user does not even need to hit send, the server watches every key typed.  
Next to this the server keeps a heartbeat every 10 seconds with the user, making sure the connection is still valid.  

After hitting 'send' the user is prompted with the following pages before being redirected to https://www.rabobank.nl/particulieren to make the entire process seem legit. 

![loading...](image-4.png)

![verification ](image-5.png)

## Server hosting
Looking at additional IP information at https://www.abuseipdb.com/check/199.91.220.65, we can see that the website is hosted using blnwx.com. 
> blnwx.com belongs to BL Networks (also known as BitLaunch), an autonomous system and web hosting provider. Operating primarily as a Virtual Private Server (VPS) reseller and hosting network, the platform allows users to provision servers anonymously. 

The best I can do at this point is the following:   
![report phishing to blnwx](image-2.png)


## Timeline

2026-06-03 - *Domain registered*  
2026-06-05 20:54 - *Phishing SMS received*  
2026-06-05 - *Site analyzed*  
2026-06-05 - *Abuse report submitted to hosting provider*