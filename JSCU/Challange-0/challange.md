Voor de eerste challange opende ik de .ova file in VirtualBox. 
Dit maakte een Ubuntu VM aan wat vervolgens om een wachtwoord vroeg. 

Eerst probeerde ik de boot device te veranderen om te kijken of dat me iets zou bieden. 
Hierna zocht ik op hoe ik een wachtwoord kon aanpassen op een Ubuntu systeem, dit bleek shift vasthouden tijdens boot te zijn om vervolgens recovery mode in te gaan. 

Toen ik in de machine kon (met write restrictions) kon ik vlag.txt zien in mijn directory wat de volgende vlag bleek te hebben: `SUMMERSCHOOL{D3_0LYMP1SCH3VL4M_1S_0NTST0K3N}`. Deze flag komt overeen met SHA1 `71c9c11b8dbfcc895aacd37b7c7a538fea2b908e` wat een van de mogelijke vlaggen is.

Hierna opende ik de home directory en zag README.txt en weer een vlag.txt. 
In vlag.txt stond dit keer `SUMMERSCHOOL{D3_F4KK3L_1S_1N_0LYMPUS}`. Deze flag komt overeen met SHA `b11a7300a2b7ca8aef1ce7ac014262a02c5afce3` wat ook een van de mogelijke flags is. 

De eerste flag kon ik maar niet vinden in de files die gegeven waren. Eerst begon ik met het zoeken naar vergelijkbare files (net zoals vlag.txt) door middel van `sudo find / -name "vlag.txt"`. Hiermee kreeg ik helaas alleen maar mijn al gevonden flags te zien. 
Ik wilde toen eigenlijk gewoon alle files scannen voor de `SUMMERSCHOOL` prefix van de ctf. Online zocht ik hier een command voor op en kwam uit op `sudo grep -r "SUMMERSCHOOL`, hiermee zag ik gelijk mijn laatste flag `SUMMERSCHOOL{VL4G_P0RT44L_L0G1N}` en dit kwam overeen met de laatste SHA1. 

Ik realiseer wel dat dit waarschijnlijk niet de gebruikelijke manier was. 
Ik keek naar de .html pagina van de laatste flag en zag dat er in deze directory een script werd gerund. In dit sript wordt de data uit users.db gebruikt om de username en password the checken. De username is is fakkel en door de hash door een MD5 decrypter te halen krijg ik de password: theolympicdream1. 

