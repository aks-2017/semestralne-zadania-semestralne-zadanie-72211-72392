# An experimental feasibility study on applying SDN technology to disaster-resilient wide area networks
### **Autori:** Michal Škuta, Jaroslav Lišiak
### **Cvičenie:** Utorok 19:00
### **Cvičiaci:** Ing. Tomáš Boros

### Úvod
***
Článok opisuje výhody používania SDN sieti v prípade vyskytnutia sa nečakanej pohromy (búrky, tsunami). Znefunkčnenie dôležitého prvku v hlavnom uzle siete (backbone) dôsledkom nečakanej udalosti, by mohlo mať veľmi kritické následky. Autori preto experimentálne otestovali aplikovanie SDN technológie v backbone. Overovali správanie siete pri nečakaných výpadkoch dôležitých komponentov v backbone a následné presmerovanie toku dát. Ukázali efektivitu SDN technológie a rýchlosť reakcie pri nečakaných udalostiach v sieti. Overili reakčnú dobu medzi kontrolerom a prvkami siete. Overili taktiež end-to-end komunikáciu pri kritickom scenári s použitím SDN technológie a bez nej.

## Analýza
***
Práca je rozdelená na tri samostatné testovania. Prvé testovanie sa zaoberá reakčným časom, ktorý je potrebný na presmerovanie toku dát na switchi bez pomoci kontroléra. Na vytvorenie softvérového switchu je použitá aplikácia OpenvSwich, ktorá implementuje protokol OpenFlow. Protokol OpenFlow umožňuje použitie skupín(group). Vytvorená grupa je typu FastFailover. Použitá grupa slúži na zisťovanie stavu portu zariadenia. Vďaka nej vie switch okamžite reagovať na náhle zmeny v stave portu (on/off), bez pomoci kontroléra. V prípade ak je jeden z portov vypnutý, alebo stratí konektivitu (spadne linka), switch okamžite presmeruje tok dát na druhý nastavený port. V prvej časti práce autori počítajú čas od doručenia posledného paketu na linke, ktorá bola prerušená až po čas kedy bol prijatý prvý paket na druhej linke. Autori vykonali 50 takýchto testov a ich cieľom bolo dosiahnuť čas na obnovu siete menej ako 50 ms.

Druhá časť práce sa zaoberá výpočtom oneskorenia medzi kontrolérom a SDN zariadením v simulovanej backbone sieti. V prvom kroku na základe počtu zariadení v danej sieti a predom určenej rýchlosti toku dát medzi nimi vypočítali priemernú a najhoršiu dobu odozvy. V ich simulovanej sieti poupravili rýchlosť toku dát, tak aby ju prispôsobili, prostriedkom ktoré mal simulátor siete k dispozícií. V danej topológii menili počet kontrolérov a merali doby odozvy pri použití rôznych počtov kontrolérov a zároveň menili umiestnenie a pripojenia jednotlivých kontrolerov. S vyšším počtom kontrolérov v sieti klesala doba odozvy. Pri použití 4 a 5 kontrolerov nebol rozdiel v dobe odozvy až taký výrazný.

Posledná, tretia časť sa zaoberá tokom dát cez backbone sieť z pohľadu používateľa. Autori vytvorili simuláciu SINET siete v Japonsku, kde simulovali výpadky spojenia medzi datacentrami, ktoré nastali v roku 2013. Následne sledovali čas potrebný na konvergenciu siete a obnovenie toku dát v skonvergovanej sieti. Sledovali tok dát počas simulácie výpadkov a zisťovali aký vplyv by mal výpadok spojenia v simulovanej SDN sieti na koncového používateľa.

# Návrh
***
V našom návrhu plánujeme zrealizovať topológiu z poslednej časti článku. Autori sa snažili vytvoriť WAN sieť podobnú reálnej siete SINET3 v Japonsku. Autori článku taktiež špecifikujú podrobný priebeh simulácie a teda presný čas trvania simulácie a približné časy prerušení spojenia medzi uzlami siete. Túto simuláciu taktiež plánujeme zopakovať a budeme pozorovať správanie sa siete z pohľadu koncového užívateľa. Užívateľ je pripojený do tejto siete a snaží sa komunikovať so serverom umiestneným v tejto sieti. Nato aby mohli komunikovať je potrebné aby existovala cesta medzi serverom a klientom. V prípade prerušenia spojenia už táto cesta nemusí správne fungovať (byť kompletná) a je potrebné vypočítať novú cestu komunikácie medzi serverom a klientom. Takéto hľadanie novej cesty bude užívateľ vnímať ako spomalenie komunikácie so serverom (prípadne pozastavenie ak by sa cesta hľadala dlhší čas).

Autori článku prezentujú tieto informácie v grafe, kde na osi x je znázornený celý čas simulácie a na osi y je dosiahnutá rýchlosť na vybraných portoch (port klienta smerom k sieti a port uzla, cez ktorý bude viesť alternatívna cesta pri prerušení spojenia). Na obrázku 2 sú znázornené tieto grafy. Podobne ako autori článku vytvoríme grafy a overíme či získané výsledky nášho testovania sa budú zhodovať s výsledkami, ktoré sú prezentované v článku. Prípadne rozdiely medzi našim testovaním a výsledkami z článku sa budeme snažiť podrobne analyzovať a vyhodnotiť.

Analyzovaný článok sa nezameriava na aplikovanie SDN technológii do WAN siete, ale hodnotí či dokáže súčasná technológia dostatočne rýchlo reagovať na nečakané udalosti, ktoré by mali za následok stratu dát. 
Nato aby sme mohli zopakovať a overiť testovanie z daného článku však musíme aplikovať SDN technológie do wan sieti. Autori článku vytvorili modul pre SDN kontrolér POX, ktorý zabezpečuje linkovú a sieťovú vrstvu pre zariadenia a taktiež zabraňuje vzniku slučiek v sieti. V našom prípade si topológiu predstavíme v dvoch rôznych prípadov.

V prvom prípade sa sieťové uzly budú správať ako prepínače. Podobne ako pri prepínačoch tu budeme používať Spanning tree protocol na zamedzenie slučiek, ktoré by vznikali pri broadcastových rámcoch. Hneď tu sa ukazuje nevýhoda a to je blokovanie určitých spojení (na odstránenie slučiek) a tým zníženie priepustnosti siete. Ďalší problém je pomalá konvergencia siete a tým pádom dlhé výpadky pri zmene topológie. Problém pomalej konvergencie by sme chceli ďalej analyzovať a nájsť pomocou kontrolera riešenia na urýchlenie konvergencie. Serveri a klienti musia byt v rovnakej IP sieti a nepotrebujú smerovač na vzájomnú komunikáciu.

V druhom prípade sa sieťové uzly budú správať podobne ako smerovače. Každý uzol bude mať svoj unikátný identifikátor a zoznam sieti k nemu pripojených. Kontroler bude poznať kompletnu topológiu a pomocou dijkstru vypočita pre kazdy uzol cesty do všetkých ostatných uzlov. V prípade zmeny topológie sa na kontroleri len znova spusti výpočet všetkých ciest medzi uzlami. V tomto prípade je potrebné aby klient a server boli v rôznych IP sieťach, tento návrh používa len sieťovú vrstvu. 

V prípade oboch topologii je možné prerušenia spojenia hneď oznamovať kontroleru openflow správou typu portStatus. Na túto správu vie kontroler rýchlo reagovať a prepočítať nové cesty (alebo odblokovať zablkované cesty). Oba spôsoby implementácie SDN sieti v našej topológii porovnáme z hľadiska používateľa a porovnáme z údajmi od autorov článku.

![Obrázok](https://github.com/aks-2017/semestralne-zadania-semestralne-zadanie-xskuta-xlisiak/tree/master/img/image.png "Obrázok 1")

![Obrázok](https://github.com/aks-2017/semestralne-zadania-semestralne-zadanie-xskuta-xlisiak/tree/master/img/image2.png "Obrázok 2")

## Použité technológie
***
#### Mininet
Mininet slúži na vytváranie realistických virtuálnych sieti. Umožňuje simuláciu SDN sieti, všetkých komponentov tejto siete a ich prepojenia. Mininet podporuje protokol OpenFlow, ktorý taktiež použijeme pri vypracovaní tohto projektu.

### Open vSwitch
Open vSwitch je viacvrstvový virtuálny switch, licencovaný pod open source Apache 2.0 licenciou. V našom prípade použitý aj v aplikácii mininet.


### OpenFlow
Definuje komunikačný protokol v SDN sieťach, ktorý umožňuje SDN kontroleru priamo komunikovať s SDN zariadeniami.

### SDN kontrolér
SDN kontrolér je základným prvkom SDN sieti, získavá dáta z jednotlivých zariadení a na základe týchto dát vykonáva základnú riadiacu logiku nad týmito zariadeniami.

### Spanning Tree Protocol
STP je protokol, ktorý v linkovej vrstve modelu OSI slúži na riešenie problémov so slučkami. Používa BPDU správy na vymieňanie si informácii o prepínačoch a na dohodnutie sa na jednotnej kostre grafu. V súčasnosti sa nahradzuje rýchlejšími alternatívami (napr.RSTP).


### Dijkstra
Dijkstrov algoritmus je jedným zo základných algoritmov teórie grafov, jeho primárnym využitím je hľadanie najkratšej cesty v hranovo-ohodnotenom digrafe. Tento graf pozostáva z množiny vrcholov, orientovaných hrán a funkcie , ktorá zobrazuje množinu hrán do množiny reálnych čísel. Typovo ide o algoritmus najkratšej cesty z jedného vrcholu  do ostatných, najčastejšie však do jedného konkrétneho.