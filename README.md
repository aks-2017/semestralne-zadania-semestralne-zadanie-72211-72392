# An experimental feasibility study on applying SDN technology to disaster-resilient wide area networks

## Štruktúra repozitára
```
deploy-scripts\		- priečinok obsahujúci script, ktorý nainštaluje potrebné programy
docs\			- dokumentácie
img\			- obrázky použité v dokumentácii a Readme.md súbore
mininet-scripts\	- súbory potrebné pre zostavenie požadovanej topológie a spustenie simulácie
ryu\			- kontrolér použitý pri simulácii
```

## Dokument
Finálny článok nájdete [tu](../master/docs/Skuta_Lisiak.pdf)

## Naša implementácia
Vytvorili sme 2 prototypy odlišujúce sa spôsobom smerovania dát v topológii.

#### *Prvý prototyp smeruje len na základe MAC adries:*

*Mininet:*
  * mininet-scripts/runner_auto.py 
  * mininet-scripts/runner.py

*Kontrolér:*
  * ryu/simple_switch_nx.py


#### *Druhý prototyp smeruje aj na základe IP adries:*

*Mininet:*
  * mininet-scripts/runner3_auto.py
  * mininet-scripts/runner3.py


*Kontrolér:*
  * ryu/simple_switch_nx3.py

## Požiadavky softvéru:

 - ryu-manager
 - mininet
 - knižnica networkx (sudo pip install networkx)
 - knižnica ipaddress (sudo pip install ipaddress)

#### *Inštalácia softvéru:*
```bash
git clone https://github.com/aks-2017/semestralne-zadania-semestralne-zadanie-xskuta-xlisiak.git
cd semestralne-zadania-semestralne-zadanie-xskuta-xlisiak/deploy-scripts
chmod +x ./check_ubuntu_dependecies.sh
sudo ./check_ubuntu_dependecies.sh
```



## Spustenie softvéru

#### *Automatické na otestovanie scenára:*
```bash
sudo python mininet-scripts/runner3_auto.py
sudo python mininet-scripts/runner_auto.py
```
#### *Manuálne testovanie:*
 
 *Layer2*

```bash
sudo python mininet-scripts/runner.py
ryu-manager --observe-links ryu/simple_switch_nx.py
```

*Layer3*
```bash
sudo python mininet-scripts/runner3.py
ryu-manager --observe-links ryu/simple_switch_nx3.py
```


