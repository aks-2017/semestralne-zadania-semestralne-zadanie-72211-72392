# An experimental feasibility study on applying SDN technology to disaster-resilient wide area networks

## Štruktúra repozitára
Kde sa čo nachádza

## Dokument
Odkaz na dokument?

## Naša implementácia
Vytvorili sme 2 prototypy odlišujúce sa spôsobom smerovania dát v topológii.
Prvý prototyp smeruje len na základe mac adries:

    mininet-scripts/runner_auto.py alebo mininet-scripts/runner.py

    ryu/simple_switch_nx.py
Druhý prototyp smeruje aj na základe IP adries:

    mininet-scripts/runner3_auto.py alebo mininet-scripts/runner3.py

    ryu/simple_switch_nx3.py

**Požiadavky softvéru:**

 - ryu-manager
 - mininet
 - knižnica networkx (sudo pip install networkx)
 - knižnica ipaddress (sudo pip install ipaddress)

**Inštalácia softvéru:**

    git clone https://github.com/aks-2017/semestralne-zadania-semestralne-zadanie-xskuta-xlisiak.git
    cd semestralne-zadania-semestralne-zadanie-xskuta-xlisiak/deploy-scripts
	chmod +x ./check_ubuntu_dependecies.sh
    sudo ./check_ubuntu_dependecies.sh



**Spustenie softvéru:**

 - automatické na otestovanie scenára:

    sudo python mininet-scripts/runner3_auto.py alebo mininet-scripts/runner_auto.py

 - manuálne testovanie:

    sudo python mininet-scripts/runner3.py alebo mininet-scripts/runner.py
	
    ryu-manager --observe-links ryu/simple_switch_nx3.py alebo
    ryu-manager --observe-links ryu/simple_switch_nx.py
