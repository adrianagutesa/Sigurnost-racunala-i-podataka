# Laboratorijske vježbe 1

# Man-in-the-middle attacks (ARP spoofing)

Zadatak vježbe je realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola. Koristili smo virtualnu Docker mrežu koju čine 3 virtualizirana Docker računala: dvije žrtve station-1 i station-2 te napadač evil-station.

Spojili smo se u terminal station-1 uređaja i provjerili njegovu IP i MAC adresu koristeći naredbu *ipconfig*. Da bi saznali nalazili se station-2 na istoj mreži, koristili smo naredbu *ping.* Uspostavili smo vezu između station-1 i station-2 naredbom *netcat.* 

Kako bi presreli promet između ova dva računala, potrebno je narušiti integritet na način da se evil-station predstavi stationu-1 kao station-2 koristeći njegovu MAC adresu, ali ne i njegovu IP adresu.

Na taj način je station-1 slao promet evil-stationu ,a on ga je dalje prosljeđivao stationu-2. 

Kako bi vidjeli promet koji se razmjenjuje, koristili smo naredbu *arpspoof* i tako narušili povjerljivost podataka. Ukoliko evil-station ne bi prosljeđivao promet stationu-2, bila bi narušena i dostupnost podataka.

Promet koji je station-2 slao stationu-1 prolazio je bez presretanja evil-stationa.