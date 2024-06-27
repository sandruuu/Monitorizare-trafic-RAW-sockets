# Monitorizare-trafic-RAW-sockets

# 6/18/2024
Creare RAW socket si capturare pachete.
Monitorizarea traficului in retea folosind RAW sockets ofera acces asupra datelor de retea primite si transmise, care in mod obisnuit sunt ascunse de modul de incapsulare al datelor.
STRUCTURA: socket(domain,SOCK_RAW,protocol)
Acest tip de socket este utilizat la layer 2 tcp/ip(AF_PACKET) si layer 3 tcp/ip(AF_INET) prin specificarea domeniului de comunicatie. 
Se pot captura toate tipurile de pachete care trec prin interfata de retea(htons(ETH_P_ALL)) sau doar anumite pachete prin specificarea protocolului.
NETWORK PACKET: Ethernet header, IP header, Transport header, Data

sites: https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
       https://www.baeldung.com/cs/raw-sockets

# 6/19/2024
Afisare informatii.
Filtrarea pachetelor in functie de protocol.

sites: https://gist.github.com/miraigajettolab/a0f8d3ae1014663ef7769bd74cc9a036

# 6/20/2024
Prelucrarea corespunzatoare a pachetelor.

sites: https://stackoverflow.com/questions/30780082/sock-raw-option-in-socket-system-call

# 6/25/2024
Afisarea informatiilor in fisierul out.txt.
Filtrarea informatiilor stocate in fisier prin intermediul scriptului filter.sh.

Optiuni de filtrare: 
-afisarea adreselor MAC(sursa si destinatie) si a producatorului.

# 6/26/2024
Adaugare optiuni filtrare:
-conversia adreselor IP intr-un nume de domeniu(DNS Lookup) si afisarea continutului fisierului modificat
-afisarea adreselor IP si a numelui de domeniu
-afisarea pachetelor in functie de protocol(TCP/UDP/ICMP/ARP)
