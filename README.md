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

