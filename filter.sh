#!/bin/bash 

if [[ $# -ne 1 ]]
then
    echo "Utilizare: $0 <nume_fisier>"
    exit 1
fi

OUI_FILE="oui.txt"
if [[ ! -f "$OUI_FILE" ]]
then
    wget http://standards-oui.ieee.org/oui.txt -O "$OUI_FILE"
fi

producator(){
    local mac_prefix=$(echo "$1" | cut -d':' -f1-3 | tr '[:lower:]' '[:upper:]')
    mac_prefix=$(echo "$mac_prefix" | sed 's/:/-/g')  

    local prod=$(grep -i "^$mac_prefix" "$OUI_FILE" | awk -F'\t' '{print $3}')
    
    if [[ -n "$prod" ]]
    then
        echo "$prod"
    else
        echo "Unknown"
    fi
}

mac_producator(){
    local -A mac_array

    if [[ ! -f "$1" ]]
    then
        echo "Fisierul nu exista."
        exit 0
    fi

    while read -r line
    do
        for mac in $(echo "$line" | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
        do
            if [[ -z "${mac_array[$mac]}" ]]
            then
                mac_array[$mac]=1
                prod=$(producator "$mac")
                echo "$mac - $prod"
            fi
        done
    done < "$1"
}

PS3="Alege o optiune din meniu: " 
select ITEM in "Afiseaza adresa MAC si producatorul." "Afiseaza..." "Exit" 
do 
    case $REPLY in 
        1) mac_producator "$1" ;; 
        
        
        2)  ;;
        
        
        3) exit 0 ;;   
        
        *) echo "Optiune incorecta." 
    esac
done