#!/bin/bash 

if [[ $# -ne 1 ]]
then
    exit 1
fi

if [[ ! -f "$1" ]]
then
    exit 1
fi

OUI_FILE="oui.txt"
if [[ ! -f "$OUI_FILE" ]]
then
    wget http://standards-oui.ieee.org/oui.txt -O "$OUI_FILE"
fi

get_vendor(){
    local oui=$(echo "$1" | cut -d':' -f1-3 | tr '[:lower:]' '[:upper:]')
    oui=$(echo "$oui" | sed 's/:/-/g')  

    local vendor=$(grep -i "^$oui" "$OUI_FILE" | awk -F'\t' '{print $3}')
    
    if [[ -n "$vendor" ]]
    then
        echo "$vendor"
    else
        echo "Unknown"
    fi
}

print_mac_vendor(){
    local -A mac_array

    while read -r line
    do
        for mac in $(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
        do
            if [[ -z "${mac_array[$mac]}" ]]
            then
                mac_array[$mac]=1
                local vendor=$(get_vendor "$mac")
                echo "$mac - $vendor"
            fi
        done
    done < "$1"
}

get_domain(){
    local ip=$1
    local domain_to_check=$(host "$ip" | head -n 1)
    if echo "$domain_to_check" | grep -q "not found"
    then
        echo $ip
    else
        echo $(echo $domain_to_check | awk '{print $5}' | sed 's/\.$//')
    fi
}

print_ip_to_domain(){
    while IFS= read -r line
    do
        
        local ip1=$(echo "$line" | awk '{print $4}')
        local ip2=$(echo "$line" | awk '{print $8}')
        local domain1=$(get_domain "$ip1")
        local domain2=$(get_domain "$ip2")

        local modified_line=$(echo "$line" | sed "s/$ip1/$domain1/g")
        modified_line=$(echo "$modified_line" | sed "s/$ip2/$domain2/g")

        echo "$modified_line"
    
    done < "$1"
}

print_ip_domain(){
    local -A ip_array

    while read -r line
    do
        local ip1=$(echo "$line" | awk '{print $4}')
        local ip2=$(echo "$line" | awk '{print $8}')
        
        if [[ -z "${ip_array[$ip1]}" ]]
        then
            ip_array[$ip1]=1
            domain=$(get_domain "$ip1")
            echo "$ip1 $domain"
        fi

        if [[ -z "${ip_array[$ip2]}" ]]
        then
            ip_array[$ip2]=1
            domain=$(get_domain "$ip2")
            echo "$ip2 $domain"
        fi
    done < "$1"
}

protocol_filter(){
    read -p "Enter the protocol name(TCP/UDP/ICMP/ARP): " protocol
    while read -r line
    do
        local line_to_check=$(echo $line | grep "$protocol")
        if [[ ! -z "$line_to_check" ]]
        then
            echo "$line"
        fi
    done < "$1"
}

ip_filter(){
    read -p "Enter source or dest ip: " place
    read -p "Enter ip: " ip
    while read -r line
    do
        if [[ "$place" == "source" ]]
        then
            echo "$line" | grep -q "$ip .*>"
            if [[ $? -eq 0 ]]
            then
                echo "$line"
            fi
        elif [[ "$place" == "dest" ]]
        then
            echo "$line" | grep -q ">.* $ip"
            if [[ $? -eq 0 ]]
            then
                echo "$line"
            fi
        fi
    done < "$1"
}

PS3="Choose a filtering option: " 
select ITEM in "Display MAC address and vendor." "Convert IP addresses to domain names and display the modified file." "Display IP addresses and domain names." "Display packets by protocol." "Display packets by source/destination IP." "Exit." 
do 
    case $REPLY in 
        1) print_mac_vendor "$1" ;; 
        
        2) print_ip_to_domain "$1" ;;
        
        3) print_ip_domain "$1" ;;

        4) protocol_filter "$1" ;;

        5) ip_filter "$1";;

        6) exit 0 ;;   
        
        *) echo "Incorrect option." 
    esac
done