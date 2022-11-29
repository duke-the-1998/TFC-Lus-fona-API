#!bin/bash
curl -s https://crt.sh/?q=%25.$1 > curl.out
cat curl.out | grep $1 | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | sort -u > $1-subdomains.txt
rm curl.out