IFS=" " read -r a b c d  <<< $(echo  "obase=256 ; $1" |bc)
echo ${a#0}.${b#0}.${c#0}.${d#0}
