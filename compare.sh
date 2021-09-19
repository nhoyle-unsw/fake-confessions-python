hashReal=$(openssl SHA256 < confession_real.txt)
hashRealEnd="88d"
counter=0;
while true
do
	#echo comparing real and fake
	hashFake=$(openssl SHA256 < confession_fake.txt)
	#hashReal=$(openssl SHA256 < confession_real.txt)
	if [[ $hashFake == *588d ]]; then
		echo "They are equal"
		echo "Real: $hashReal"
		echo "Fake: $hashFake"
		exit 0;

	else
		((counter+=1))
		echo $counter $hashFake
	#	echo $hashReal
	fi
	echo " " >> confession_fake.txt
	#sleep 1
done

