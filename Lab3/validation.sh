# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
rm -f /tmp/_pub.pem /tmp/_msg.bin /tmp/_sig.bin
cat > /tmp/_pub.pem<<EOF
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAILamhh4aXszHBI25FFaRDEi2SBohmL2wkXKSHMlX38g=
-----END PUBLIC KEY-----
EOF
echo -n 'FLAG{g0t_sud0ku_so1ved_2o25!}|Fri Apr  4 15:22:34 2025|' > /tmp/_msg.bin
echo 'vxqSFKMvi9cGuERpv9hOAvnioxmTNa8GV2usybMg575IwYAHwZjr1Iu4sewMo62wdO0SXh0L8IJBumOm98LBCQ==' | base64 -d > /tmp/_sig.bin
openssl pkeyutl -verify -pubin -inkey /tmp/_pub.pem -rawin -in /tmp/_msg.bin -sigfile /tmp/_sig.bin