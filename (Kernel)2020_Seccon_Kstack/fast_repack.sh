gcc -static -pthread -o3 ./test_leak.c -o leak_exp.out && cp ./leak_exp.out ~/todo
gcc -static -pthread -o3 ./test_rop.c -o rop_exp.out && cp ./rop_exp.out ~/todo
rm ./rootfs.cpio.gz
rm ~/todo/rootfs.cpio.gz

(cd ~/todo && sudo -s find ./ -print0 | cpio --null -ov --format=newc | gzip -9 > rootfs.cpio.gz)
cp ~/todo/rootfs.cpio.gz ./

rm ~/todo/rootfs.cpio.gz
rm ./rootfs.cpio

gunzip ./rootfs.cpio.gz
rm ./rootfs.cpio.gz

echo "Done"