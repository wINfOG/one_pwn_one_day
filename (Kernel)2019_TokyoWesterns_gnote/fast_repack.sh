gcc -static -pthread -o3 ./test.c -o exp.out && cp ./exp.out ~/todo

rm ./rootfs.cpio.gz
rm ~/todo/rootfs.cpio.gz

(cd ~/todo && sudo -s find ./ -print0 | cpio --null -ov --format=newc | gzip -9 > rootfs.cpio.gz)
cp ~/todo/rootfs.cpio.gz ./

rm ~/todo/rootfs.cpio.gz
rm ./rootfs.cpio

gunzip ./rootfs.cpio.gz
rm ./rootfs.cpio.gz

echo "Done"