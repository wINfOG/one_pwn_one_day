gcc -static -o3 ./test.c -o exp.out && cp ./exp.out ~/todo

rm ./initramfs.cpio.gz
rm ~/todo/initramfs.cpio.gz

(cd ~/todo && sudo -s find ./ -print0 | cpio --null -ov --format=newc | gzip -9 > initramfs.cpio.gz)
cp ~/todo/initramfs.cpio.gz ./

rm ~/todo/initramfs.cpio.gz
rm ./initramfs.cpio

gunzip ./initramfs.cpio.gz
rm ./initramfs.cpio.gz

echo "Done"