gcc -static -o3 ./test.c -o exp.out
mkdir -p ~/todo
sudo mount ./rootfs.ext2 ~/todo
sudo cp ./exp.out ~/todo/exp
sudo umount ~/todo
echo "Done"