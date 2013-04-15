make clean && make
sudo cp libpe.so /usr/lib/libpe.so
sudo cp libpe.so /usr/lib/libpe.so.1
gcc -o petest petest.c -lpe
make clean
./petest ~/winapp/putty.exe
