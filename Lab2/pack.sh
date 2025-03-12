# if [ -z "$1" ]; then
#   echo "Error: Missing argument. Please provide the module name as the first argument."
#   exit 1
# fi

# rm -rf rootfs/*
# mkdir -p rootfs
# bzip2 -dc ./dist/rootfs.cpio.bz2 | (cd rootfs && cpio -idmu) 
# mkdir -p rootfs/modules
# cp "$1"mod/"$1" "$1"mod/"$1"mod.ko rootfs/modules
cd ./rootfs && find . | cpio -o -H newc | bzip2 > ../dist/rootfs.cpio.bz2