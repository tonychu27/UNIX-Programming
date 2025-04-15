colima start --arch x86_64
docker context use colima
docker run -it --platform linux/amd64 \
  --privileged \
  --name up_x86 \
  -v "$PWD":/workspace \
  -w /workspace/ \
  ubuntu