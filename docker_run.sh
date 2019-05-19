docker run --env USER=root --privileged -it  --device=/dev/net/tun -v /home/zyw/experiment/FirmAFL:/home/zyw/experiment/FirmAFL ubuntu:16.04 /bin/bash
docker run --cap-add NET_ADMIN --cap-add NET_RAW --device=/dev/net/tun -d -p 1193:1193/udp --env USER=root -it  -v /home/zyw/experiment/FirmAFL:/home/zyw/experiment/FirmAFL ubuntu:16.04 /bin/bash
#apt-get install uml-utilities
#apt-get install net-tools
#apt-get install sudo
#apt-get install iputils-ping
#apt-get install iproute2
#apt-get install telnet
#apt-get install python
#apt-get install qemu
#docker run -it  --env USER=root --privileged -it  --device=/dev/net/tun -v /home/zyw/experiment/:/home/zyw/experiment/ f79afbed9a38 /bin/bash
#docker exec  -it f79afbed9a38 bash
#docker ps

docker run -it --cpuset-cpus=1 --env USER=root --privileged -it  --device=/dev/net/tun -v /home/zyw/experiment/FirmAFL/firmadyne/outputs:/home/zyw/image/outputs -v /home/zyw/experiment/:/home/zyw/experiment/ b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun -v /home/zyw/experiment/FirmAFL/firmadyne/outputs:/home/zyw/image/outputs -v /home/zyw/experiment/:/home/zyw/experiment/ b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/zyw/experiment/:/home/zyw/experiment/ b25c40366c54 /bin/bash

docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/work5/image_10853:/home/zyw/image_10853 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/image_105609:/home/zyw/image_105609 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/work4/image_161160:/home/zyw/image_161160 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/devn/et/tun  -v /home/iotse/zyw-work/FirmAFL/work9/image_9054:/home/zyw/image_9054 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/work9/image_9050:/home/zyw/image_9050 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/work4/image_9925:/home/zyw/image_9925 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/work9/image_10566:/home/zyw/image_10566 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/work1/image_105600:/home/zyw/image_105600 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/work4/image_129780:/home/zyw/image_129780 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/iotse/zyw-work/FirmAFL/work2/image_129781:/home/zyw/image_129781 b25c40366c54 /bin/bash


docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/zyw/experiment/FirmAFL/work4/image_10853:/home/zyw/image_10853 b25c40366c54 /bin/bashd
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/zyw/experiment/FirmAFL/work3/image_129780:/home/zyw/image_129780 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/zyw/experiment/FirmAFL/work1/image_129781:/home/zyw/image_129781 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/zyw/experiment/FirmAFL/work2/image_9925:/home/zyw/image_9925 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/zyw/experiment/FirmAFL/work1/image_10853:/home/zyw/image_10853 b25c40366c54 /bin/bash


docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/wsn/zyw/work_new_3/image_9050:/home/zyw/image_9050 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/wsn/zyw/work_new_4/image_129780:/home/zyw/image_129780 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/wsn/zyw/work_new_6/image_129781:/home/zyw/image_129781 b25c40366c54 /bin/bash
docker run -it --env USER=root --privileged -it  --device=/dev/net/tun  -v /home/wsn/zyw/work_new_1/image_161160:/home/zyw/image_161160 b25c40366c54 /bin/bash
