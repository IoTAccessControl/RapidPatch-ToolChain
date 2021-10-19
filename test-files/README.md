## 测试用例

**下载地址**

* https://cloud.tsinghua.edu.cn/f/a6d7ab8a9b624ecfbba3/
* 我图方便所以把整个build文件夹都拷贝了



3 * 4 * 6 = 72个组合，72个固件

* **4个系统版本**

  * v1.13.0

    * ```
      export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
      export ZEPHYR_SDK_INSTALL_DIR=/home/cbackyx/research/zephyr-version/zephyr-sdk/zephyr-sdk-0.9.3 # 这个是默认的安装路径
      export ZEPHYR_BASE=~/research/zephyr-version/zephyr_1130  # 这个是zephyr的根目录
      ```

    * 这个版本里ZEPHYR_SDK_INSTALL_DIR的配置好像根本就不管用，必须是默认路径，所以我覆盖安装了zephyr-sdk

    * ```
      cd $ZEPHYR_BASE/samples/hello_world
      mkdir build && cd build
      cmake -GNinja -DBOARD=arduino_101 ../..
      ninja
      ```

  * v1.14.1

    * zephyr-sdk-0.10.0

    * ```
      export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
      export ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk
      export ZEPHYR_BASE=~/research/zephyr-version/zephyr_1141/zephyr
      ```

    * ```
      mkdir build && cd build
      cmake -GNinja -DBOARD=nrf52840_pca10056 -DOVERLAY_CONFIG="overlay-ram-disk.conf" ../..
      cmake -GNinja -DBOARD=stm32f429i_disc1 -DOVERLAY_CONFIG="overlay-ram-disk.conf" ../..
      cmake -GNinja -DBOARD=disco_l475_iot1 ../..
      ninja
      ```

  * v2.2.1

    * ```
      export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
      export ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk
      export ZEPHYR_BASE=~/research/zephyr-version/zephyr_221/zephyr
      ```

  * v2.3.0

    * ```
      export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
      export ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk
      export ZEPHYR_BASE=~/research/zephyr-version/zephyr_230/zephyr
      ```

* **4个设备**

  * nrf52840_pca10056
  * stm32f429i_disc1
  * disco_l475_iot1
  * frdm_k64f

* **6个漏洞函数**

  * [subsys/usb/class/mass_storage.c](https://github.com/zephyrproject-rtos/zephyr/pull/23455/commits/bc1118d8a64e7fd84e70503f5c7c23337445d4d5#diff-afdfa938983e2f8a9d1bac5ab73b2ab3bb973765596e50d3ca32a31e64e64ac9)
    * CVE-2020-10021
    * inforTransfer()
      * 未修复：v1.13.0，v1.14.1
      * 已修复：v2.2.1
  * [subsys/net/lib/coap/coap.c](https://github.com/zephyrproject-rtos/zephyr/pull/24530/commits/e235a093b4dbe51b08be763789ecdfc29b74cda1#diff-d634274191b4482708f8fb94a2132e8b43310ca10e075a0dd3cc90a0edb21ed8)
    * CVE-2020-10063
    * parse_option()
      * 未修复：v1.13.0，v1.14.1
      * 已修复：v2.2.1
  * （舍弃）drivers/gpio/gpio_handlers.c
    * Z_SYSCALL_HANDLER
      * 1.13.0中修复了(应该是在新的commit中修复的)，1.14.1没有修复
      * 只是个宏
    * z_vrfy_gpio_enable_callback/z_vrfy_gpio_disable_callback/z_vrfy_gpio_get_pending_int
      * 2.2.1中宏换成了inline函数
  * [subsys/net/lib/mqtt/mqtt_decoder.c](https://github.com/zephyrproject-rtos/zephyr/pull/23821/commits/11b7a37d9a0b438270421b224221d91929843de4#diff-e775caa5bb0c6392dd0763e237d79daaf8c57aaaefcf6bc87de33a50e68412a3)
    * CVE-2020-10062
    * packet_length_decode()
      * 未修复：v1.14.1，v2.2.1
      * 已修复：v2.3.0
  * [subsys/net/lib/mqtt/mqtt_rx.c](https://github.com/zephyrproject-rtos/zephyr/pull/23821/commits/0b39cbf3c01d7feec9d0dd7cc7e0e374b6113542#diff-5b81bfd8fe1001477d4e2cdf13911bb9afc2b2e9102ef8d4f35c0097ba254eea)
    * CVE-2020-10070
    * mqtt_read_message_chunk()
      * 未修复：v1.14.1，v2.2.1
      * 已修复：v2.3.0
  * [subsys/net/lib/mqtt/mqtt_decoder.c](https://github.com/zephyrproject-rtos/zephyr/pull/23821/commits/989c4713ba429aa5105fe476b4d629718f3e6082#diff-e775caa5bb0c6392dd0763e237d79daaf8c57aaaefcf6bc87de33a50e68412a3)
    * CVE-2020-10071
      * 这个CVE和前面两个的firmware是一样的
    * publish_decode()
      * 未修复：v1.14.1，v2.2.1
      * 已修复：v2.3.0
  * [subsys/shell/shell_utils.c](https://github.com/zephyrproject-rtos/zephyr/pull/23646/commits/abba6d7774cdd73665e69f6aa45f42439729e414#diff-64594ae39e237a7c67ff26cc3b2ac2b7489dc99fee0e09e1542a16bd555e4642)
    * CVE-2020-10023
    * shell_spaces_trim()
      * 未修复：v1.14.1
      * 已修复：v2.2.1，v2.3.0
    * 这个函数修复仅仅是修改了一个变量，应该识别不出来，可以作为反例

## Tips

指定zephyr-sdk安装目录

```
cd <sdk download directory>
chmod +x zephyr-sdk-0.12.3-x86_64-linux-setup.run
./zephyr-sdk-0.12.3-x86_64-linux-setup.run -- -d ~/zephyr-sdk-0.12.3
```

