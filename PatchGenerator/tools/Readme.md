#### 如何测试
在Linux下单独测试eBPF库。

1. 生成cmake的Makefile项目。
2. 由于汇编用到的

```
python2 -m install requirements.txt
python2 -m nose test_vm.py

# 调试
python2 test_vm.py
```


在windows下的不完整的测试，由于python assemble和dessemble所依赖的库需要在linux下，所以
需要跳过这一类测试。只是进行load bin mem的测试。

``` 
# python3
pip install nose
nosetests
```