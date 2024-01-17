## The eTPSS implemented using OPenssl and C

一共实现五种操作：`Share Recovery Add ScalP Mul`

### 一.文件定义

头文件定义在./include内，./test使用cuTest准备写单元测试类，未完成

**eTPSS.c**是头文件的实现

**eTPSS_test.c**是测试类

### 二.使用说明

确保计算机安装了`openssl`以及CMake构建工具

```shell
# 安装openssl
apt update
apt install libssl-dev -y
# 安装CMake
apt install cmake
```

> CMake需要版本设置了最低需求 3.25

使用流程：

~~~shell
# 进入程序主目录
cd xx
mkdir build
cd build
cmake ..
make
~~~

<img src="https://typora-oldoldcoder.oss-cn-hangzhou.aliyuncs.com/img/image-20240117172413252.png" alt="image-20240117172413252" style="zoom:67%;" />

运行结果图如下所示：

![image-20240117171606338](https://typora-oldoldcoder.oss-cn-hangzhou.aliyuncs.com/img/image-20240117171606338.png)