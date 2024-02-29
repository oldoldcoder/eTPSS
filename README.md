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

## 版本修改历史
|     版本     |                修改内容                 | 修改人 |
|:----------:|:-----------------------------------:|:---:|
|    v0.1    | 创建项目ETPSS，实现初版对于正数的支持，完成算法文件规定的五种算法 | 何琪  |
|    v0.2    |    实现对于负值的支持，-5 mod 3 = 1-2这种修改     | 何琪  |
|    v0.3    |       实现ETPSS判断符号，已经et_Sub的算法       | 何琪  |
|    v0.4    |  修改算法，尝试完成对于负值的支持,-99 mod 100 = 1   | 何琪  |
| v0.5-final |          完全修改,不对负值和正值进行区分           | 何琪  |
|            |                                     |     |