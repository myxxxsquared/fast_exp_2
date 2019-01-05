# FAST 二层交换机

从 fast-0.3.0 修改得到

 * 解决输入输出端口一致时的泛洪问题
 * 改用C++
 * 修改了存储数据结构，改为二叉树
 * 加入了环路检测
 * 加入了硬件直接转发

## 生成

### 生成所需环境

 * arm-linux-gnueabi-gcc
 * arm-linux-gnueabi-g++
 * autoreconf

### 生成步骤

```sh
autoreconf --install --force
./configure --host=arm-linux-gnueabi
make
```
