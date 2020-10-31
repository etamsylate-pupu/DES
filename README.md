#### description

Windows 10环境；C语言实现ECB、CBC、CFB、OFB四种工作模式的DES加解密；其中module_test.c文件生成 5MB 的随机测试数据，连续加密、解密 20 次，输出每种模式的加密和解密的总时间（毫秒）和速度（MByte/ 秒）

des_plain.txt：明文文件，16字节，128bit。16进制表示为4E6574776F726B205365637572697479

des_key.txt：密钥文件，8字节，64bit。16进制表示为：57696C6C69616D53

des_iv.txt：向量文件。16进制表示为：5072656E74696365

des_Cipher.txt：密文文件，16字节，128bit。用来保存密文

​		ECB模式：958920B1358EF1972B9EE4548DC08E8A

​		CBC模式：5EB15B91506B9AE7CEB65954AE115E03

​		CFB模式：F70F01584ACF4D966ADC143EB240C962

​		OFB模式：F7B0FFCDC0B9BBA76092B929D769417A

#### step

1. 运行.c文件，生成.exe文件；

2. 打开cmd，进入.exe文件所在目录；

3. 命令行指定明文文件、密钥文件、初始化向量文件的位置和名称、加密的操作模式以及加密完成后密文文件的位置和名称

   命令行具体格式为：e1des -p plainfile -k keyfile [-v vifile] -m mode -c cipherfile 

   参数： 

   ​		-p plainfile 指定明文文件的位置和名称

   ​		-k keyfile 指定密钥文件的位置和名称 

   ​		-v vifile 指定初始化向量文件的位置和名称

   ​		-m mode 指定加密的操作模式

   ​		-c cipherfile 指定密文文件的位置和名称 

   eg：DES_work.exe -p des_plain.txt -k des_key.txt -v des_iv.txt -m ECB -c des_Cipher.txt

#### result

​	CFB和OFB分组为8位，ECB和CBC分组为64位，后者与前者相比连续20次加解密总时间倍数大致为8

 

 