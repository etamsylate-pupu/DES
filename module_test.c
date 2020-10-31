#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include<time.h>
//#include <stdbool.h>
typedef enum
{
    false = 0,
    true  = 1
} bool;
const char* DES_MODE[] = { "ECB","CBC","CFB","OFB" };

char* plainfile = NULL;
char* keyfile = NULL;
char* vifile = NULL;
char* mode = NULL;
char* cipherfile = NULL;

char* plaintext = NULL;
char* keytext = NULL;
char* vitext = NULL;
char* ciphertext = NULL;
static bool Subkeys[16][48]={0}; //存储子密钥
const int LS_Table[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1}; //左循环移位表
const int IP_Table[64] = {                                     //IP置换矩阵
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
const int E_Table[48] = {                                    //扩展矩阵
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1 };
const int P_Table[32] = {                                     //P置换盒
	16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25 };
const int PC1_Table[56] = {                               //密钥第一次置换矩阵PC-1
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4 };
const int PC2_Table[48] = {                          // 密钥第二次置换矩阵PC-2
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
const int S_Box[8][4][16] = {                     //8个S盒
    // S1
	14, 4,  13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	// S2
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	// S3
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
	// S4
	7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
	// S5
	2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
	// S6
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
	// S7
	4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
	// S8
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};
const int IPR_Table[64] = {                                    //逆IP置换矩阵
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25 };
void print_usage() {
	printf("\n非法输入,支持的参数有以下：\n-p plainfile 指定明文文件的位置和名称\n-k keyfile  指定密钥文件的位置和名称\n-v vifile  指定初始化向量文件的位置和名称\n-m mode  指定加密的操作模式(ECB,CBC,CFB,OFB)\n-c cipherfile 指定密文文件的位置和名称。\n");
	exit(-1);
};
//读取16进制数文件转化为字节表示
bool readfile2memory(const char* filename, char** memory) {

	FILE* fp = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END); //从文件末尾向前偏移0长度给文件指针fp
	int size = ftell(fp);  //ftell返回文件当前位置，则size为文件大小
	fseek(fp, 0, SEEK_SET); //回到文件开头
	int i;
	*memory = (char*)malloc((size+1)*sizeof(char));  //按16进制读
	memset(*memory, 0, size+1);
    while(fgets(*memory,size+1, fp) != NULL){
        printf("读取内容%s\n", *memory);
    }
    (*memory)[size+1]='\0';

	return true;
	/*if (size % 2 != 0) {
		printf("%s:文件字节数不为偶数！\n", filename);
		fclose(fp);
		return false;
	}
	char* tmp = malloc(size);
	memset(tmp, 0, size);  //将tmp数组的值置为0

	fread(tmp, size, 1, fp);  //每个元素大小为文件大小，一个元素，输入到tmp中
	if (ferror(fp)) {
		printf("读取%s出错了！\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}

	*memory = malloc(size / 2 + 1);  //一个分组的大小
	memset(*memory, 0, size / 2 + 1);

	char parsewalker[3] = { 0 }; //数组用来保存一个字节的内容
	for (int i = 0; i < size; i += 2) {  //将所有16进制数按2个一组作为一个字节分开
		parsewalker[0] = tmp[i];
		parsewalker[1] = tmp[i + 1];
		(*memory)[i / 2] = strtol(parsewalker, 0, 16);  //把parsewalker所指的2位16进制数根据给定的base16转换为对应的字母
		printf("debug info : %c\n", (*memory)[i / 2]);  //输出字母，注意是i/2取整，连续保存内容
	}

	free(tmp);*/
};
void ByteToBit( bool * output,char * input,int num) //字节转换为位
{
    int i,j;
    for(i=0;i<num;i++)
    {
        output[i]=(input[i/8]>>(i%8))&0x01;
    }
};
void BitToByte(char* output,bool * input,int num) //位转换成字节
{
    int i=0;
    for(i=0;i<(num/8);i++)
    {
        output[i]=0;
    }
    for(i=0;i<num;i++)
    {
        output[i/8]|=input[i]<<(i%8);
    }
};
void char_to_bool(bool * output,char* input,int num){ //将明文字符串转化为bool型数组
	int i,j,l,n;
  	for(i=0;i<num/8;i++){
   		n=input[i]-'0'+48;
   		for(j=0;j<8;j++){
   			output[(i+1)*8-j-1]=n%2;
   			n=n/2;
		   }
 	}
};
void bool_to_char(char *output,bool* input,int num){   //将bool型数组转化为字符串
	int i,j,n;
	for(i=0;i<num/8;i++){
		n=0;
		for(j=0;j<8;j++){
			n+=input[8*i+j]*pow(2,8-j-1);
		}
		output[i]=n+0;
	}
};
void bit_to_hex(char *output,bool *input,int num)  //将二进制数转化为十六进制数
{
    int i=0;
    for(i=0;i<num/4;i++)
    {
        output[i]=0;
    }
    for(i=0;i<num/4;i++)
    {
        output[i] = (input[i*4]<<3)+(input[i*4+1]<<2)+(input[i*4+2]<<1)+(input[i*4+3]<<0);
        if((output[i]%16)>9)
        {
            output[i]=output[i]%16+'7';       // 10-15 to A-F
        }
        else
        {
            output[i]=output[i]%16+'0';       //  0-9
        }
    }

}
void hex_to_bit(bool *output,char *input,int num)  //将16进制数转化为二进制数
{
    int i=0;
    for(i=0;i<num;i++)
    {
        if((input[i/4])>'9')
        {
            output[i]=((input[i/4]-'7')>>(3-(i%4)))&0x01;
        }
        else
        {
            output[i]=((input[i/4]-'0')>>(3-(i%4)))&0x01;
        }
    }
}
void Xor(bool * output,bool * input,int num){  //对num位二进制数进行异或操作
    int i;
    for(i=0;i<num;i++){
	   output[i]=output[i]^input[i];
    }
};
void Table_copy(bool * output, bool * input,int num) { //复制数组
	 int i;
 	 for(i=0;i<num;i++){
	     output[i]=input[i];
	 }
};
void Substitute(bool* output,bool* input, const int* table,int num){  //置换函数，table为置换表
	int i;
	for(i=0;i<num;i++){
		output[i]=input[table[i]-1];
	}
};
void RotateL(bool* output,bool* input,int len,int num){  //子密钥生成过程的左循环移位
	int i;
	for(i=0;i<len;i++){
		output[i]=input[(i+num)%len];
	}
};
void Subkey_func(bool* key_bool){  //生成子密钥
	bool pc1[56];  //保存PC-1置换后的密钥
	bool R[28],L[28];
	bool temp_L[28],temp_R[28],temp[56]={0};
	int i,j,t;

	Substitute(pc1,key_bool,PC1_Table,56);//进行PC1置换，输出至pc1
	Table_copy(temp,pc1,56);
	for(i=0;i<16;i++){//生成每一轮密钥

		for(t=0;t<28;t++){ //分为分成左右两部分
            L[t]=temp[t];
            R[t]=temp[t+28];
	    }
		RotateL(temp_R,R,28,LS_Table[i]);
		RotateL(temp_L,L,28,LS_Table[i]);  //分别对左右两部分进行对应的左循环移位，注意因为temp存储了后续进行左循环移位的数组，所以已经有累加偏移数
		for(t=0;t<28;t++){
			temp[t]=temp_L[t];
			temp[t+28]=temp_R[t];
		}
		Substitute(Subkeys[i],temp,PC2_Table,48);
	}

};
void S_compress(bool * output,bool * input ) //S盒变换
{
    int i;
    int j=0; //记得初始化
	int INT[8]={0};
	int column=0,row=0;
	for (i=0;i<48;i=i+6)
	{
	    row=input[i+5]+2*input[i];  //对应S盒的行，行号从0开始，b1b6
        column=input[i+4]+input[i+3]*2+input[i+2]*4+input[i+1]*8;  //对应S盒的列,列号从0开始，b2b3b4b5
        INT[j]=S_Box[j][row][column];
		j++;
	}
    for (j = 0; j<8; j++) //10进制转化为二进制输出
	{
		for (i = 0; i<4; i++)
		{
			output[3 * (j + 1) - i + j] = (INT[j] >> i) & 1;
		}
	}
}
void F_func(bool* output,bool* input,bool* key){  //F函数
	int i;
	bool temp_1[48];
	bool temp_2[32];

	Substitute(temp_1,input,E_Table,48); //Ri进行E扩展
	Xor(temp_1,key,48);  //K⊕E(R)，K为子密钥
	S_compress(temp_2,temp_1);  //S(K⊕E(R)),S盒压缩
	Substitute(output,temp_2,P_Table,32); //P(S(K⊕E(R)))，P置换
};

void DES_one_round(bool* output,bool* input,bool* subkey){
	bool in_R[32],in_L[32],out_R[32];
	int i;
	for(i=0;i<32;i++){
		in_R[i]=input[32+i];
		output[i]=input[32+i]; //每轮左半部分为上一次的右半部分
		in_L[i]=input[i];
	}
	F_func(out_R,in_R,subkey);
	Xor(out_R,in_L,32);
	for(i=0;i<32;i++){
		output[i+32]=out_R[i];
	}
}
void Encrypt(bool* output, bool* input, bool* key_in){
    bool in_IP[64],temp_in[64],temp_out[64],output_1[64];
	int i,j;
    Subkey_func(key_in); //生成子密钥
	Substitute(in_IP,input,IP_Table,64); //明文初始IP置换
    Table_copy(temp_in,in_IP,64);
	for(i=0;i<16;i++){
		DES_one_round(temp_out,temp_in,Subkeys[i]); //轮函数
		Table_copy(temp_in,temp_out,64);
	}
	for(i=0;i<32;i++){
		output_1[i]=temp_out[i+32];
		output_1[i+32]=temp_out[i];
	}
	Substitute(output,output_1,IPR_Table,64);
    /*不单独将轮变换拿出，即无DES_one_round
    int i,j,k;
    bool temp_1[64]={0};
    bool temp_2[64]={0};
    bool l[17][32]={0}, r[17][32]={0};
    Subkey_func(key_in); //生成子密钥
    Substitute(temp_1,input,IP_Table,64); //明文初始IP置换
    for (i = 0; i<32; i++)
	{
		l[0][i] = temp_1[i];
		r[0][i] = temp_1[32 + i];  //将明文初始置换后的分为左右两部分
	};

	for (j = 1; j<16; j++)//前15轮的操作
	{
		Table_copy(l[j],r[j-1],32);
		F_func(r[j], r[j - 1], Subkeys[j - 1]);
		Xor(r[j], l[j - 1], 32);  //R[j]=L[j-1]⊕f(R[j-1],K[])
	};
    Table_copy(r[16],r[15],32);//最后一轮后,将位置交换加上
	F_func(l[16],r[15],Subkeys[15]);
	Xor(l[16], l[15], 32);
	for (j= 0; j<32; j++)
	{
		temp_2[j] = l[16][j];
		temp_2[32 + j] = r[16][j];
	}
	Substitute(output,temp_2,IPR_Table,64);*/
};
void Decrypt(bool* output,bool* input,bool* key_in){
    bool in_IP[64],temp_in[64],temp_out[64],output_1[64];
	int i,j;

	Substitute(in_IP,input,IP_Table,64);
    Table_copy(temp_in,in_IP,64);

	for(i=15;i>=0;i--){
		DES_one_round(temp_out,temp_in,Subkeys[i]);
		Table_copy(temp_in,temp_out,64);
	}
	for(i=0;i<32;i++){
		output_1[i]=temp_out[i+32];
		output_1[i+32]=temp_out[i];
	}
	Substitute(output,output_1,IPR_Table,64);
};
void ECB(const char* plaintext, const char* keytext, char** ciphertext) {
	bool plain_set[64];  //保存一组64位的明文
	bool cipher_set[64];  //保存一组64位的密文
	bool bool_key[64];  //保存64位的密钥
	int num,i,j;
	char* cipher;
	char hex[16];
	char temp[16],temp_char[16];
	*ciphertext= (char *)malloc((strlen(plaintext)+1)*sizeof(char)); //动态分配内存，记住加1，需要以NULL结尾
	cipher=*ciphertext;

	hex_to_bit(bool_key,keytext,64); //将字节形式的密钥改为二进制形式
	num=(strlen(plaintext))/16;   //看几个分组进行加密
	for(i=0;i<num;i++){
		for(j=0;j<16;j++){
            temp[j]=plaintext[j+i*16];    //保存8字节的明文，16个16进制数
		}
		hex_to_bit(plain_set,temp,64);  //将16进制形式的明文转为二进制形式
		Encrypt(cipher_set,plain_set,bool_key);
		bit_to_hex(hex,cipher_set,64); //将密文转为16进制数表示
		for(j=0;j<16;j++){
			cipher[i*16+j]=hex[j];
		}
	}
	cipher[strlen(plaintext)]='\0';  //以NULL结尾
};
void ECB_decrypt(char** plaintext,const char* ciphertext,const char* keytext){
    bool bool_key[64];
    int num,i,j;
    char temp[16],temp_char[16];
    bool plain_set[64];  //保存一组64位的明文
	bool cipher_set[64];  //保存一组64位的密文
	char *plain;
	*plaintext= (char *)malloc((strlen(ciphertext)+1)*sizeof(char)); //动态分配内存，记住加1，需要以NULL结尾
	plain=*plaintext;

	hex_to_bit(bool_key,keytext,64); //将16进制形式的密钥改为二进制形式
    num=(strlen(ciphertext))/16;
    for(i=0;i<num;i++){
        for(j=0;j<16;j++){
            temp[j]=ciphertext[j+i*16];    //保存16进制数表示的密文
		}
		hex_to_bit(cipher_set,temp,64);  //将16进制密文转化为二进制表示
		Decrypt(plain_set,cipher_set,bool_key);  //解密
		bit_to_hex(temp_char,plain_set,64); //将二进制形式的明文转化为16进制表示
		for(j=0;j<16;j++){
            plain[j+i*16]=temp_char[j];
            //printf("%c",temp_char[j]);
		}
    }
    //printf("\n");
    plain[strlen(ciphertext)]='\0';  //以NULL结尾
}
void CBC(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	bool plain_set[64];  //保存64位的明文，即一次一个分组
    bool cipher_set[64];  //保存64位的密文
    bool bool_key[64];  //保存64位密钥
    bool bool_iv[64],bool_temp[64];
	int num,i,j,t;
	char temp[16]; //保存明文
	char hex[16];  //保存16进制数密文
    char* cipher;
	*ciphertext= (char *)malloc((strlen(plaintext)+1)*sizeof(char));
    cipher=*ciphertext;
	num=(strlen(plaintext))/16;
	hex_to_bit(bool_key,keytext,64); //将字符型密钥转换为二进制数表示的密钥
	hex_to_bit(bool_iv,vitext,64);
    Table_copy(bool_temp,bool_iv,64);
	for(i=0;i<num;i++){
		for(j=0;j<16;j++){
            temp[j]=plaintext[j+i*16];
		}
		hex_to_bit(plain_set,temp,64);
		Xor(plain_set,bool_temp,64); //第一次向量与明文进行异或，后续前一个密文分组与当前明文进行异或
		Encrypt(cipher_set,plain_set,bool_key);  //加密得密文分组一
		Table_copy(bool_temp,cipher_set,64);
		bit_to_hex(hex,cipher_set,64);
		for(j=0;j<16;j++){
            cipher[j+i*16]=hex[j]; //16进制数表示的密文传递给cipher
            //printf("%c",hex[j]);
		}
	}
	cipher[strlen(plaintext)]='\0';  //以NULL结尾
};
void CBC_decrypt(char** plaintext,const char* ciphertext,const char* keytext,const char* vitext){
    bool plain_set[64];  //保存64位的明文，即一次一个分组
    bool cipher_set[64];  //保存64位的密文
    bool bool_key[64];  //保存64位密钥
    bool bool_iv[64],bool_temp[64];
	int num,i,j;
	char temp[16]; //保存密文
	char hex[16];  //保存明文
	char *plain;
	*plaintext= (char *)malloc((strlen(ciphertext)+1)*sizeof(char)); //动态分配内存，记住加1，需要以NULL结尾
	plain=*plaintext;

	hex_to_bit(bool_key,keytext,64); //将16进制形式的密钥改为二进制形式
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp,bool_iv,64);
    num=(strlen(ciphertext))/16;
    for(i=0;i<num;i++){
        for(j=0;j<16;j++){
            temp[j]=ciphertext[i*16+j];
        }
        hex_to_bit(cipher_set,temp,64);
        Decrypt(plain_set,cipher_set,64);
        Xor(plain_set,bool_temp,64);
        Table_copy(bool_temp,cipher_set,64);
        bit_to_hex(hex,plain_set,64);
        for(j=0;j<16;j++){
            plain[j+i*16]=hex[j];
            //printf("%c",hex[j]);
        }

    }
    //printf("\n");
    plain[strlen(ciphertext)]='\0';  //以NULL结尾

};
void CFB(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	bool plain_set[8];  //保存8位的明文，即一次一个分组
    bool cipher_set[8]={0};  //保存8位的密文
    bool bool_key[64];  //保存64位密钥
    bool bool_register[64];
    bool bool_iv[64],bool_temp[64],bool_temp1[64],bool_temp2[64];
	int num,i,j;
	char temp[2]; //保存明文
	char hex[2];  //保存16进制数密文
	char* cipher;
	*ciphertext= (char *)malloc((strlen(plaintext)+1)*sizeof(char)); //动态分配内存，记住加1，需要以NULL结尾
	cipher=*ciphertext;

	num=(strlen(plaintext))/2; //为8位CFB模式
	hex_to_bit(bool_key,keytext,64);
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp1,bool_iv,64);

	for(i=0;i<num;i++){
        Encrypt(bool_register,bool_temp1,bool_key);
        Table_copy(cipher_set,bool_register,8);  //选择左边的8位
        for(j=0;j<2;j++){
            temp[j]=plaintext[i*2+j];
        }

		hex_to_bit(plain_set,temp,8);
		Xor(cipher_set,plain_set,8); //第一次向量加密后丢弃32位与明文进行异或，后续前一个密文分组左移S位加密后丢弃32位与当前明文进行异或
		Table_copy(bool_temp2,cipher_set,8);
		bit_to_hex(hex,cipher_set,8);
		for(j=0;j<2;j++){
            cipher[j+i*2]=hex[j]; //16进制数表示的密文传递给cipher
		}
		RotateL(bool_temp,bool_temp1,64,8);  //左循环移位
		Table_copy(bool_temp1,bool_temp,64);
		for(j=0;j<8;j++){
            bool_temp1[j+56]=bool_temp2[j];  //将寄存器右边8位用密文替代
		}

	}
	cipher[strlen(plaintext)]='\0';  //以NULL结尾
};
void CFB_decrypt(char** plaintext,const char* ciphertext,const char* keytext,const char* vitext){
    bool plain_set[8];  //保存8位的明文，即一次一个分组
    bool cipher_set[8]={0};  //保存8位的密文
    bool bool_key[64];  //保存64位密钥
    bool bool_register[64];
    bool bool_iv[64],bool_temp[64],bool_temp1[64],bool_temp2[64];
	int num,i,j;
	char temp[2]; //保存密文
	char hex[2];  //保存16进制数明文
	char *plain;
	*plaintext= (char *)malloc((strlen(ciphertext)+1)*sizeof(char)); //动态分配内存，记住加1，需要以NULL结尾
	plain=*plaintext;
	hex_to_bit(bool_key,keytext,64); //将16进制形式的密钥改为二进制形式
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp1,bool_iv,64);
    num=(strlen(ciphertext))/2;
    for(i=0;i<num;i++){
        Encrypt(bool_register,bool_temp1,bool_key);
        Table_copy(plain_set,bool_register,8);  //选择左边的8位
        for(j=0;j<2;j++){
            temp[j]=ciphertext[i*2+j];
        }
		hex_to_bit(cipher_set,temp,8);
		Xor(plain_set,cipher_set,8);
		Table_copy(bool_temp2,cipher_set,8);
		bit_to_hex(hex,plain_set,8);
		for(j=0;j<2;j++){
            plain[j+i*2]=hex[j];
            //printf("%c",hex[j]);
		}
		RotateL(bool_temp,bool_temp1,64,8);  //左循环移位
		Table_copy(bool_temp1,bool_temp,64);
		for(j=0;j<8;j++){
            bool_temp1[j+56]=bool_temp2[j];  //将寄存器右边8位用密文替代
		}

	}
	//printf("\n");
	plain[strlen(ciphertext)]='\0';  //以NULL结尾
};
void OFB(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintext为明文字符数组,以NULL结尾
	//keytext为密钥字符数组，以NULL结尾
	//vitext为初始化向量字符数组，以NULL结尾
	//cipher为密文字符数组，以NULL结尾，需要你来填充，注意要給cipher分配空间！
	//请实现~
	bool plain_set[8];  //保存8位的明文，即一次一个分组
    bool cipher_set[64],temp_cipher[8];  //保存8位的密文
    bool bool_key[64];  //保存64位密钥
    bool bool_iv[64],bool_temp[64],bool_temp1[64],bool_temp2[64];
	int num,i,j;
	char temp[2]; //保存明文
	char hex[2];  //保存16进制数密文
	char* cipher;
	*ciphertext= (char *)malloc((strlen(plaintext)+1)*sizeof(char));
    cipher=*ciphertext;

	num=(strlen(plaintext))/2;//8位OFB模式
	hex_to_bit(bool_key,keytext,64);
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp,bool_iv,64);
	Table_copy(bool_temp1,bool_iv,64);

	for(i=0;i<num;i++){
        Encrypt(cipher_set,bool_temp,bool_key);  //寄存器内容进行加密
		Table_copy(temp_cipher,cipher_set,8); //加密后的前八位
		RotateL(bool_temp2,bool_temp1,64,8);  //左循环移位
		for(j=0;j<8;j++){
            bool_temp2[j+56]=temp_cipher[j];  //将寄存器右边8位用密文替代
		}
		Table_copy(bool_temp1,bool_temp2,64);  //bool_temp1用来存放每次寄存器偏移补位之后的数据
        Table_copy(bool_temp,bool_temp1,64);
        for(j=0;j<2;j++){
            temp[j]=plaintext[i*2+j];
        }

		hex_to_bit(plain_set,temp,8);
		Xor(temp_cipher,plain_set,8);
		bit_to_hex(hex,temp_cipher,8);
		for(j=0;j<2;j++){
            cipher[j+i*2]=hex[j]; //16进制数表示的密文传递给cipher
		}
	}
	cipher[strlen(plaintext)]='\0';  //以NULL结尾
};
void OFB_decrypt(char** plaintext,const char* ciphertext,const char* keytext,const char* vitext){
    bool plain_set[64],temp_plain[8];  //保存8位的明文，即一次一个分组
    bool cipher_set[8]={0};  //保存8位的密文
    bool bool_key[64];  //保存64位密钥
    bool bool_iv[64],bool_temp[64],bool_temp1[64],bool_temp2[64];
	int num,i,j;
	char temp[2]; //保存密文
	char hex[2];  //保存16进制数明文
	char *plain;
	*plaintext= (char *)malloc((strlen(ciphertext)+1)*sizeof(char)); //动态分配内存，记住加1，需要以NULL结尾
	plain=*plaintext;

	hex_to_bit(bool_key,keytext,64); //将16进制形式的密钥改为二进制形式
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp1,bool_iv,64);
    num=(strlen(ciphertext))/2;
    Table_copy(bool_temp,bool_iv,64);

	for(i=0;i<num;i++){
        Encrypt(plain_set,bool_temp,bool_key);  //寄存器内容进行加密
		Table_copy(temp_plain,plain_set,8); //加密后的前八位
		RotateL(bool_temp2,bool_temp1,64,8);  //左循环移位
		for(j=0;j<8;j++){
            bool_temp2[j+56]=temp_plain[j];  //将寄存器右边8位用密文替代
		}
		Table_copy(bool_temp1,bool_temp2,64);  //bool_temp1用来存放每次寄存器偏移补位之后的数据
        Table_copy(bool_temp,bool_temp1,64);
        for(j=0;j<2;j++){
            temp[j]=ciphertext[i*2+j];
        }
		hex_to_bit(cipher_set,temp,8);
		Xor(temp_plain,cipher_set,8);
		bit_to_hex(hex,temp_plain,8);
		for(j=0;j<2;j++){
            plain[j+i*2]=hex[j];
            //printf("%c",hex[j]);
		}
	}
	//printf("\n");
	plain[strlen(ciphertext)]='\0';  //以NULL结尾
};
void test(int choice) {
		char* key_test=NULL;
		char* plain_test=NULL;
		char* plain_test1=NULL;
		char* cipher_test=NULL;
		char* vi_test=NULL;
		char num;
		bool read;
		int j,k,t;
		long i;
		double size;
		clock_t start, stop; //clock_t为clock()函数返回的变量类型
		double duration;
		double v;

		i=10*pow(2,20);  //需要生成5MB的随机测试数据,以16进制数生成,i个16进制数
		plain_test=(char*)malloc(i*sizeof(char)+1);
		for(k=0;k<i;k++){
			num = rand()%16;
			if(num>=10){
				num = num -10 +'A';
			}
			else{
				num = num + '0';
			}
			plain_test[k]=num;
		}
		plain_test[k]='\0';
		size=(double)(i/(2*1024*1024));
		printf("生成数据成功！数据大小%.2fMB\n",size);

		/*plain_test1=(char*)malloc((i*sizeof(char))/2+1);  //变为字节形式
		char parsewalker[3] = { 0 }; //数组用来保存一个字节的内容
        for ( j= 0; j< i; j+= 2) {  //将所有16进制数按2个一组作为一个字节分开
            parsewalker[0] = plain_test[i];
            parsewalker[1] = plain_test[i + 1];
            plain_test1[j / 2] = strtol(parsewalker, 0, 16);  //把parsewalker所指的2位16进制数根据给定的base16转换为对应的字母
            //printf("%c", plain_test1[i / 2]);  //输出字母，注意是i/2取整，连续保存内容
        }*/
		read= readfile2memory("des_key.txt", &key_test);
		read= readfile2memory("des_iv.txt", &vi_test);
		switch(choice){
			case 1:
				printf("\nECB模式连续20次加解密测试:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nECB第%d次加解密开始：",k);
                    ECB(plain_test,key_test,&cipher_test);
                    ECB_decrypt(&plain_test,cipher_test,key_test);
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCK为clock()函数的时间单位，即时钟打点
    			printf("\nECB连续加解密20次总时间为：%.4fms",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("\n速度为：%.4fMByte/s\n",v);
    			break;
    		case 2:
    			printf("\nCBC模式连续加解密20次:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nCBC第%d次加解密开始：",k);
                    CBC(plain_test,key_test,vi_test,&cipher_test);
                    CBC_decrypt(&plain_test,cipher_test,key_test,vi_test);
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCK为clock()函数的时间单位，即时钟打点
    			printf("\nCBC连续加解密20次总时间为：%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("速度为：%.4fMByte/s\n",v);
    			break;
    		case 3:
    			printf("\nCFB连续加解密20次:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nCFB第%d次加解密开始：",k);
                    CFB(plain_test,key_test,vi_test,&cipher_test);
                    CFB_decrypt(&plain_test,cipher_test,key_test,vi_test);
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCK为clock()函数的时间单位，即时钟打点
    			printf("\nCFB连续加解密20次总时间为：%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("速度为：%.4fMByte/s\n",v);
    			break;
    		case 4:
    			   	printf("\nOFB连续加解密20次:");
					start=clock();
    				for(k=1;k<21;k++){
                        printf("\nOFB第%d次加解密开始：",k);
                        OFB(plain_test,key_test,vi_test,&cipher_test);
                        OFB_decrypt(&plain_test,cipher_test,key_test,vi_test);
					}
   				stop=clock();
    			duration=(double)(stop-start); //CLK_TCK为clock()函数的时间单位，即时钟打点
    			printf("\nOFB连续加解密20次总时间为：%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("速度为：%.4fMByte/s\n",v);
    			break;
    		default:
    			printf("出错！");
		}
}

int main(int argc, char** argv) {
	//argc 表示参数的个数，argv表示每个参数的一个字符串数组
	int i;
	printf("argc:%d\n", argc);
	for (i = 0; i < argc; i++) {
		printf("%d : %s\n", i, argv[i]);
	}

	/*
	-p plainfile 指定明文文件的位置和名称
	-k keyfile  指定密钥文件的位置和名称
	-v vifile  指定初始化向量文件的位置和名称
	-m mode  指定加密的操作模式
	-c cipherfile 指定密文文件的位置和名称。
	*/

	if (argc % 2 == 0) {
		print_usage();
	}

	for (i = 1; i < argc; i += 2) {
		if (strlen(argv[i]) != 2) {
			print_usage();
		}
		switch (argv[i][1]) {
		case 'p':
			plainfile = argv[i + 1];
			break;
		case 'k':
			keyfile = argv[i + 1];
			break;
		case 'v':
			vifile = argv[i + 1];
			break;
		case 'm':
			if (strcmp(argv[i + 1], DES_MODE[0]) != 0 && strcmp(argv[i + 1], DES_MODE[1]) != 0 && strcmp(argv[i + 1], DES_MODE[2]) != 0 && strcmp(argv[i + 1], DES_MODE[3]) != 0) {
				print_usage();
			}
			mode = argv[i + 1];
			break;
		case 'c':
			cipherfile = argv[i + 1];
			break;
		default:
			print_usage();
		}
	}

	if (plainfile == NULL || keyfile == NULL || mode == NULL || cipherfile == NULL) {
		print_usage();
	}

	if (strcmp(mode, "ECB") != 0 && vifile == NULL) {
		print_usage();
	}

	printf("解析参数完成！\n");
	printf("参数为明文文件的位置和名称:%s\n", plainfile);
	printf("参数为密钥文件的位置和名称:%s\n", keyfile);
	if (strcmp(mode, "ECB") != 0) {
		printf("参数为初始化向量文件文件的位置和名称:%s\n", vifile);
	}
	printf("参数为密文文件的位置和名称:%s\n", cipherfile);
	printf("参数为加密的模式:%s\n", mode);

	printf("现在开始读取文件！\n");

	printf("读取明文文件...\n");
	bool read_result = readfile2memory(plainfile, &plaintext);
	if (read_result == false) {
		printf("读取明文文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取明文文件成功！\n");

	printf("读取密钥文件...\n");
	read_result = readfile2memory(keyfile, &keytext);
	if (read_result == false) {
		printf("读取密钥文件失败，请检查路径及文件是否存在\n");
		exit(-1);
	}
	printf("读取密钥文件成功！\n");

	if (strcmp(mode, "ECB") != 0) {
		printf("读取初始向量文件...\n");
		read_result = readfile2memory(vifile, &vitext);
		if (read_result == false) {
			printf("读取初始向量文件失败，请检查路径及文件是否存在\n");
			exit(-1);
		}
		printf("读取初始向量文件成功！\n");
	}

	if (strcmp(mode, "ECB") == 0) {
		ECB(plaintext, keytext, &ciphertext);
		ECB_decrypt(&plaintext,ciphertext,keytext);//测试解密
		printf("解密出的明文为%s\n",plaintext);

	}
	else if (strcmp(mode, "CBC") == 0) {
		CBC(plaintext, keytext, vitext, &ciphertext);
		CBC_decrypt(&plaintext,ciphertext, keytext, vitext);
		printf("解密出的明文为%s\n",plaintext);
	}
	else if (strcmp(mode, "CFB") == 0) {
		CFB(plaintext, keytext, vitext, &ciphertext);
		CFB_decrypt(&plaintext,ciphertext, keytext, vitext);
		printf("解密出的明文为%s\n",plaintext);
	}
	else if (strcmp(mode, "OFB") == 0) {
		OFB(plaintext, keytext, vitext, &ciphertext);
		OFB_decrypt(&plaintext, ciphertext,keytext, vitext);
		printf("解密出的明文为%s\n",plaintext);
	}
	else {
		//不应该能到达这里
		printf("致命错误！！！\n");
		exit(-2);
	}

	if (ciphertext == NULL) {
		printf("同学，ciphertext没有分配内存哦，需要补补基础~\n失败，程序退出中...");
		exit(-1);
	}

	if (ciphertext[strlen(ciphertext)]!=NULL) {
		printf("长度%d",strlen(ciphertext));
		printf("%s\n",ciphertext);
		printf("同学，ciphertext没有以NULL为结尾哦，或者cipher弄错了，请再检查一下~\n失败，程序退出中...");
		exit(-1);
	}

	printf("加密出来的密文（十六进制表示）为:%s\n", ciphertext);
	/*printf("16进制表示为:");

	int count = strlen(ciphertext);
	char* cipherhex = malloc(count * 2 + 1);
	memset(cipherhex, 0, count * 2 + 1);

	for (i = 0; i < count; i++) {
		sprintf(cipherhex + i * 2, "%2X", ciphertext[i]);*/
	//}
	//printf("%s\n写入文件中...\n", ciphertext);
    printf("\n写入文件中...\n");
	FILE* fp = fopen(cipherfile, "w");
	if (fp == NULL) {
		printf("文件 %s 打开失败,请检查", cipherfile);
		exit(-1);
	}

	int writecount=fwrite(ciphertext,sizeof(char),strlen(ciphertext),fp);
	if (writecount != strlen(ciphertext)) {
		printf("写入文件出现故障，请重新尝试！");
		exit(-1);
	}
	else{
		printf("写入成功\n");
	}
	if (strcmp(mode, "ECB") == 0) {
		test(1);
	}
	else if (strcmp(mode, "CBC") == 0) {
		test(2);
	}
	else if (strcmp(mode, "CFB") == 0) {
		test(3);
	}
	else if (strcmp(mode, "OFB") == 0) {
		test(4);
	}
	else {
		printf("致命错误！！！\n");
		exit(-2);
	}
	printf("恭喜你完成了该程序，请提交代码!");

	return 0;
}

