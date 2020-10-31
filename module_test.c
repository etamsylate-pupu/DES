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
static bool Subkeys[16][48]={0}; //�洢����Կ
const int LS_Table[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1}; //��ѭ����λ��
const int IP_Table[64] = {                                     //IP�û�����
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
const int E_Table[48] = {                                    //��չ����
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1 };
const int P_Table[32] = {                                     //P�û���
	16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25 };
const int PC1_Table[56] = {                               //��Կ��һ���û�����PC-1
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4 };
const int PC2_Table[48] = {                          // ��Կ�ڶ����û�����PC-2
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
const int S_Box[8][4][16] = {                     //8��S��
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
const int IPR_Table[64] = {                                    //��IP�û�����
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25 };
void print_usage() {
	printf("\n�Ƿ�����,֧�ֵĲ��������£�\n-p plainfile ָ�������ļ���λ�ú�����\n-k keyfile  ָ����Կ�ļ���λ�ú�����\n-v vifile  ָ����ʼ�������ļ���λ�ú�����\n-m mode  ָ�����ܵĲ���ģʽ(ECB,CBC,CFB,OFB)\n-c cipherfile ָ�������ļ���λ�ú����ơ�\n");
	exit(-1);
};
//��ȡ16�������ļ�ת��Ϊ�ֽڱ�ʾ
bool readfile2memory(const char* filename, char** memory) {

	FILE* fp = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END); //���ļ�ĩβ��ǰƫ��0���ȸ��ļ�ָ��fp
	int size = ftell(fp);  //ftell�����ļ���ǰλ�ã���sizeΪ�ļ���С
	fseek(fp, 0, SEEK_SET); //�ص��ļ���ͷ
	int i;
	*memory = (char*)malloc((size+1)*sizeof(char));  //��16���ƶ�
	memset(*memory, 0, size+1);
    while(fgets(*memory,size+1, fp) != NULL){
        printf("��ȡ����%s\n", *memory);
    }
    (*memory)[size+1]='\0';

	return true;
	/*if (size % 2 != 0) {
		printf("%s:�ļ��ֽ�����Ϊż����\n", filename);
		fclose(fp);
		return false;
	}
	char* tmp = malloc(size);
	memset(tmp, 0, size);  //��tmp�����ֵ��Ϊ0

	fread(tmp, size, 1, fp);  //ÿ��Ԫ�ش�СΪ�ļ���С��һ��Ԫ�أ����뵽tmp��
	if (ferror(fp)) {
		printf("��ȡ%s�����ˣ�\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}

	*memory = malloc(size / 2 + 1);  //һ������Ĵ�С
	memset(*memory, 0, size / 2 + 1);

	char parsewalker[3] = { 0 }; //������������һ���ֽڵ�����
	for (int i = 0; i < size; i += 2) {  //������16��������2��һ����Ϊһ���ֽڷֿ�
		parsewalker[0] = tmp[i];
		parsewalker[1] = tmp[i + 1];
		(*memory)[i / 2] = strtol(parsewalker, 0, 16);  //��parsewalker��ָ��2λ16���������ݸ�����base16ת��Ϊ��Ӧ����ĸ
		printf("debug info : %c\n", (*memory)[i / 2]);  //�����ĸ��ע����i/2ȡ����������������
	}

	free(tmp);*/
};
void ByteToBit( bool * output,char * input,int num) //�ֽ�ת��Ϊλ
{
    int i,j;
    for(i=0;i<num;i++)
    {
        output[i]=(input[i/8]>>(i%8))&0x01;
    }
};
void BitToByte(char* output,bool * input,int num) //λת�����ֽ�
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
void char_to_bool(bool * output,char* input,int num){ //�������ַ���ת��Ϊbool������
	int i,j,l,n;
  	for(i=0;i<num/8;i++){
   		n=input[i]-'0'+48;
   		for(j=0;j<8;j++){
   			output[(i+1)*8-j-1]=n%2;
   			n=n/2;
		   }
 	}
};
void bool_to_char(char *output,bool* input,int num){   //��bool������ת��Ϊ�ַ���
	int i,j,n;
	for(i=0;i<num/8;i++){
		n=0;
		for(j=0;j<8;j++){
			n+=input[8*i+j]*pow(2,8-j-1);
		}
		output[i]=n+0;
	}
};
void bit_to_hex(char *output,bool *input,int num)  //����������ת��Ϊʮ��������
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
void hex_to_bit(bool *output,char *input,int num)  //��16������ת��Ϊ��������
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
void Xor(bool * output,bool * input,int num){  //��numλ������������������
    int i;
    for(i=0;i<num;i++){
	   output[i]=output[i]^input[i];
    }
};
void Table_copy(bool * output, bool * input,int num) { //��������
	 int i;
 	 for(i=0;i<num;i++){
	     output[i]=input[i];
	 }
};
void Substitute(bool* output,bool* input, const int* table,int num){  //�û�������tableΪ�û���
	int i;
	for(i=0;i<num;i++){
		output[i]=input[table[i]-1];
	}
};
void RotateL(bool* output,bool* input,int len,int num){  //����Կ���ɹ��̵���ѭ����λ
	int i;
	for(i=0;i<len;i++){
		output[i]=input[(i+num)%len];
	}
};
void Subkey_func(bool* key_bool){  //��������Կ
	bool pc1[56];  //����PC-1�û������Կ
	bool R[28],L[28];
	bool temp_L[28],temp_R[28],temp[56]={0};
	int i,j,t;

	Substitute(pc1,key_bool,PC1_Table,56);//����PC1�û��������pc1
	Table_copy(temp,pc1,56);
	for(i=0;i<16;i++){//����ÿһ����Կ

		for(t=0;t<28;t++){ //��Ϊ�ֳ�����������
            L[t]=temp[t];
            R[t]=temp[t+28];
	    }
		RotateL(temp_R,R,28,LS_Table[i]);
		RotateL(temp_L,L,28,LS_Table[i]);  //�ֱ�����������ֽ��ж�Ӧ����ѭ����λ��ע����Ϊtemp�洢�˺���������ѭ����λ�����飬�����Ѿ����ۼ�ƫ����
		for(t=0;t<28;t++){
			temp[t]=temp_L[t];
			temp[t+28]=temp_R[t];
		}
		Substitute(Subkeys[i],temp,PC2_Table,48);
	}

};
void S_compress(bool * output,bool * input ) //S�б任
{
    int i;
    int j=0; //�ǵó�ʼ��
	int INT[8]={0};
	int column=0,row=0;
	for (i=0;i<48;i=i+6)
	{
	    row=input[i+5]+2*input[i];  //��ӦS�е��У��кŴ�0��ʼ��b1b6
        column=input[i+4]+input[i+3]*2+input[i+2]*4+input[i+1]*8;  //��ӦS�е���,�кŴ�0��ʼ��b2b3b4b5
        INT[j]=S_Box[j][row][column];
		j++;
	}
    for (j = 0; j<8; j++) //10����ת��Ϊ���������
	{
		for (i = 0; i<4; i++)
		{
			output[3 * (j + 1) - i + j] = (INT[j] >> i) & 1;
		}
	}
}
void F_func(bool* output,bool* input,bool* key){  //F����
	int i;
	bool temp_1[48];
	bool temp_2[32];

	Substitute(temp_1,input,E_Table,48); //Ri����E��չ
	Xor(temp_1,key,48);  //K��E(R)��KΪ����Կ
	S_compress(temp_2,temp_1);  //S(K��E(R)),S��ѹ��
	Substitute(output,temp_2,P_Table,32); //P(S(K��E(R)))��P�û�
};

void DES_one_round(bool* output,bool* input,bool* subkey){
	bool in_R[32],in_L[32],out_R[32];
	int i;
	for(i=0;i<32;i++){
		in_R[i]=input[32+i];
		output[i]=input[32+i]; //ÿ����벿��Ϊ��һ�ε��Ұ벿��
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
    Subkey_func(key_in); //��������Կ
	Substitute(in_IP,input,IP_Table,64); //���ĳ�ʼIP�û�
    Table_copy(temp_in,in_IP,64);
	for(i=0;i<16;i++){
		DES_one_round(temp_out,temp_in,Subkeys[i]); //�ֺ���
		Table_copy(temp_in,temp_out,64);
	}
	for(i=0;i<32;i++){
		output_1[i]=temp_out[i+32];
		output_1[i+32]=temp_out[i];
	}
	Substitute(output,output_1,IPR_Table,64);
    /*���������ֱ任�ó�������DES_one_round
    int i,j,k;
    bool temp_1[64]={0};
    bool temp_2[64]={0};
    bool l[17][32]={0}, r[17][32]={0};
    Subkey_func(key_in); //��������Կ
    Substitute(temp_1,input,IP_Table,64); //���ĳ�ʼIP�û�
    for (i = 0; i<32; i++)
	{
		l[0][i] = temp_1[i];
		r[0][i] = temp_1[32 + i];  //�����ĳ�ʼ�û���ķ�Ϊ����������
	};

	for (j = 1; j<16; j++)//ǰ15�ֵĲ���
	{
		Table_copy(l[j],r[j-1],32);
		F_func(r[j], r[j - 1], Subkeys[j - 1]);
		Xor(r[j], l[j - 1], 32);  //R[j]=L[j-1]��f(R[j-1],K[])
	};
    Table_copy(r[16],r[15],32);//���һ�ֺ�,��λ�ý�������
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
	bool plain_set[64];  //����һ��64λ������
	bool cipher_set[64];  //����һ��64λ������
	bool bool_key[64];  //����64λ����Կ
	int num,i,j;
	char* cipher;
	char hex[16];
	char temp[16],temp_char[16];
	*ciphertext= (char *)malloc((strlen(plaintext)+1)*sizeof(char)); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	cipher=*ciphertext;

	hex_to_bit(bool_key,keytext,64); //���ֽ���ʽ����Կ��Ϊ��������ʽ
	num=(strlen(plaintext))/16;   //������������м���
	for(i=0;i<num;i++){
		for(j=0;j<16;j++){
            temp[j]=plaintext[j+i*16];    //����8�ֽڵ����ģ�16��16������
		}
		hex_to_bit(plain_set,temp,64);  //��16������ʽ������תΪ��������ʽ
		Encrypt(cipher_set,plain_set,bool_key);
		bit_to_hex(hex,cipher_set,64); //������תΪ16��������ʾ
		for(j=0;j<16;j++){
			cipher[i*16+j]=hex[j];
		}
	}
	cipher[strlen(plaintext)]='\0';  //��NULL��β
};
void ECB_decrypt(char** plaintext,const char* ciphertext,const char* keytext){
    bool bool_key[64];
    int num,i,j;
    char temp[16],temp_char[16];
    bool plain_set[64];  //����һ��64λ������
	bool cipher_set[64];  //����һ��64λ������
	char *plain;
	*plaintext= (char *)malloc((strlen(ciphertext)+1)*sizeof(char)); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	plain=*plaintext;

	hex_to_bit(bool_key,keytext,64); //��16������ʽ����Կ��Ϊ��������ʽ
    num=(strlen(ciphertext))/16;
    for(i=0;i<num;i++){
        for(j=0;j<16;j++){
            temp[j]=ciphertext[j+i*16];    //����16��������ʾ������
		}
		hex_to_bit(cipher_set,temp,64);  //��16��������ת��Ϊ�����Ʊ�ʾ
		Decrypt(plain_set,cipher_set,bool_key);  //����
		bit_to_hex(temp_char,plain_set,64); //����������ʽ������ת��Ϊ16���Ʊ�ʾ
		for(j=0;j<16;j++){
            plain[j+i*16]=temp_char[j];
            //printf("%c",temp_char[j]);
		}
    }
    //printf("\n");
    plain[strlen(ciphertext)]='\0';  //��NULL��β
}
void CBC(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintextΪ�����ַ�����,��NULL��β
	//keytextΪ��Կ�ַ����飬��NULL��β
	//vitextΪ��ʼ�������ַ����飬��NULL��β
	//cipherΪ�����ַ����飬��NULL��β����Ҫ������䣬ע��Ҫ�ocipher����ռ䣡
	//��ʵ��~
	bool plain_set[64];  //����64λ�����ģ���һ��һ������
    bool cipher_set[64];  //����64λ������
    bool bool_key[64];  //����64λ��Կ
    bool bool_iv[64],bool_temp[64];
	int num,i,j,t;
	char temp[16]; //��������
	char hex[16];  //����16����������
    char* cipher;
	*ciphertext= (char *)malloc((strlen(plaintext)+1)*sizeof(char));
    cipher=*ciphertext;
	num=(strlen(plaintext))/16;
	hex_to_bit(bool_key,keytext,64); //���ַ�����Կת��Ϊ����������ʾ����Կ
	hex_to_bit(bool_iv,vitext,64);
    Table_copy(bool_temp,bool_iv,64);
	for(i=0;i<num;i++){
		for(j=0;j<16;j++){
            temp[j]=plaintext[j+i*16];
		}
		hex_to_bit(plain_set,temp,64);
		Xor(plain_set,bool_temp,64); //��һ�����������Ľ�����򣬺���ǰһ�����ķ����뵱ǰ���Ľ������
		Encrypt(cipher_set,plain_set,bool_key);  //���ܵ����ķ���һ
		Table_copy(bool_temp,cipher_set,64);
		bit_to_hex(hex,cipher_set,64);
		for(j=0;j<16;j++){
            cipher[j+i*16]=hex[j]; //16��������ʾ�����Ĵ��ݸ�cipher
            //printf("%c",hex[j]);
		}
	}
	cipher[strlen(plaintext)]='\0';  //��NULL��β
};
void CBC_decrypt(char** plaintext,const char* ciphertext,const char* keytext,const char* vitext){
    bool plain_set[64];  //����64λ�����ģ���һ��һ������
    bool cipher_set[64];  //����64λ������
    bool bool_key[64];  //����64λ��Կ
    bool bool_iv[64],bool_temp[64];
	int num,i,j;
	char temp[16]; //��������
	char hex[16];  //��������
	char *plain;
	*plaintext= (char *)malloc((strlen(ciphertext)+1)*sizeof(char)); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	plain=*plaintext;

	hex_to_bit(bool_key,keytext,64); //��16������ʽ����Կ��Ϊ��������ʽ
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
    plain[strlen(ciphertext)]='\0';  //��NULL��β

};
void CFB(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintextΪ�����ַ�����,��NULL��β
	//keytextΪ��Կ�ַ����飬��NULL��β
	//vitextΪ��ʼ�������ַ����飬��NULL��β
	//cipherΪ�����ַ����飬��NULL��β����Ҫ������䣬ע��Ҫ�ocipher����ռ䣡
	//��ʵ��~
	bool plain_set[8];  //����8λ�����ģ���һ��һ������
    bool cipher_set[8]={0};  //����8λ������
    bool bool_key[64];  //����64λ��Կ
    bool bool_register[64];
    bool bool_iv[64],bool_temp[64],bool_temp1[64],bool_temp2[64];
	int num,i,j;
	char temp[2]; //��������
	char hex[2];  //����16����������
	char* cipher;
	*ciphertext= (char *)malloc((strlen(plaintext)+1)*sizeof(char)); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	cipher=*ciphertext;

	num=(strlen(plaintext))/2; //Ϊ8λCFBģʽ
	hex_to_bit(bool_key,keytext,64);
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp1,bool_iv,64);

	for(i=0;i<num;i++){
        Encrypt(bool_register,bool_temp1,bool_key);
        Table_copy(cipher_set,bool_register,8);  //ѡ����ߵ�8λ
        for(j=0;j<2;j++){
            temp[j]=plaintext[i*2+j];
        }

		hex_to_bit(plain_set,temp,8);
		Xor(cipher_set,plain_set,8); //��һ���������ܺ���32λ�����Ľ�����򣬺���ǰһ�����ķ�������Sλ���ܺ���32λ�뵱ǰ���Ľ������
		Table_copy(bool_temp2,cipher_set,8);
		bit_to_hex(hex,cipher_set,8);
		for(j=0;j<2;j++){
            cipher[j+i*2]=hex[j]; //16��������ʾ�����Ĵ��ݸ�cipher
		}
		RotateL(bool_temp,bool_temp1,64,8);  //��ѭ����λ
		Table_copy(bool_temp1,bool_temp,64);
		for(j=0;j<8;j++){
            bool_temp1[j+56]=bool_temp2[j];  //���Ĵ����ұ�8λ���������
		}

	}
	cipher[strlen(plaintext)]='\0';  //��NULL��β
};
void CFB_decrypt(char** plaintext,const char* ciphertext,const char* keytext,const char* vitext){
    bool plain_set[8];  //����8λ�����ģ���һ��һ������
    bool cipher_set[8]={0};  //����8λ������
    bool bool_key[64];  //����64λ��Կ
    bool bool_register[64];
    bool bool_iv[64],bool_temp[64],bool_temp1[64],bool_temp2[64];
	int num,i,j;
	char temp[2]; //��������
	char hex[2];  //����16����������
	char *plain;
	*plaintext= (char *)malloc((strlen(ciphertext)+1)*sizeof(char)); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	plain=*plaintext;
	hex_to_bit(bool_key,keytext,64); //��16������ʽ����Կ��Ϊ��������ʽ
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp1,bool_iv,64);
    num=(strlen(ciphertext))/2;
    for(i=0;i<num;i++){
        Encrypt(bool_register,bool_temp1,bool_key);
        Table_copy(plain_set,bool_register,8);  //ѡ����ߵ�8λ
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
		RotateL(bool_temp,bool_temp1,64,8);  //��ѭ����λ
		Table_copy(bool_temp1,bool_temp,64);
		for(j=0;j<8;j++){
            bool_temp1[j+56]=bool_temp2[j];  //���Ĵ����ұ�8λ���������
		}

	}
	//printf("\n");
	plain[strlen(ciphertext)]='\0';  //��NULL��β
};
void OFB(const char* plaintext, const char* keytext, const char* vitext, char** ciphertext) {
	//plaintextΪ�����ַ�����,��NULL��β
	//keytextΪ��Կ�ַ����飬��NULL��β
	//vitextΪ��ʼ�������ַ����飬��NULL��β
	//cipherΪ�����ַ����飬��NULL��β����Ҫ������䣬ע��Ҫ�ocipher����ռ䣡
	//��ʵ��~
	bool plain_set[8];  //����8λ�����ģ���һ��һ������
    bool cipher_set[64],temp_cipher[8];  //����8λ������
    bool bool_key[64];  //����64λ��Կ
    bool bool_iv[64],bool_temp[64],bool_temp1[64],bool_temp2[64];
	int num,i,j;
	char temp[2]; //��������
	char hex[2];  //����16����������
	char* cipher;
	*ciphertext= (char *)malloc((strlen(plaintext)+1)*sizeof(char));
    cipher=*ciphertext;

	num=(strlen(plaintext))/2;//8λOFBģʽ
	hex_to_bit(bool_key,keytext,64);
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp,bool_iv,64);
	Table_copy(bool_temp1,bool_iv,64);

	for(i=0;i<num;i++){
        Encrypt(cipher_set,bool_temp,bool_key);  //�Ĵ������ݽ��м���
		Table_copy(temp_cipher,cipher_set,8); //���ܺ��ǰ��λ
		RotateL(bool_temp2,bool_temp1,64,8);  //��ѭ����λ
		for(j=0;j<8;j++){
            bool_temp2[j+56]=temp_cipher[j];  //���Ĵ����ұ�8λ���������
		}
		Table_copy(bool_temp1,bool_temp2,64);  //bool_temp1�������ÿ�μĴ���ƫ�Ʋ�λ֮�������
        Table_copy(bool_temp,bool_temp1,64);
        for(j=0;j<2;j++){
            temp[j]=plaintext[i*2+j];
        }

		hex_to_bit(plain_set,temp,8);
		Xor(temp_cipher,plain_set,8);
		bit_to_hex(hex,temp_cipher,8);
		for(j=0;j<2;j++){
            cipher[j+i*2]=hex[j]; //16��������ʾ�����Ĵ��ݸ�cipher
		}
	}
	cipher[strlen(plaintext)]='\0';  //��NULL��β
};
void OFB_decrypt(char** plaintext,const char* ciphertext,const char* keytext,const char* vitext){
    bool plain_set[64],temp_plain[8];  //����8λ�����ģ���һ��һ������
    bool cipher_set[8]={0};  //����8λ������
    bool bool_key[64];  //����64λ��Կ
    bool bool_iv[64],bool_temp[64],bool_temp1[64],bool_temp2[64];
	int num,i,j;
	char temp[2]; //��������
	char hex[2];  //����16����������
	char *plain;
	*plaintext= (char *)malloc((strlen(ciphertext)+1)*sizeof(char)); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	plain=*plaintext;

	hex_to_bit(bool_key,keytext,64); //��16������ʽ����Կ��Ϊ��������ʽ
	hex_to_bit(bool_iv,vitext,64);
	Table_copy(bool_temp1,bool_iv,64);
    num=(strlen(ciphertext))/2;
    Table_copy(bool_temp,bool_iv,64);

	for(i=0;i<num;i++){
        Encrypt(plain_set,bool_temp,bool_key);  //�Ĵ������ݽ��м���
		Table_copy(temp_plain,plain_set,8); //���ܺ��ǰ��λ
		RotateL(bool_temp2,bool_temp1,64,8);  //��ѭ����λ
		for(j=0;j<8;j++){
            bool_temp2[j+56]=temp_plain[j];  //���Ĵ����ұ�8λ���������
		}
		Table_copy(bool_temp1,bool_temp2,64);  //bool_temp1�������ÿ�μĴ���ƫ�Ʋ�λ֮�������
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
	plain[strlen(ciphertext)]='\0';  //��NULL��β
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
		clock_t start, stop; //clock_tΪclock()�������صı�������
		double duration;
		double v;

		i=10*pow(2,20);  //��Ҫ����5MB�������������,��16����������,i��16������
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
		printf("�������ݳɹ������ݴ�С%.2fMB\n",size);

		/*plain_test1=(char*)malloc((i*sizeof(char))/2+1);  //��Ϊ�ֽ���ʽ
		char parsewalker[3] = { 0 }; //������������һ���ֽڵ�����
        for ( j= 0; j< i; j+= 2) {  //������16��������2��һ����Ϊһ���ֽڷֿ�
            parsewalker[0] = plain_test[i];
            parsewalker[1] = plain_test[i + 1];
            plain_test1[j / 2] = strtol(parsewalker, 0, 16);  //��parsewalker��ָ��2λ16���������ݸ�����base16ת��Ϊ��Ӧ����ĸ
            //printf("%c", plain_test1[i / 2]);  //�����ĸ��ע����i/2ȡ����������������
        }*/
		read= readfile2memory("des_key.txt", &key_test);
		read= readfile2memory("des_iv.txt", &vi_test);
		switch(choice){
			case 1:
				printf("\nECBģʽ����20�μӽ��ܲ���:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nECB��%d�μӽ��ܿ�ʼ��",k);
                    ECB(plain_test,key_test,&cipher_test);
                    ECB_decrypt(&plain_test,cipher_test,key_test);
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCKΪclock()������ʱ�䵥λ����ʱ�Ӵ��
    			printf("\nECB�����ӽ���20����ʱ��Ϊ��%.4fms",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("\n�ٶ�Ϊ��%.4fMByte/s\n",v);
    			break;
    		case 2:
    			printf("\nCBCģʽ�����ӽ���20��:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nCBC��%d�μӽ��ܿ�ʼ��",k);
                    CBC(plain_test,key_test,vi_test,&cipher_test);
                    CBC_decrypt(&plain_test,cipher_test,key_test,vi_test);
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCKΪclock()������ʱ�䵥λ����ʱ�Ӵ��
    			printf("\nCBC�����ӽ���20����ʱ��Ϊ��%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("�ٶ�Ϊ��%.4fMByte/s\n",v);
    			break;
    		case 3:
    			printf("\nCFB�����ӽ���20��:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nCFB��%d�μӽ��ܿ�ʼ��",k);
                    CFB(plain_test,key_test,vi_test,&cipher_test);
                    CFB_decrypt(&plain_test,cipher_test,key_test,vi_test);
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCKΪclock()������ʱ�䵥λ����ʱ�Ӵ��
    			printf("\nCFB�����ӽ���20����ʱ��Ϊ��%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("�ٶ�Ϊ��%.4fMByte/s\n",v);
    			break;
    		case 4:
    			   	printf("\nOFB�����ӽ���20��:");
					start=clock();
    				for(k=1;k<21;k++){
                        printf("\nOFB��%d�μӽ��ܿ�ʼ��",k);
                        OFB(plain_test,key_test,vi_test,&cipher_test);
                        OFB_decrypt(&plain_test,cipher_test,key_test,vi_test);
					}
   				stop=clock();
    			duration=(double)(stop-start); //CLK_TCKΪclock()������ʱ�䵥λ����ʱ�Ӵ��
    			printf("\nOFB�����ӽ���20����ʱ��Ϊ��%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("�ٶ�Ϊ��%.4fMByte/s\n",v);
    			break;
    		default:
    			printf("����");
		}
}

int main(int argc, char** argv) {
	//argc ��ʾ�����ĸ�����argv��ʾÿ��������һ���ַ�������
	int i;
	printf("argc:%d\n", argc);
	for (i = 0; i < argc; i++) {
		printf("%d : %s\n", i, argv[i]);
	}

	/*
	-p plainfile ָ�������ļ���λ�ú�����
	-k keyfile  ָ����Կ�ļ���λ�ú�����
	-v vifile  ָ����ʼ�������ļ���λ�ú�����
	-m mode  ָ�����ܵĲ���ģʽ
	-c cipherfile ָ�������ļ���λ�ú����ơ�
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

	printf("����������ɣ�\n");
	printf("����Ϊ�����ļ���λ�ú�����:%s\n", plainfile);
	printf("����Ϊ��Կ�ļ���λ�ú�����:%s\n", keyfile);
	if (strcmp(mode, "ECB") != 0) {
		printf("����Ϊ��ʼ�������ļ��ļ���λ�ú�����:%s\n", vifile);
	}
	printf("����Ϊ�����ļ���λ�ú�����:%s\n", cipherfile);
	printf("����Ϊ���ܵ�ģʽ:%s\n", mode);

	printf("���ڿ�ʼ��ȡ�ļ���\n");

	printf("��ȡ�����ļ�...\n");
	bool read_result = readfile2memory(plainfile, &plaintext);
	if (read_result == false) {
		printf("��ȡ�����ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
		exit(-1);
	}
	printf("��ȡ�����ļ��ɹ���\n");

	printf("��ȡ��Կ�ļ�...\n");
	read_result = readfile2memory(keyfile, &keytext);
	if (read_result == false) {
		printf("��ȡ��Կ�ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
		exit(-1);
	}
	printf("��ȡ��Կ�ļ��ɹ���\n");

	if (strcmp(mode, "ECB") != 0) {
		printf("��ȡ��ʼ�����ļ�...\n");
		read_result = readfile2memory(vifile, &vitext);
		if (read_result == false) {
			printf("��ȡ��ʼ�����ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
			exit(-1);
		}
		printf("��ȡ��ʼ�����ļ��ɹ���\n");
	}

	if (strcmp(mode, "ECB") == 0) {
		ECB(plaintext, keytext, &ciphertext);
		ECB_decrypt(&plaintext,ciphertext,keytext);//���Խ���
		printf("���ܳ�������Ϊ%s\n",plaintext);

	}
	else if (strcmp(mode, "CBC") == 0) {
		CBC(plaintext, keytext, vitext, &ciphertext);
		CBC_decrypt(&plaintext,ciphertext, keytext, vitext);
		printf("���ܳ�������Ϊ%s\n",plaintext);
	}
	else if (strcmp(mode, "CFB") == 0) {
		CFB(plaintext, keytext, vitext, &ciphertext);
		CFB_decrypt(&plaintext,ciphertext, keytext, vitext);
		printf("���ܳ�������Ϊ%s\n",plaintext);
	}
	else if (strcmp(mode, "OFB") == 0) {
		OFB(plaintext, keytext, vitext, &ciphertext);
		OFB_decrypt(&plaintext, ciphertext,keytext, vitext);
		printf("���ܳ�������Ϊ%s\n",plaintext);
	}
	else {
		//��Ӧ���ܵ�������
		printf("�������󣡣���\n");
		exit(-2);
	}

	if (ciphertext == NULL) {
		printf("ͬѧ��ciphertextû�з����ڴ�Ŷ����Ҫ��������~\nʧ�ܣ������˳���...");
		exit(-1);
	}

	if (ciphertext[strlen(ciphertext)]!=NULL) {
		printf("����%d",strlen(ciphertext));
		printf("%s\n",ciphertext);
		printf("ͬѧ��ciphertextû����NULLΪ��βŶ������cipherŪ���ˣ����ټ��һ��~\nʧ�ܣ������˳���...");
		exit(-1);
	}

	printf("���ܳ��������ģ�ʮ�����Ʊ�ʾ��Ϊ:%s\n", ciphertext);
	/*printf("16���Ʊ�ʾΪ:");

	int count = strlen(ciphertext);
	char* cipherhex = malloc(count * 2 + 1);
	memset(cipherhex, 0, count * 2 + 1);

	for (i = 0; i < count; i++) {
		sprintf(cipherhex + i * 2, "%2X", ciphertext[i]);*/
	//}
	//printf("%s\nд���ļ���...\n", ciphertext);
    printf("\nд���ļ���...\n");
	FILE* fp = fopen(cipherfile, "w");
	if (fp == NULL) {
		printf("�ļ� %s ��ʧ��,����", cipherfile);
		exit(-1);
	}

	int writecount=fwrite(ciphertext,sizeof(char),strlen(ciphertext),fp);
	if (writecount != strlen(ciphertext)) {
		printf("д���ļ����ֹ��ϣ������³��ԣ�");
		exit(-1);
	}
	else{
		printf("д��ɹ�\n");
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
		printf("�������󣡣���\n");
		exit(-2);
	}
	printf("��ϲ������˸ó������ύ����!");

	return 0;
}

