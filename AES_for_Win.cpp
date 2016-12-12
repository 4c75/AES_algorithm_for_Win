// AES_for_Win.cpp : Defines the entry point for the console application.
//

//#include <stdafx.h>
#include <string.h>
#include "aeslib.c"
#include <iostream>
using namespace std;


int main(int argc, char* argv[])
{
	char crypto_text[] = "Loti sarezgitais un sifretais teksts, kurs var but jebkada garuma";  //need to put option to insert different plain text
	unsigned char key[] = "1234567891234567"; //need to put option to insert different key
	unsigned char result[2000]; //assume the longest result will be 2000 char long
	unsigned char temp_result[2000];
	unsigned char text_fragment [17]; //place to  hold plain text fragments 16 + end symbol
	int length_plain_text=0;

	length_plain_text = strlen(crypto_text); //need to get lenght of plain text
	int last_block_starts = length_plain_text - (length_plain_text % 16);
	int last_block_element_count = length_plain_text % 16;


	for (int i= 0; i<= length_plain_text; i=i+16)	//will go through all blocks
	{
		if (last_block_starts>i)//for blocks who are full of values
		{
			for (int j = 0; j+i < i + 16; j++)
				{
					text_fragment[j] = crypto_text[i+j];
				};
					text_fragment[16] = '\0';
		}
		else //for last block, who isnt full of values
		{
			for (int j=0; j<=last_block_element_count; j++)
			{
				text_fragment[j] = crypto_text[j + i];
			}
			for (int j = 0 + last_block_element_count; j <= 16; j++)
			{
				text_fragment[j] = '0';
			}
			text_fragment[16] = '\0';
		}
		encrypt_AES(text_fragment, key);
		//Puts together all result blocks
		for (int j = 0; j <= 16; j++)
		{
			result[i+j] = text_fragment[j];
		};
		
	};
	cout << "Encrypted:" << endl;
	cout << result << endl;
	//Decrypts and puts result into string
	for (int i = 0; i <= length_plain_text; i = i + 16)
	{
		for (int j = 0; j < 16; j++)
		{
			text_fragment[j] = result[i + j];
		};
		decrypt_AES(text_fragment, key);
		for (int j = 0; j <= 16; j++)
		{
			temp_result[i + j] = text_fragment[j];
		};
	};
	cout << "Decrypted:" << endl;	//SHOULD MAKE FUNCTION WHICH REMOVES ALL 0 FROM END OF STRING!!!!
	cout << temp_result << endl;

	/*cout << text_fragment << endl;
	ShiftRows(text_fragment);
	cout << text_fragment << endl;
	ShiftRows_inversed(text_fragment);
	cout << text_fragment << endl;*/



	/*
	cout <<"text fragment: "<< text_fragment<<endl;
	ShiftRows(text_fragment);
	SubBtyes(text_fragment,16);
	AddRoundKey(text_fragment, key);
	cout <<"after cryption: "<< text_fragment<<endl;

	AddRoundKey(text_fragment, key);
	SubBtyes_inversed(text_fragment,16);
	ShiftRows_inversed(text_fragment);
	cout <<"after decryption: " << text_fragment<<endl<<endl;
	*/

	system("pause");
	return 0;
}
