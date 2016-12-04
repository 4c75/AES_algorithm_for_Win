// AES_for_Win.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "aeslib.c"
#include <iostream>
using namespace std;


int _tmain(int argc, _TCHAR* argv[])
{
	char crypto_text[] = "Loti sarezgitais un sifretais teksts, kurs var but jebkada garuma";  //need to put option to insert different plain text
	char key[] = "2222222222222211"; //need to put option to insert different key
	char rezult[2000]; //assume the longest result will be 2000char long
	char text_fragment [17]; //place to  hold plain text fragments 16 + end symbol
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

		//rest of operations
		encrypt_AES(text_fragment, key);
		cout << text_fragment << endl;
		decrypt_AES(text_fragment, key);
		cout << text_fragment << endl;
	};

	system("pause");
	return 0;
}

