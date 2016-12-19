// AES_for_Win.cpp : Defines the entry point for the console application.
//

//#include "stdafx.h"
#include <string.h>
#include "aeslib.c"
#include <iostream>
#include <fstream>
#include <string>
using namespace std;


int main(int argc, char* argv[])
{
	char crypto_text[]="HOHOHOHO";//[2000];// ="Loti sarezgitais un sifretais teksts, kurs var but jebkada garuma HOHO";
	unsigned char key[] = "KAUTKADSKAUTKADS";
	//cin.getline(crypto_text, 2000);
	//cin.getline(key, 16);
	unsigned char text_fragment [17];
	int length_plain_text=0;

	length_plain_text = strlen(crypto_text);
	int last_block_starts = length_plain_text - (length_plain_text % 16);
	int last_block_element_count = length_plain_text % 16;

	//for(int hu =0 ; hu<1000001; hu++){



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
				text_fragment[j] = 0;
			}
			text_fragment[16] = '\0';
		}

		encrypt_AES(text_fragment, key);
		for(int p = 0; p<16; p++){
			printf("%02X", text_fragment[p]);
		}
		cout << endl;//text_fragment << endl;

		decrypt_AES(text_fragment, key);

		cout << "decrypted: " << text_fragment << endl;

	};

	//}

	//system("pause");
	return 0;
}
