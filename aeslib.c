
//resources:
//https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
//https://www.lri.fr/~fmartignon/documenti/systemesecurite/5-AES.pdf

//unsigned unsigned char round_keys[10 * 16];

static unsigned char Rijndael_S_box[256] =
 {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
 };

static unsigned char Rijndael_S_box_reversed[256] =
{
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

void AddRoundKey(unsigned char *state, unsigned char *round_key)
{
    for(int i=0; i < 16; i++)
	{
        state[i] = state [i] ^ round_key[i];	//XOR operation
	};
};

// pass array of 16 elements
/*We swap unsigned char with it's S-Box value
(The first 4 bits in the byte (the first hexadecimal value, hence) individuate the row,
the last 4 bits individuate the column) in Rijndael S-Box*/
void SubBtyes(unsigned char *state, int size)
{
    int i = 0;
    for(;i<size;i++) state[i] = Rijndael_S_box[state[i]];
};

void SubBtyes_inversed(unsigned char *state, int size)
{
    int i = 0;
    for(;i<size;i++) state[i] = Rijndael_S_box_reversed[state[i]];
};

// pass array of 16 elements
void ShiftRows(unsigned char *state)
{
    int col, row = 0;
    for(; row<4; row++)
	{
        unsigned char remember = state[row *4+ 0];
        for(col = 1; col<4; col++){
            state[row *4+ (col-1)] = state[row *4+ col];
		};
		state[row *4+ 3] = remember;
	};
};

void ShiftRows_inversed(unsigned char *state)
{
	int col, row = 0;
	for (; row<4; row++)
	{
		unsigned char remember = state[row * 4 + 3];
		for (col = 2; col>-1; col--){
			state[row * 4 + (col + 1)] = state[row * 4 + col];
		};
		state[row * 4 + 0] = remember;
	};
};

//Used in function Multiply
unsigned char xtime(unsigned char x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

int Multiply(int x, int y)
{
  return (((x & 1) * y) ^
       ((x>>1 & 1) * xtime(y)) ^
       ((x>>2 & 1) * xtime(xtime(y))) ^
       ((x>>3 & 1) * xtime(xtime(xtime(y)))) ^
       ((x>>4 & 1) * xtime(xtime(xtime(xtime(y))))));
};

/*	These numbers are used as arguments in Mix Column,if change these then need to change inversed values too
02 03 01 01
01 02 03 01
03 01 01 02
*/
void MixColumns(unsigned char *state)
{
  char tmp[16];
	for (int i = 0; i < 16; i+=4)
	{
		tmp[i] = Multiply(0x02, state[i]) ^ Multiply(0x03, state[i + 1]) ^ Multiply(0x01, state[i + 2]) ^ Multiply(0x01, state[i + 3]);	//XOR counted as +
		tmp[i + 1] = Multiply(0x01, state[i]) ^ Multiply(0x02, state[i + 1]) ^ Multiply(0x03, state[i + 2]) ^ Multiply(0x01, state[i + 3]);
		tmp[i + 2] = Multiply(0x01, state[i]) ^ Multiply(0x01, state[i + 1]) ^ Multiply(0x02, state[i + 2]) ^ Multiply(0x03, state[i + 3]);
		tmp[i + 3] = Multiply(0x03, state[i]) ^ Multiply(0x01, state[i + 1]) ^ Multiply(0x01, state[i + 2]) ^ Multiply(0x02, state[i + 3]);
	};
  for(int i = 0; i<16; i++) state[i] = tmp[i];
};

/*	Used for inversed function, if change these then need to change those who are in MixColumn too
0E 0B 0D 09
09 0E 0B 0D
0D 09 0E 0B
0B 0D 09 0E
*/
void MixColumns_inversed(unsigned char *state)
{
  int i;
  char tmp[16];
	for (i = 0; i < 16; i+=4)
	{
		tmp[i] = Multiply(0x0E, state[i]) ^ Multiply(0x0B, state[i + 1]) ^ Multiply(0x0D, state[i + 2]) ^ Multiply(0x09, state[i + 3]);
		tmp[i + 1] = Multiply(0x09, state[i]) ^ Multiply(0x0E, state[i + 1]) ^ Multiply(0x0B, state[i + 2]) ^ Multiply(0x0D, state[i + 3]);
		tmp[i + 2] = Multiply(0x0D, state[i]) ^ Multiply(0x09, state[i + 1]) ^ Multiply(0x0E, state[i + 2]) ^ Multiply(0x0B, state[i + 3]);
		tmp[i + 3] = Multiply(0x0B, state[i]) ^ Multiply(0x0D, state[i + 1]) ^ Multiply(0x09, state[i + 2]) ^ Multiply(0x0E, state[i + 3]);
	};
  for(i=0; i<16; i++) state[i] = tmp[i];
};

void Rot_Word(unsigned char* word)
{
	unsigned char temp[4];
	temp[0] = word[0];
	word[0] = word[3];
	word[3] = word[2];
	word[2] = word[1];
	word[1] = temp[0];
};

/*	RCON
[01]  [02]  [04]  [08]  [10]  [20]  [40]  [80]  [1b]  [36]
[00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
[00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
[00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
*/
void XOR_column(unsigned char* prew_key, unsigned char* key, int column, int round_number, unsigned char * temp)
{
	switch (column)
	{
	case 1:
		key[0] = prew_key[0] ^ temp[0];	//AFTER THIS LINE PREW_KEY CHANGES VALUES AND I DONT KNOW WHY!!!
		switch (round_number)
		{
		case 1:
			key[0] ^= 0x01;	//Use values from RCON, only first numbers needs to be XOR'ed
			break;
		case 2:
			key[0] ^= 0x02;
			break;
		case 3:
			key[0] ^= 0x04;
			break;
		case 4:
			key[0] ^= 0x08;
			break;
		case 5:
			key[0] ^= 0x10;
			break;
		case 6:
			key[0] ^= 0x20;
			break;
		case 7:
			key[0] ^= 0x40;
			break;
		case 8:
			key[0] ^= 0x80;
			break;
		case 9:
			key[0] ^= 0x1B;
			break;
		case 10:
			key[0] ^= 0x36;
			break;
		};
		key[1] = prew_key[1] ^ temp[1] ^ 0x00;
		key[2] = prew_key[2] ^ temp[2] ^ 0X00;
		key[3] = prew_key[3] ^ temp[3] ^ 0x00;
		break;
	case 2:
		key[4] = prew_key[4] ^ key[0];
		key[5] = prew_key[5] ^ key[1];
		key[6] = prew_key[6] ^ key[2];
		key[7] = prew_key[7] ^ key[3];
		break;
	case 3:
		key[8] = prew_key[8] ^ key[4];
		key[9] = prew_key[9] ^ key[5];
		key[10] = prew_key[10] ^ key[6];
		key[11] = prew_key[11] ^ key[7];
		break;
	case 4:
		key[12] = prew_key[12] ^ key[8];
		key[13] = prew_key[13] ^ key[9];
		key[14] = prew_key[14] ^ key[10];
		key[15] = prew_key[15] ^ key[12];
		break;
	}
};

/*	Used this to generate 1 key at time
void getRoundKey(unsigned char *key, unsigned char* round_key, int round_number)
{
	unsigned char temp[4];
	//Take 4 elements from first key (last column)
	temp[0] = key[12];
	temp[1] = key[13];
	temp[2] = key[14];
	temp[3] = key[15];
	Rot_Word(temp);  //Rot_word and subbytes only for first column
	SubBtyes(temp, 4);
	XOR_column(key, round_key, 1, round_number, temp);  //will use temp file only for 1 column key generation
	XOR_column(key, round_key, 2, round_number, temp);
	XOR_column(key, round_key, 3, round_number, temp);
	XOR_column(key, round_key, 4, round_number, temp);
};
*/

void getRoundKey10Times(unsigned char *key, unsigned char* round_key, int round_number, unsigned char* round_keys)
{
  int i;
  int round = round_number;
  for(i =0; i<10; i++)
  {
    unsigned char temp[4];
  	//Take 4 elements from first key (last column)
  	temp[0] = key[12];
  	temp[1] = key[13];
  	temp[2] = key[14];
  	temp[3] = key[15];
  	Rot_Word(temp);  //Rot_word and subbytes only for first column
  	SubBtyes(temp, 4);
  	XOR_column(key, round_key, 1, round, temp);  //will use temp file only for 1 column key generation
  	XOR_column(key, round_key, 2, round, temp);
  	XOR_column(key, round_key, 3, round, temp);
  	XOR_column(key, round_key, 4, round, temp);

	round++;

    int j;
    for(j=0; j<16; j++)
	{
      round_keys[i *16+ j] = round_key[j];
      key[j]=round_key[j];
	  
    }
  };
};

void encrypt_AES(unsigned char *state, unsigned char* key)
{
	unsigned char *round_key;
	unsigned char *prew_round_key;
	unsigned unsigned char round_keys[10 * 16];
	AddRoundKey(state, key);
	prew_round_key = key;
	round_key = key;
	getRoundKey10Times(prew_round_key, round_key, 1, round_keys);
	for(int i=0; i<9 ;i++){
        SubBtyes(state, 16);
        ShiftRows(state);
        MixColumns(state);
		for (int df = 0; df<16; df++)
		{
			round_key[df] = round_keys[i * 16 + df];
		}
        AddRoundKey(state, round_key);
	};
    SubBtyes(state, 16);
    ShiftRows(state);
	for (int df = 0; df<16; df++)
	{
		round_key[df] = round_keys[10 * 16 + df];
	}
    AddRoundKey(prew_round_key, round_key);
};

void decrypt_AES(unsigned char * state, unsigned char *key)
{
	unsigned char *round_key;
	unsigned char *prew_round_key;
	unsigned unsigned char round_keys[10 * 16];
	prew_round_key = key;
	round_key = key;
	getRoundKey10Times(prew_round_key, round_key, 1, round_keys);
	for (int df = 0; df<16; df++)
	{
		round_key[df] = round_keys[10 * 16 + df];
	}
	AddRoundKey(state, round_key);
	for (int i = 9; i>0; i--) 
	{
		ShiftRows_inversed(state);
		SubBtyes_inversed(state, 16);
		MixColumns_inversed(state);
		for (int df = 0; df<16; df++)
		{
			round_key[df] = round_keys[i * 16 + df];
		}
		AddRoundKey(state, round_key);
	};
	ShiftRows_inversed(state);
	SubBtyes_inversed(state, 16);
	for(int df = 0; df<16; df++)
	{
    round_key[df] = round_keys[0*16 + df];
	}
	AddRoundKey(state, round_key);
};
